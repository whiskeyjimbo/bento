//go:build linux

package runner

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

// straceAvailable reports whether strace is on the host PATH.
func straceAvailable() bool {
	_, err := exec.LookPath("strace")
	return err == nil
}

// wrapWithStrace prepends strace to (exe, args) so file-open calls in the
// child tree are recorded to tracePath. The "-qq" suppresses strace's own
// attach/detach lines; "-f" follows forks. Syscall coverage:
//   - openat/openat2: glibc's open() wrapper and the modern direct API
//   - creat:          older tools (e.g. GNU tar) still use this directly;
//                     without it, subprocess writes via tar/cpio are invisible
//   - open:           a handful of statically-linked or non-glibc binaries
//                     invoke the legacy syscall
//   - unlink/unlinkat/rmdir: deletes; recorded as a write of the parent dir
//                     so `find -delete`, `rm`, and similar are not invisible
//   - rename/renameat/renameat2: moves; recorded as a write of both parent
//                     dirs (source and dest)
func wrapWithStrace(exe string, args []string, tracePath string) (string, []string) {
	out := []string{
		"-f",
		"-qq",
		"-y", // decode fd args inline as `N<path>` — needed for *at syscalls
		"-e", "trace=openat,openat2,creat,open,unlink,unlinkat,rmdir,rename,renameat,renameat2,connect",
		"-o", tracePath,
		"--",
		exe,
	}
	return "strace", append(out, args...)
}

// parseStraceOpens reads a strace -o file and returns unique openat attempts
// (both success and failure), with sandbox/bwrap noise and auto-mounted
// prefixes filtered out. A successful attempt for a path supersedes a failed
// one (same path appears once with OK=true).
func parseStraceOpens(tracePath, scriptAbs string, extraPrefixes []string) ([]FSOpen, error) {
	f, err := os.Open(tracePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type acc struct {
		ok    bool
		write bool
	}
	seen := make(map[string]acc)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	record := func(path string, ok, write bool) {
		// Relative paths in an openat(AT_FDCWD, ...) are resolved against
		// the script's cwd, which bento sets to /sandbox. Promote them so
		// downstream filters can recognize /sandbox/* paths consistently.
		if !filepath_IsAbs(path) {
			path = spec.SandboxRoot + "/" + path
		}
		// filepath.Clean normalizes `/sandbox/./reports/x` → `/sandbox/reports/x`.
		// Without this, "/sandbox/.<anything>" matches the prefix used downstream
		// to skip bento's internal scratch files, silently dropping user writes
		// to relative paths from the tmpfs-vanish detection.
		path = filepath.Clean(path)
		// Keep /sandbox/* opens only when they're writes — they're how we
		// detect silent writes into the sandbox tmpfs. Everything else
		// under /sandbox is bento internals (script, launcher, shim files).
		if isNoisePath(path, scriptAbs, extraPrefixes) && !(write && isSandboxUserPath(path)) && !(write && isUserWriteTarget(path)) {
			return
		}
		prev, exists := seen[path]
		if !exists {
			seen[path] = acc{ok: ok, write: write}
			return
		}
		// Promote: any successful open wins, any write flag wins.
		if !prev.ok && ok {
			prev.ok = ok
		}
		if write {
			prev.write = true
		}
		seen[path] = prev
	}
	for sc.Scan() {
		line := sc.Text()
		if path, ok, write, found := extractOpenatAttempt(line); found {
			record(path, ok, write)
			continue
		}
		// Mutation syscalls (unlink/rmdir/rename) need write permission on the
		// containing directory, not the affected leaf. Surface the parent dir
		// as a write so the generated manifest's `write:` list lets the script
		// delete/move files on a subsequent `bento run`. Without this, a
		// `find -delete` profile produces a manifest that can't delete.
		for _, m := range extractMutationAttempts(line) {
			record(m.path, m.ok, true)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]FSOpen, 0, len(seen))
	for p, a := range seen {
		out = append(out, FSOpen{Path: p, OK: a.ok, Write: a.write})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// parseStraceConnects extracts unique connect() destinations from a strace -f
// log. Used by Profile to surface outbound TCP attempts from compiled binaries
// that bypass libproxychains (Go statically-linked net.Dial, Rust tokio, etc.).
//
// Line shapes (with -y the fd has an extra `<...>` suffix that doesn't matter
// for us):
//
//	connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
//	connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 EACCES (Permission denied)
//	connect(3, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, "2606:4700::1", &sin6_addr), ...}, 28) = -1 EACCES (...)
//	connect(3, {sa_family=AF_UNIX, sun_path="/run/nscd/socket"}, 110) = -1 ECONNREFUSED
//
// AF_UNIX is intentionally dropped — only AF_INET / AF_INET6 are useful for a
// network-rule manifest hint.
func parseStraceConnects(tracePath string) ([]ConnectAttempt, error) {
	f, err := os.Open(tracePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type key struct {
		ip   string
		port int
	}
	seen := make(map[key]bool) // value = any-success
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "connect(") {
			continue
		}
		ip, port, ok, found := extractConnectAttempt(line)
		if !found {
			continue
		}
		k := key{ip, port}
		if prev, exists := seen[k]; !exists || (!prev && ok) {
			seen[k] = ok
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]ConnectAttempt, 0, len(seen))
	for k, ok := range seen {
		out = append(out, ConnectAttempt{IP: k.ip, Port: k.port, OK: ok})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}

// extractConnectAttempt pulls (ip, port, ok) from a single strace connect()
// line. Skips AF_UNIX and AF_NETLINK (those don't belong in a manifest hint).
func extractConnectAttempt(line string) (ip string, port int, ok, found bool) {
	switch {
	case strings.Contains(line, "sa_family=AF_INET,") || strings.Contains(line, "sa_family=AF_INET6,"):
		// keep going
	default:
		return "", 0, false, false
	}
	// Port: look for sin_port=htons(NNN) or sin6_port=htons(NNN).
	portIdx := strings.Index(line, "_port=htons(")
	if portIdx < 0 {
		return "", 0, false, false
	}
	rest := line[portIdx+len("_port=htons("):]
	close := strings.IndexByte(rest, ')')
	if close < 0 {
		return "", 0, false, false
	}
	p, err := strconv.Atoi(rest[:close])
	if err != nil {
		return "", 0, false, false
	}
	// IP: prefer inet_addr("X") for v4, inet_pton(AF_INET6, "X", ...) for v6.
	if i := strings.Index(line, `inet_addr("`); i >= 0 {
		j := strings.IndexByte(line[i+len(`inet_addr("`):], '"')
		if j < 0 {
			return "", 0, false, false
		}
		ip = line[i+len(`inet_addr("`) : i+len(`inet_addr("`)+j]
	} else if i := strings.Index(line, `inet_pton(AF_INET6, "`); i >= 0 {
		j := strings.IndexByte(line[i+len(`inet_pton(AF_INET6, "`):], '"')
		if j < 0 {
			return "", 0, false, false
		}
		ip = line[i+len(`inet_pton(AF_INET6, "`) : i+len(`inet_pton(AF_INET6, "`)+j]
	} else {
		return "", 0, false, false
	}
	// Return value: `= 0` (ok), `= -1 EXXX (...)` (denied/refused).
	ok = strings.Contains(line, ") = 0")
	return ip, p, ok, true
}

// isUserWriteTarget reports whether a path under /tmp, /var, or /run is a
// plausible user-chosen write destination (e.g. /tmp/output.json), not a
// bento-internal sidecar (e.g. /tmp/bento-launcher-*). Used to override the
// /tmp/etc noise filter for writes — scripts writing to /tmp are common and
// the manifest needs to declare them.
func isUserWriteTarget(p string) bool {
	for _, root := range []string{"/tmp/", "/var/tmp/", "/run/user/"} {
		if !strings.HasPrefix(p, root) {
			continue
		}
		rest := p[len(root):]
		if strings.HasPrefix(rest, ".bento-") {
			return false
		}
		for _, sidecar := range bentoSidecarPrefixes {
			if strings.HasPrefix(rest, sidecar) {
				return false
			}
		}
		return true
	}
	return false
}

// bentoSidecarPrefixes are temp-file basename prefixes bento itself creates
// under /tmp during a sandbox run. They must not be reported back to the user
// as "writes to declare in the manifest".
var bentoSidecarPrefixes = []string{
	"bento-launcher-",
	"bento-passwd-",
	"bento-group-",
	"bento-proxychains-",
	"bento-fsshim-",
	"bento-fsobs-",
	"bento-fstrace-",
}

// isSandboxUserPath reports whether a /sandbox/* path is a user-visible file
// (not a bento internal). Bento internals: /sandbox/script, /sandbox/launcher,
// /sandbox/proxychains.conf, anything starting with /sandbox/.bento-.
func isSandboxUserPath(p string) bool {
	if !strings.HasPrefix(p, spec.SandboxRoot+"/") {
		return false
	}
	switch p {
	case spec.SandboxScriptPath, spec.SandboxLauncherPath, spec.SandboxProxychainsConfPath:
		return false
	}
	rest := p[len(spec.SandboxRoot)+1:]
	if strings.HasPrefix(rest, ".bento-") {
		return false
	}
	return true
}

// mutationAttempt is one unlink/rmdir/rename path observation. `path` is the
// parent directory of the affected leaf — that's the directory that needs
// write permission for the syscall to succeed.
type mutationAttempt struct {
	path string
	ok   bool
}

// extractMutationAttempts parses a single strace line for unlink/unlinkat/
// rmdir/rename/renameat/renameat2. Returns the parent-dir paths the syscall
// touched (one for unlink/rmdir, two for rename/renameat). Empty result if
// the line isn't a recognized mutation syscall.
//
// Lines look like:
//
//	unlink("/x/y/file") = 0
//	unlinkat(AT_FDCWD, "/x/y/file", 0) = 0
//	rmdir("/x/y/empty") = 0
//	rename("/x/old", "/x/new") = 0
//	renameat(AT_FDCWD, "/x/old", AT_FDCWD, "/y/new") = 0
//	renameat2(AT_FDCWD, "/x/old", AT_FDCWD, "/y/new", 0) = 0
func extractMutationAttempts(line string) []mutationAttempt {
	switch {
	case strings.Contains(line, "unlinkat("):
		return atFdcwdSinglePath(line, "unlinkat(")
	case strings.Contains(line, "unlink("):
		if !isBareCall(line, "unlink(") {
			return nil
		}
		return singleQuotedPath(line, "unlink(", returnOK(line))
	case strings.Contains(line, "rmdir("):
		if !isBareCall(line, "rmdir(") {
			return nil
		}
		return singleQuotedPath(line, "rmdir(", returnOK(line))
	case strings.Contains(line, "renameat2("):
		return atFdcwdDoublePath(line, "renameat2(")
	case strings.Contains(line, "renameat("):
		return atFdcwdDoublePath(line, "renameat(")
	case strings.Contains(line, "rename("):
		if !isBareCall(line, "rename(") {
			return nil
		}
		return doubleQuotedPath(line, "rename(", returnOK(line))
	}
	return nil
}

// isBareCall guards against false positives — `unlinkat(` should not match
// the `unlink(` branch, etc. We require the preceding character to not be
// an identifier char (so `rename(` doesn't match inside `frename(`).
func isBareCall(line, token string) bool {
	idx := strings.Index(line, token)
	if idx <= 0 {
		return idx == 0
	}
	c := line[idx-1]
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
		return false
	}
	return true
}

func singleQuotedPath(line, token string, ok bool) []mutationAttempt {
	rest := line[strings.Index(line, token)+len(token):]
	p, found := nextQuotedString(rest)
	if !found {
		return nil
	}
	return []mutationAttempt{{path: filepath_Dir(p), ok: ok}}
}

func doubleQuotedPath(line, token string, ok bool) []mutationAttempt {
	rest := line[strings.Index(line, token)+len(token):]
	p1, found := nextQuotedString(rest)
	if !found {
		return nil
	}
	// Advance past p1 and look for the second.
	idx := strings.Index(rest, "\"")
	rest = rest[idx+1+len(p1)+1:]
	p2, found := nextQuotedString(rest)
	if !found {
		return []mutationAttempt{{path: filepath_Dir(p1), ok: ok}}
	}
	d1, d2 := filepath_Dir(p1), filepath_Dir(p2)
	out := []mutationAttempt{{path: d1, ok: ok}}
	if d2 != d1 {
		out = append(out, mutationAttempt{path: d2, ok: ok})
	}
	return out
}

// atFdcwdSinglePath handles unlinkat(<dirref>, "path", flags). <dirref> is
// either `AT_FDCWD` or strace's `-y`-decoded `N<path>` form. Without -y we
// can't resolve a bare numeric dirfd, so those would be skipped — but we
// pass -y in wrapWithStrace specifically so this lookup works.
func atFdcwdSinglePath(line, token string) []mutationAttempt {
	rest := line[strings.Index(line, token)+len(token):]
	dirAbs, rest, ok := consumeDirRef(rest)
	if !ok {
		return nil
	}
	leaf, found := nextQuotedString(rest)
	if !found {
		return nil
	}
	full := resolveAt(dirAbs, leaf)
	return []mutationAttempt{{path: filepath_Dir(full), ok: returnOK(line)}}
}

// atFdcwdDoublePath handles renameat(<dirref>, "p1", <dirref>, "p2", ...).
func atFdcwdDoublePath(line, token string) []mutationAttempt {
	rest := line[strings.Index(line, token)+len(token):]
	dir1, rest, ok := consumeDirRef(rest)
	if !ok {
		return nil
	}
	p1, found := nextQuotedString(rest)
	if !found {
		return nil
	}
	// Advance past the quoted p1.
	if idx := strings.Index(rest, "\""); idx >= 0 {
		rest = rest[idx+1+len(p1)+1:]
	}
	dir2, rest, ok := consumeDirRef(rest)
	if !ok {
		return nil
	}
	p2, found := nextQuotedString(rest)
	okret := returnOK(line)
	full1 := resolveAt(dir1, p1)
	d1 := filepath_Dir(full1)
	if !found {
		return []mutationAttempt{{path: d1, ok: okret}}
	}
	full2 := resolveAt(dir2, p2)
	d2 := filepath_Dir(full2)
	out := []mutationAttempt{{path: d1, ok: okret}}
	if d2 != d1 {
		out = append(out, mutationAttempt{path: d2, ok: okret})
	}
	return out
}

// consumeDirRef parses the leading dir-fd argument of an *at syscall. With
// strace `-y` the form is `N<path>` (e.g. `5</tmp/foo>`) for a real fd, or
// the literal `AT_FDCWD`. Returns the resolved directory path, the rest of
// the line (after the trailing comma/space), and whether it parsed. A bare
// numeric fd without -y decoding is treated as unresolvable (returns false).
func consumeDirRef(s string) (string, string, bool) {
	s = strings.TrimLeft(s, " ,")
	if strings.HasPrefix(s, "AT_FDCWD") {
		// Caller will resolve the leaf relative to "" → absolute or sandbox cwd.
		return "", s[len("AT_FDCWD"):], true
	}
	// Numeric fd: digits then optional `<path>`.
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return "", s, false
	}
	rest := s[i:]
	if !strings.HasPrefix(rest, "<") {
		// Bare fd, no -y decoding — we can't resolve.
		return "", rest, false
	}
	end := strings.Index(rest, ">")
	if end < 0 {
		return "", rest, false
	}
	return rest[1:end], rest[end+1:], true
}

// resolveAt joins a dir-fd path and a syscall-supplied name. An empty dir
// signals AT_FDCWD; leaf is returned unchanged (caller already handled
// absolute paths via existing AT_FDCWD logic upstream).
func resolveAt(dir, leaf string) string {
	if leaf == "" {
		return dir
	}
	if leaf[0] == '/' {
		return leaf
	}
	if dir == "" {
		return leaf
	}
	if dir[len(dir)-1] == '/' {
		return dir + leaf
	}
	return dir + "/" + leaf
}

func nextQuotedString(s string) (string, bool) {
	q1 := strings.Index(s, "\"")
	if q1 < 0 {
		return "", false
	}
	q2 := strings.Index(s[q1+1:], "\"")
	if q2 < 0 {
		return "", false
	}
	return s[q1+1 : q1+1+q2], true
}

// filepath_Dir mirrors filepath.Dir without importing the package here (the
// rest of this file deliberately avoids path/filepath for the build-tag-clean
// helper above; one-liner duplication is cheaper than a new import here).
func filepath_Dir(p string) string {
	if p == "" {
		return "."
	}
	// Strip trailing slashes (except for root).
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return p[:i]
}

// extractOpenatAttempt parses a single strace line and returns (path, ok, write, found).
// `found` is true when the line is a file-open call we recognize; `ok` is true
// when the return value is a non-negative fd; `write` is true when the flags
// argument requests write access. Lines look like:
//
//	[pid 1234] openat(AT_FDCWD, "/foo/bar", O_RDONLY) = 3
//	openat(AT_FDCWD, "/foo/bar", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
//	openat(AT_FDCWD, "/foo/bar", O_RDONLY) = -1 ENOENT (No such file)
//	creat("/tmp/out.tar", 0666) = 3                        // tools like tar
//	open("/foo/bar", O_RDONLY) = 3                         // legacy open(2)
func extractOpenatAttempt(line string) (string, bool, bool, bool) {
	switch {
	case strings.Contains(line, "openat("), strings.Contains(line, "openat2("):
		return parseOpenatLine(line)
	case strings.Contains(line, "creat("):
		return parseCreatLine(line)
	case strings.Contains(line, "open("):
		// Bare "open(" — guard against false positives from substrings like
		// "openat(" (already handled above) and "reopen(" by checking that the
		// preceding char isn't an identifier char.
		if idx := strings.Index(line, "open("); idx > 0 {
			c := line[idx-1]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
				return "", false, false, false
			}
		}
		return parseOpenLine(line)
	}
	return "", false, false, false
}

// parseOpenatLine handles openat(AT_FDCWD, "path", flags, ...) — also works
// for openat2 since the first two arguments are the same shape.
func parseOpenatLine(line string) (string, bool, bool, bool) {
	i := strings.Index(line, "openat")
	if i < 0 {
		return "", false, false, false
	}
	paren := strings.Index(line[i:], "(")
	if paren < 0 {
		return "", false, false, false
	}
	rest := line[i+paren+1:]
	if !strings.HasPrefix(rest, "AT_FDCWD") {
		return "", false, false, false
	}
	q1 := strings.Index(rest, "\"")
	if q1 < 0 {
		return "", false, false, false
	}
	q2 := strings.Index(rest[q1+1:], "\"")
	if q2 < 0 {
		return "", false, false, false
	}
	path := rest[q1+1 : q1+1+q2]
	afterPath := rest[q1+1+q2+1:]
	write := flagsRequestWrite(afterPath)
	return path, returnOK(line), write, true
}

// parseCreatLine handles creat("path", mode) — always a write.
func parseCreatLine(line string) (string, bool, bool, bool) {
	i := strings.Index(line, "creat(")
	if i < 0 {
		return "", false, false, false
	}
	rest := line[i+len("creat("):]
	q1 := strings.Index(rest, "\"")
	if q1 < 0 {
		return "", false, false, false
	}
	q2 := strings.Index(rest[q1+1:], "\"")
	if q2 < 0 {
		return "", false, false, false
	}
	path := rest[q1+1 : q1+1+q2]
	return path, returnOK(line), true, true
}

// parseOpenLine handles the legacy open("path", flags, ...) syscall.
func parseOpenLine(line string) (string, bool, bool, bool) {
	i := strings.Index(line, "open(")
	if i < 0 {
		return "", false, false, false
	}
	rest := line[i+len("open("):]
	q1 := strings.Index(rest, "\"")
	if q1 < 0 {
		return "", false, false, false
	}
	q2 := strings.Index(rest[q1+1:], "\"")
	if q2 < 0 {
		return "", false, false, false
	}
	path := rest[q1+1 : q1+1+q2]
	afterPath := rest[q1+1+q2+1:]
	write := flagsRequestWrite(afterPath)
	return path, returnOK(line), write, true
}

// flagsRequestWrite scans the flags argument (the chunk after the path) for
// any O_* token that implies write access.
func flagsRequestWrite(afterPath string) bool {
	comma := strings.Index(afterPath, ",")
	if comma < 0 {
		return false
	}
	flagsEnd := strings.IndexAny(afterPath[comma+1:], ",)")
	if flagsEnd < 0 {
		return false
	}
	flags := afterPath[comma+1 : comma+1+flagsEnd]
	return strings.Contains(flags, "O_WRONLY") ||
		strings.Contains(flags, "O_RDWR") ||
		strings.Contains(flags, "O_CREAT") ||
		strings.Contains(flags, "O_TRUNC") ||
		strings.Contains(flags, "O_APPEND")
}

// returnOK parses the "= <n>" tail of a strace line and reports whether the
// syscall succeeded (fd >= 0).
func returnOK(line string) bool {
	eq := strings.LastIndex(line, "= ")
	if eq < 0 {
		return false
	}
	tail := strings.TrimSpace(line[eq+2:])
	end := 0
	for end < len(tail) && (tail[end] == '-' || (tail[end] >= '0' && tail[end] <= '9')) {
		end++
	}
	if end == 0 {
		return false
	}
	n, err := strconv.Atoi(tail[:end])
	if err != nil {
		return false
	}
	return n >= 0
}

// isNoisePath filters sandbox/bwrap/system paths the user wouldn't put in a
// manifest. Workspace and home-but-not-system paths are kept.
func isNoisePath(p, scriptAbs string, extraPrefixes []string) bool {
	if p == "/" || p == scriptAbs {
		return true
	}
	if strings.HasPrefix(p, "/newroot/") {
		return true // bwrap setup
	}
	if strings.HasPrefix(p, spec.SandboxRoot+"/") || p == spec.SandboxRoot {
		return true
	}
	for _, pfx := range noisePrefixes {
		if p == pfx || strings.HasPrefix(p, pfx+"/") {
			return true
		}
	}
	for _, pfx := range extraPrefixes {
		if pfx == "" {
			continue
		}
		if p == pfx || strings.HasPrefix(p, pfx+"/") {
			return true
		}
	}
	return false
}

// noisePrefixes are roots that profile already covers via system mounts or
// that aren't meaningful for read rules. Order matters only for readability.
var noisePrefixes = []string{
	"/proc",
	"/sys",
	"/dev",
	"/tmp",
	"/run",
	"/usr",
	"/bin",
	"/sbin",
	"/lib",
	"/lib64",
	"/etc/ld.so.cache",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
	"/etc/ssl",
	"/etc/ca-certificates",
	"/etc/pki",
	"/etc/resolv.conf",
	"/etc/nsswitch.conf",
	"/etc/passwd",
	"/etc/group",
	"/etc/hosts",
	"/etc/localtime",
}

// filepath_IsAbs avoids importing path/filepath just for one call.
func filepath_IsAbs(p string) bool { return len(p) > 0 && p[0] == '/' }
