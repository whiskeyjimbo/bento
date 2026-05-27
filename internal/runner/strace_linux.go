//go:build linux

package runner

import (
	"bufio"
	"os"
	"os/exec"
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

// wrapWithStrace prepends strace to (exe, args) so openat() calls in the
// child tree are recorded to tracePath. The "-qq" suppresses strace's own
// attach/detach lines; "-f" follows forks; "-e trace=openat,openat2" limits
// recorded syscalls to file opens.
func wrapWithStrace(exe string, args []string, tracePath string) (string, []string) {
	out := []string{
		"-f",
		"-qq",
		"-e", "trace=openat,openat2",
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

	seen := make(map[string]bool) // path -> OK (any success wins)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		path, ok, found := extractOpenatAttempt(sc.Text())
		if !found {
			continue
		}
		if !filepath_IsAbs(path) {
			continue
		}
		if isNoisePath(path, scriptAbs, extraPrefixes) {
			continue
		}
		if prev, exists := seen[path]; !exists || (!prev && ok) {
			seen[path] = ok
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]FSOpen, 0, len(seen))
	for p, ok := range seen {
		out = append(out, FSOpen{Path: p, OK: ok})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// extractOpenatAttempt parses a single strace line and returns (path, ok, found).
// `found` is true when the line is an openat/openat2 call we recognize; `ok`
// is true when the return value is a non-negative fd. Lines look like:
//
//	[pid 1234] openat(AT_FDCWD, "/foo/bar", O_RDONLY) = 3
//	openat(AT_FDCWD, "/foo/bar", O_RDONLY) = -1 ENOENT (No such file)
func extractOpenatAttempt(line string) (string, bool, bool) {
	i := strings.Index(line, "openat")
	if i < 0 {
		return "", false, false
	}
	paren := strings.Index(line[i:], "(")
	if paren < 0 {
		return "", false, false
	}
	rest := line[i+paren+1:]
	if !strings.HasPrefix(rest, "AT_FDCWD") {
		return "", false, false
	}
	q1 := strings.Index(rest, "\"")
	if q1 < 0 {
		return "", false, false
	}
	q2 := strings.Index(rest[q1+1:], "\"")
	if q2 < 0 {
		return "", false, false
	}
	path := rest[q1+1 : q1+1+q2]
	eq := strings.LastIndex(line, "= ")
	if eq < 0 {
		return "", false, false
	}
	tail := strings.TrimSpace(line[eq+2:])
	end := 0
	for end < len(tail) && (tail[end] == '-' || (tail[end] >= '0' && tail[end] <= '9')) {
		end++
	}
	if end == 0 {
		return "", false, false
	}
	n, err := strconv.Atoi(tail[:end])
	if err != nil {
		return "", false, false
	}
	return path, n >= 0, true
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
