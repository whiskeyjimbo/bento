// Package profile turns what a script was observed doing into a proposed policy.
//
// A profiling run executes the script under a default-deny sandbox with observation; this
// package filters the raw observations down to the paths and hosts a human would
// actually put in a manifest, and assembles a Policy from them. The result is a
// proposal to review, not a final manifest - profiling sees only the code paths
// one run exercised.
package profile

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/whiskeyjimbo/bento-v2/policy"
)

// HostPort is one observed outbound destination.
type HostPort struct {
	Host string
	Port string
}

// Observation is everything a profiling run saw.
type Observation struct {
	Reads  []string
	Writes []string
	Hosts  []HostPort
	Execed bool
	// Interpreter is the absolute, resolved path the interpreter ran from (empty
	// for a self-interpreting binary). It anchors dropping the interpreter's own
	// runtime tree from the proposal - under a version manager that tree lives in
	// $HOME, so a system-prefix filter alone does not catch it.
	Interpreter string
	// ExitCode is the profiled run's exit status (128+signal when Signaled).
	// Signaled/Signal report a run that died from a signal (crash, OOM, timeout). A
	// nonzero or signaled run may have stopped partway, so the observations - and any
	// manifest synthesized from them - may be incomplete; the frontend warns.
	ExitCode int
	Signaled bool
	Signal   int
}

// systemDirs are the runtime and OS directory trees every program touches to load
// its libs and config. Any path at or under one is the interpreter's business, not
// the script's, so it never belongs in a manifest. Matched as the directory itself
// or anything beneath it - a sibling that merely shares a name stem (/etc/sslkeys vs
// /etc/ssl) is a distinct path the reviewer must still see.
var systemDirs = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/etc/ssl", "/etc/ca-certificates", "/etc/pki", "/etc/alternatives",
	"/proc", "/sys", "/dev", "/run", "/var/run", "/nix/store",
	// The sandbox's /tmp is a private tmpfs; anything a run writes there is
	// ephemeral and randomly named, so it is scratch, never a manifest grant.
	"/tmp",
}

// systemFiles are the exact /etc files a program reads to resolve users, hosts, and
// time. Matched by equality, not prefix: a neighbor like /etc/passwd.bak or
// /etc/hosts.allow is a different file (often a credential-adjacent one) the reviewer
// must see, so it must not be swallowed by a prefix match on the runtime name.
var systemFiles = []string{
	"/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/resolv.conf",
	"/etc/hosts", "/etc/localtime",
}

// ldSoPrefix matches the dynamic-linker config family: /etc/ld.so.cache,
// /etc/ld.so.conf, and /etc/ld.so.conf.d/ are files and a directory sharing the
// /etc/ld.so stem rather than living under an /etc/ld.so/ directory. A bare prefix is
// correct here precisely because no unrelated /etc/ld.so* path exists to over-match.
const ldSoPrefix = "/etc/ld.so"

// Synthesize assembles a proposed policy from observations. It drops the paths
// every program touches (the interpreter's runtime, /proc, /dev) and the script
// and interpreter themselves, keeping the reads and writes that describe what
// *this* script needs. Exec is proposed as `all` only if the script actually
// spawned a subprocess; otherwise the default deny stands.
func Synthesize(entrypoint, interpreter string, obs Observation) *policy.Policy {
	// The observer emits absolute paths - it anchors a relative open at the process's
	// real working directory - so a path that is still relative here has no anchor we
	// can trust. Guessing one (the run's starting directory) produced grants that named
	// files the run never touched, so a relative path is dropped instead of turned into
	// fiction.
	canon := func(p string) string {
		if !filepath.IsAbs(p) {
			return ""
		}
		return filepath.Clean(p)
	}

	runtime := runtimeTree(obs.Interpreter)
	skip := func(p string) bool {
		return p == "" || p == entrypoint || p == obs.Interpreter || isSystemPath(p) ||
			resolvesIntoProc(p) ||
			(runtime != "" && strings.HasPrefix(p, runtime+"/"))
	}

	// Write grants are directory-granular (bwrap can only make a directory
	// writable in a rename-safe way), so an observed write to a file becomes a
	// grant of its directory.
	writeDir := func(p string) string {
		if !filepath.IsAbs(p) {
			return ""
		}
		return filepath.Dir(p)
	}

	// A write collapses to a directory grant, so an observed write anywhere under a
	// system config tree would propose a writable system directory: a target that
	// merely attempts a write to /etc/cron.d seeds a writable /etc/cron.d grant that
	// becomes root code execution if a reviewer approves it. The observer records the
	// attempted path even when default-deny blocked the write, so trying is enough.
	// isSystemPath's /etc coverage is a hand-list of specific runtime files, not a
	// directory prefix, so it misses these subdirectories; floor writes to them here.
	// Reads under /etc still surface unchanged - the reviewer needs to see them.
	writeSkip := func(dir string) bool {
		return skip(dir) || isSystemWriteDir(dir)
	}

	p := &policy.Policy{
		Entrypoint:  entrypoint,
		Interpreter: interpreter,
		Read:        cleanPaths(obs.Reads, canon, skip),
		Write:       cleanPaths(obs.Writes, writeDir, writeSkip),
		Exec:        policy.ExecNone,
	}
	if obs.Execed {
		p.Exec = policy.ExecAll
	}
	// Deduping a read that a write grant already covers (DropCovered) is deliberately
	// NOT done here: the caller applies it only after clamping the shielded and
	// over-broad write grants, so a read of a credential store the script also wrote
	// near (e.g. ~/.ssh under a $HOME-level write) is surfaced to the reviewer rather
	// than silently swallowed by a broad write that is itself about to be dropped.

	seen := map[string]bool{}
	for _, h := range obs.Hosts {
		key := h.Host + ":" + h.Port
		if h.Host == "" || seen[key] {
			continue
		}
		seen[key] = true
		p.Network = append(p.Network, policy.NetworkRule{Host: h.Host, Port: h.Port})
	}
	sort.Slice(p.Network, func(i, j int) bool {
		// Sort on the same host:port key the dedup above uses. Concatenating host and
		// port with no separator would collide {a.example,443} with {a.example4,43}, and
		// sort.Slice is unstable, so observation order could flip the two - changing the
		// serialized manifest and invalidating a prior approval.
		return p.Network[i].Host+":"+p.Network[i].Port < p.Network[j].Host+":"+p.Network[j].Port
	})
	return p
}

// systemWriteRoots are trees under which a proposed writable-directory grant is a
// privilege-escalation vector rather than a legitimate need: /etc/cron.d,
// /etc/sudoers.d, /etc/systemd/system, /etc/profile.d and the like all run code as
// root or another user. Only writes are floored here; reads under these trees are
// still proposed so the reviewer sees them.
var systemWriteRoots = []string{"/etc/"}

// isSystemWriteDir reports whether a collapsed write-grant directory lands in a
// system config tree. It matches the tree ("/etc/cron.d") and the bare root
// ("/etc") itself.
func isSystemWriteDir(dir string) bool {
	for _, root := range systemWriteRoots {
		if strings.HasPrefix(dir, root) || dir == root[:len(root)-1] {
			return true
		}
	}
	return false
}

func isSystemPath(p string) bool {
	if strings.HasPrefix(p, ldSoPrefix) {
		return true
	}
	if slices.Contains(systemFiles, p) {
		return true
	}
	for _, dir := range systemDirs {
		// The bare directory itself matches (a write to /run/app.pid collapses via
		// writeDir to the grant /run, which must be recognized as system too);
		// otherwise only paths strictly beneath it, so /etc/sslkeys is not caught by
		// /etc/ssl.
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return false
}

// resolvesIntoProc reports whether p, once its symlinks are followed, lands in
// procfs. The observed name can look script-owned while pointing into /proc:
// /etc/mtab and /dev/fd are host symlinks to /proc/self/mounts and /proc/self/fd,
// and /proc/self resolves on to /proc/<pid>. A grant of such a path is refused at
// run time (the sandbox has its own pid namespace and procfs), so proposing it
// yields a manifest bento rejects. Resolving here catches it while cleanPaths still
// emits the observed name for the honorable cases. This runs on the host after a
// real profiling run, so following the symlink is against the same filesystem the
// grant would be resolved against. A path that does not resolve (a write target not
// yet created) is left for the other filters.
func resolvesIntoProc(p string) bool {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return false
	}
	return resolved == "/proc" || strings.HasPrefix(resolved, "/proc/")
}

// runtimeTree returns the install root of the interpreter (…/bin/python3 → …),
// so the whole runtime it loads can be dropped from the proposal in one prefix.
// A system interpreter is already covered by isSystemPath and returns "".
func runtimeTree(interp string) string {
	if interp == "" || isSystemPath(interp) {
		return ""
	}
	dir := filepath.Dir(interp)
	tree := dir
	if filepath.Base(dir) == "bin" {
		tree = filepath.Dir(dir)
	}
	// Every check here is a one-way ratchet toward "not a runtime tree": being too
	// conservative only leaves the interpreter's stdlib in the proposal as noise, while
	// being too aggressive silently drops the credential reads (~/.ssh/id_rsa,
	// ~/.local/share/keyrings) the reviewer must see. So reject any tree broad enough to
	// enclose a user's credential stores - the root, a top-level dir, or a home-shaped
	// tree (a home directory itself or a shallow child of one like ~/.local under
	// pipx/pip --user, or ~/miniconda3). The home-shape test is structural, not keyed on
	// the profiler's own $HOME, so it holds under sudo, an unset HOME, or a symlinked
	// home; the $HOME match is a cheap supplement for a home outside the usual
	// containers (matched empty/relative-home is skipped, as in clampShieldedGrants).
	if tree == "/" || filepath.Dir(tree) == "/" || isHomeShapedTree(tree) {
		return ""
	}
	if home, _ := os.UserHomeDir(); home != "" && filepath.IsAbs(home) && tree == filepath.Clean(home) {
		return ""
	}
	return tree
}

// homeContainers are the directories user home directories sit directly under. A tree
// that is a home ($container/user) or a shallow child of one ($container/user/x) can
// enclose that user's credential stores, so it is too broad to prefix-drop.
var homeContainers = []string{"/home", "/var/home", "/Users"}

// isHomeShapedTree reports whether tree looks like a user's home directory or a shallow
// child of one, without consulting $HOME - so it catches an interpreter under another
// user's home (sudo) or a symlinked home that a $HOME comparison would miss. /root is a
// home in its own right.
func isHomeShapedTree(tree string) bool {
	parent := filepath.Dir(tree)
	if tree == "/root" || parent == "/root" {
		return true
	}
	// tree is a home itself (parent is a container) or a direct child of one (the
	// container is the grandparent).
	return slices.Contains(homeContainers, parent) || slices.Contains(homeContainers, filepath.Dir(parent))
}

// cleanPaths canonicalizes, filters, de-duplicates, and sorts observed paths.
func cleanPaths(paths []string, canon func(string) string, skip func(string) bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		p = canon(p)
		if skip(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// DropCovered removes any read path that is at or below one of the write
// directories, since a write grant is readable too.
func DropCovered(reads, writeDirs []string) []string {
	var out []string
	for _, r := range reads {
		covered := false
		for _, w := range writeDirs {
			if r == w || isUnder(r, w) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, r)
		}
	}
	return out
}

// isUnder reports whether child is inside parent.
func isUnder(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
