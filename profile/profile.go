// Package profile turns what a script was observed doing into a proposed policy.
//
// A profiling run executes the script permissively under observation; this
// package filters the raw observations down to the paths and hosts a human would
// actually put in a manifest, and assembles a Policy from them. The result is a
// proposal to review, not a final manifest - profiling sees only the code paths
// one run exercised.
package profile

import (
	"path/filepath"
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

// systemPrefixes are paths every program touches to load its runtime and libs.
// They are the interpreter's business, not the script's, so they never belong in
// a manifest and are dropped from the proposal.
var systemPrefixes = []string{
	"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
	"/etc/ld.so", "/etc/ssl", "/etc/ca-certificates", "/etc/pki", "/etc/alternatives",
	"/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/resolv.conf", "/etc/hosts",
	"/etc/localtime",
	"/proc/", "/sys/", "/dev/", "/run/", "/var/run/", "/nix/store/",
	// The sandbox's /tmp is a private tmpfs; anything a run writes there is
	// ephemeral and randomly named, so it is scratch, never a manifest grant.
	"/tmp/",
}

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

	p := &policy.Policy{
		Entrypoint:  entrypoint,
		Interpreter: interpreter,
		Read:        cleanPaths(obs.Reads, canon, skip),
		Write:       cleanPaths(obs.Writes, writeDir, skip),
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
		return p.Network[i].Host+p.Network[i].Port < p.Network[j].Host+p.Network[j].Port
	})
	return p
}

func isSystemPath(p string) bool {
	for _, pre := range systemPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
		// A directory-prefix entry ("/run/") must also match the bare directory
		// ("/run") itself, which is what writeDir yields for an observed write to a
		// file directly inside it (write to /run/app.pid -> the grant /run). Without
		// this the profiler proposes a grant of the shielded directory that the run
		// then refuses.
		if len(pre) > 1 && pre[len(pre)-1] == '/' && p == pre[:len(pre)-1] {
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
// A system interpreter is already covered by systemPrefixes and returns "".
func runtimeTree(interp string) string {
	if interp == "" || isSystemPath(interp) {
		return ""
	}
	dir := filepath.Dir(interp)
	if filepath.Base(dir) == "bin" {
		return filepath.Dir(dir)
	}
	return dir
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
