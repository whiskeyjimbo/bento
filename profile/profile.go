// Package profile turns what a script was observed doing into a proposed policy.
//
// A profiling run executes the script under a default-deny sandbox with observation; this
// package filters the raw observations down to the paths and hosts a human would
// actually put in a manifest, and assembles a Policy from them. The result is a
// proposal to review, not a final manifest - profiling sees only the code paths
// one run exercised.
package profile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/policy"
)

// ErrSeccompKilled is returned by Synthesize for an observation in which a process
// died on SIGSYS. It names both causes because they are not distinguishable from the
// observation: bento's own foreign-arch guard (the amd64 observer cannot decode a
// 32-bit process's syscalls) and a target that installs its own sandbox both land here.
var ErrSeccompKilled = errors.New("a process in this run was killed by a seccomp filter, so everything it touched is unobservable and no manifest can be proposed from this run: either it used a non-native (32-bit) syscall ABI, which bento's profiler refuses because it decodes amd64 syscalls only, or the target installs its own sandbox. Build the target for amd64, run it without its own sandbox, or write the manifest by hand")

// HostPort is one observed outbound destination.
type HostPort struct {
	Host string
	Port string
}

// Observation is everything a profiling run saw.
type Observation struct {
	Reads  []string
	Writes []string
	// Absent is the subset of the accessed paths that nothing was ever found at: every
	// open of one returned "no such file". They stay in Reads/Writes because the run
	// meant to open them and enforcement has to reproduce the same answer, but a path
	// that never resolved cannot have been read, which is what lets a warning about a
	// deceptive filename say whether there was a file behind it.
	Absent []string
	// Probed is the subset of the accessed paths that nothing ever opened: every syscall
	// naming one only asked whether it was there. They stay in Reads for the same reason
	// Absent's do - a stat that succeeds during profiling and returns ENOENT under
	// enforcement sends the program down a different branch, so the grant is real - but a
	// path the program never opened is one it may never have named itself, which is what
	// lets the entrypoint's resolution chain be told from a directory it listed.
	Probed []string
	Hosts  []HostPort
	// Blocked is the subset of Hosts whose egress the proxy's upstream guard refused,
	// because the name resolved to an address the sandbox must not reach (loopback,
	// private space, cloud metadata). It is the one refusal a profiling run can tell
	// apart: the discovery allowlist is *:* and consults no gate, so nothing is denied
	// by policy, and with egress not forwarded (the default) nothing is dialed at all -
	// so this is populated only under --allow-network. A host recorded here is one an
	// enforced run would refuse the same way, whatever the manifest grants.
	Blocked []HostPort
	// Untunneled are the destinations the run addressed without asking the proxy to
	// tunnel to them - plain http:// through a CONNECT proxy. They are NOT in Hosts:
	// bento's egress cannot carry such a request whatever the manifest says, so proposing
	// a rule for one would write a grant that reads as satisfied and never carries
	// traffic. They are recorded instead, so the proposal can say what it declined to
	// propose and why, which is the only place the destination survives at all.
	Untunneled []HostPort
	Execed     bool
	// Interpreter is the absolute, resolved path the interpreter ran from (empty
	// for a self-interpreting binary). It anchors dropping the interpreter's own
	// runtime tree from the proposal - under a version manager that tree lives in
	// $HOME, so a system-prefix filter alone does not catch it.
	Interpreter string
	// InterpreterName is the interpreter's absolute path before symlink resolution,
	// empty when resolution changed nothing. A version-managed runtime is reached
	// through a symlinked name (~/.pyenv/versions/3.12 -> a store path, or /home ->
	// /var/home), and the target's stdlib reads carry THAT prefix, not the resolved
	// one - so dropping the runtime by the resolved tree alone leaves the whole stdlib
	// in the proposal as noise.
	InterpreterName string
	// ExitCode is the profiled run's exit status (128+signal when Signaled).
	// Signaled/Signal report a run that died from a signal (crash, OOM, timeout). A
	// nonzero or signaled run may have stopped partway, so the observations - and any
	// manifest synthesized from them - may be incomplete; the frontend warns.
	ExitCode int
	Signaled bool
	Signal   int
	// Dropped counts file accesses the observer saw happen but could not name - a
	// pathname it could not read out of the tracee, an anchor directory /proc would not
	// resolve. Nonzero means this observation is missing accesses the run really made,
	// so a manifest synthesized from it is short by an unknown amount; the frontend
	// warns, because the alternative is a proposal that looks complete and is not.
	Dropped int
	// SeccompKilled reports that a process in this run died on SIGSYS - a kill-mode
	// seccomp filter refused one of its syscalls. Everything that process touched is
	// absent from this observation, and re-profiling produces the same result, so a
	// manifest must not be synthesized from it. During profiling the filter is normally
	// bento's own foreign-arch guard (a 32-bit process, which the amd64 observer cannot
	// decode), but a target that sandboxes itself dies the same way, so the two are not
	// distinguishable here and the message must not claim otherwise.
	SeccompKilled bool
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
}

// sandboxTmp is the tmpfs every sandbox mounts at /tmp, for the profiling run and the
// enforced run alike.
const sandboxTmp = "/tmp"

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
//
// It refuses an observation that recorded a seccomp kill, because everything that
// process touched is absent from it and profiling again produces the same result - so
// there is no proposal to make, only one that would look complete. The refusal lives
// here rather than in a frontend because the proposal becomes enforcement policy
// whoever assembles it; every other shortfall (a nonzero exit, a signal, dropped
// accesses) leaves an observation that is merely incomplete, which a frontend warns
// about and a human can act on by profiling again.
func Synthesize(entrypoint, interpreter string, interpreterArgs []string, obs Observation) (*policy.Policy, error) {
	if obs.SeccompKilled {
		return nil, ErrSeccompKilled
	}
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

	// Both the resolved tree and the one the target actually opened through: they differ
	// under a version manager, and only the latter matches the observed reads. Each goes
	// through runtimeTree's own safety ratchet, so a name broad enough to enclose a
	// credential store still drops out rather than hiding one.
	runtimes := []string{runtimeTree(obs.Interpreter), runtimeTree(obs.InterpreterName)}
	// The install root itself counts as in-tree, not just the paths beneath it: a read
	// of the root is the same runtime noise as a read of its stdlib.
	inRuntime := func(p string) bool {
		for _, r := range runtimes {
			if r != "" && (p == r || strings.HasPrefix(p, r+"/")) {
				return true
			}
		}
		return false
	}
	skip := func(p string) bool {
		return p == "" || p == entrypoint || p == obs.Interpreter || p == obs.InterpreterName ||
			Unrepresentable(p) || isSystemPath(p) || SandboxScratch(p) || Socket(p) ||
			resolvesIntoProc(p) || inRuntime(p)
	}

	// An interpreter handed a script by absolute path resolves it a component at a
	// time - bash stats /home/u, /home/u/proj, /home/u/proj/deep and so on down - and
	// each of those probes succeeds, so the observer records the whole chain as read.
	// Proposing it is noise that grows with how deep the script sits: a script four
	// directories down produces four grants nobody asked for, each one broader than the
	// last, and the interactive session asks about every one of them.
	//
	// The chain grants the enforced run nothing. It binds the script's own directory,
	// and bwrap builds the mount points above it to reach there, so the same probes -
	// including a `cd ..`, which the observer records the same way - succeed against
	// that skeleton whether or not a grant names the ancestor.
	//
	// Both conditions are load-bearing. Probe-only is what separates the resolution
	// chain from a directory the script really listed: a readdir opens its directory
	// first, so an enumerated ancestor is not probe-only and keeps its grant, which the
	// skeleton would otherwise answer with only the next component down. And probe-only
	// alone is not enough to drop anything - a stat that succeeds while profiling and
	// returns ENOENT under enforcement sends the program down a different branch, so
	// outside this one chain a probe needs its grant like any other access.
	//
	// The script's own directory is not an ancestor by this test and stays granted;
	// only the strict ancestors above it go. Reads only, because skip is shared with
	// the write path, where the same test would drop a script's write to a directory it
	// merely sits below (~/proj/out.log from ~/proj/deep/nested/run.sh) - a real access,
	// recurring every round, that a proposal must not lose.
	entrypointDir := filepath.Dir(entrypoint)
	// Keyed on the canonical spelling, because readSkip is asked about a path canon has
	// already been through and the observer's own name for it need not match.
	probed := map[string]bool{}
	for _, p := range obs.Probed {
		if c := canon(p); c != "" {
			probed[c] = true
		}
	}
	readSkip := func(p string) bool {
		return skip(p) || (probed[p] && p != entrypointDir && isUnder(entrypointDir, p))
	}

	// Write grants are directory-granular (bwrap can only make a directory
	// writable in a rename-safe way), so an observed write to a file becomes a
	// grant of its directory.
	writeDir := func(p string) string {
		if !filepath.IsAbs(p) {
			return ""
		}
		// A socket write is dropped by its observed name too, and for a sharper reason than
		// the runtime case: the collapse would turn a write to /tmp/.X11-unix/X0 into a
		// writable grant of the directory holding every display's socket, which no later
		// filter recognizes as anything but an ordinary directory.
		if Socket(p) {
			return ""
		}
		// A runtime write is dropped by its observed name, before the collapse. mkdir,
		// unlink, and rename need write access to the parent, so they are recorded
		// against the entry itself: collapsing a write named at the runtime root first
		// would propose its parent - the tree holding every installed version - which no
		// later filter recognizes as runtime.
		if inRuntime(p) {
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
	//
	// The floors run against the resolved name as well as the observed one, because a
	// lexical floor is one symlink away from useless: converge mounts each accepted
	// grant for the following round, so a target granted write:~/proj can drop a
	// symlink to /etc inside it and write through the link. The observer records the
	// unresolved name, which no floor matches, while bwrap resolves at bind time and
	// the reviewer approves a grant whose text says ~/proj. Resolving is only ever
	// additive - a grant is never kept because of it - and it stays on the write side:
	// resolving reads would change which name the reviewer is shown. It resolves through
	// the same function the backend binds with, so the two cannot answer differently
	// about where a grant lands.
	writeSkip := func(dir string) bool {
		return skip(dir) || FlooredWrite(dir) || ScratchWrite(dir)
	}

	p := &policy.Policy{
		Entrypoint:      entrypoint,
		Interpreter:     interpreter,
		InterpreterArgs: interpreterArgs,
		Read:            cleanPaths(obs.Reads, canon, readSkip),
		Write:           cleanPaths(obs.Writes, writeDir, writeSkip),
		Exec:            policy.ExecNone,
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
		rule := policy.NetworkRule{Host: h.Host, Port: h.Port}
		// The recording proxy screens a CONNECT target for control bytes and a canonical
		// port, but not the host against the policy grammar, so a target can reach an
		// underscore hostname or a shorthand literal like 127.1 and have it observed. A
		// rule naming one cannot be written to a manifest at all, so proposing it fails
		// the whole profiling run at the final marshal, with the session's work already
		// spent. Drop it here the way an unanchored relative path is dropped above; the
		// frontend names what was withheld.
		if rule.Validate() != nil || seen[key] {
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
	return p, nil
}

// systemWriteRoots are trees under which a proposed writable-directory grant is a
// privilege-escalation or system-integrity vector rather than a legitimate need.
// /etc/cron.d, /etc/sudoers.d, /etc/systemd/system and /etc/profile.d run code as
// root or another user; /var covers the cron spool, the service state under
// /var/lib, and /var/tmp, which is a persistent world-writable tree rather than the
// sandbox's private scratch; /boot is the kernel and bootloader; /opt and /srv hold
// software and service trees that are executed or served. /root is root's home, so a
// write there reaches its shell rc files.
//
// A machine-local script that genuinely needs one of these is not blocked - the grant
// is left out of the PROPOSAL, and a reviewer who wants it writes it into the manifest
// themselves, which is the deliberate act flooring exists to require. Only writes are
// floored; reads under these trees are still proposed so the reviewer sees them.
var systemWriteRoots = []string{"/etc", "/var", "/boot", "/opt", "/srv", "/root"}

// isSystemWriteDir reports whether a collapsed write-grant directory lands in a
// system tree. It matches the bare root ("/etc") and anything strictly beneath it
// ("/etc/cron.d"), but never a sibling that merely shares a name stem - /etcetera and
// /vartmp are ordinary paths the reviewer must still see, the same rule isSystemPath
// applies.
func isSystemWriteDir(dir string) bool {
	for _, root := range systemWriteRoots {
		if dir == root || strings.HasPrefix(dir, root+"/") {
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

// Unrepresentable reports whether an observed path cannot be written to a manifest,
// because it carries a character policy refuses in a path field - a control byte, a
// bidi override, an invisible rune, a line separator, or a byte that is not valid UTF-8
// (the loader rejects a non-UTF-8 document whole, so such a path is unloadable twice over). A target creates its own filenames, so it can
// produce one; a proposal naming it fails validation at the marshal that ends the
// profiling run, discarding the whole session's work. Synthesize drops it instead, and
// this is exported so a frontend can name what was withheld.
//
// It defers to the same screen policy.Validate applies, so the two cannot disagree
// about which paths a manifest can hold.
func Unrepresentable(path string) bool {
	_, bad := policy.FirstUnsafeRune(path)
	return bad
}

// Socket reports whether an observed path is a unix socket on the host.
//
// A socket is never a script's own storage: it is a read-write channel to whatever
// process is listening, and the kernel refuses a write through a read-only bind only for
// regular files, directories, and symlinks, so a `read:` grant of one confers whatever
// the peer will do. The session sockets sit in the ordinary places a proposal reaches -
// /tmp/.X11-unix/X0 is control of the live X session, /tmp/ssh-XXXX/agent.N is use of
// every forwarded key, and a distribution that parks the database socket under
// /var/lib/mysql puts one there too. denylist shields the ones under /run and inside a
// credential store; these are the residual it names as uncovered, and no list of paths
// can enumerate them, so the profiler judges the file type instead.
//
// It follows symlinks, because the grant is bound at the resolved target and it is that
// target's type which decides what the grant confers.
//
// A script that genuinely talks to one is not blocked - the grant is left out of the
// PROPOSAL, and a reviewer who wants it writes it in by hand, the same deliberate act
// FlooredWrite requires. Exported so a frontend can say which access was withheld.
func Socket(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// SandboxScratch reports whether an observed path names the sandbox's own private
// tmpfs rather than content on the host. Both runs mount a fresh tmpfs at /tmp, so
// the two cases separate on whether the path exists on the host at all: one that does
// not is a file the run created inside that tmpfs, which the enforced run gets for
// free and no grant can name; one that does is host content the sandbox can only see
// through a grant - a scratch directory from `mktemp -d`, a CI workspace, an agent's
// working tree - and withholding it drafts a manifest whose script cannot find its own
// files. /tmp itself is always scratch: the enforced run refuses a grant of it whole,
// because binding the host's /tmp over the sandbox's would hand the target every other
// process's temp files.
//
// It is exported so a frontend can tell the reviewer that an observed write went to
// scratch and will not persist. The stat is the narrow part: a path outside /tmp answers
// lexically, without asking the filesystem anything.
//
// It answers about the host as it stands after the run, which is the only moment it can:
// a directory the script created and removed on its way out looks exactly like tmpfs
// scratch here. That answer is still the right one - there is no host path left for a
// grant to name - but it is why the frontend's message must not claim to know where the
// write landed.
func SandboxScratch(p string) bool {
	if p == sandboxTmp {
		return true
	}
	if !strings.HasPrefix(p, sandboxTmp+"/") {
		return false
	}
	// Only a definite absence means scratch. A path bento cannot stat for some other
	// reason (a mode that denies search on a parent) is host content it merely could not
	// look at, and dropping it there would put back the silent shortfall this test exists
	// to remove - the reviewer sees the grant and decides.
	_, err := os.Lstat(p)
	return errors.Is(err, fs.ErrNotExist)
}

// FlooredWrite reports whether a collapsed write-grant directory is one Synthesize
// withholds from a proposal: a system tree, the container every user's home sits in, or
// another user's home. It is exported so a frontend can tell the reviewer which
// observed writes were withheld and why - a grant that vanishes with no message leaves
// the script failing EACCES at enforce time with nothing to read.
//
// Callers pass the DIRECTORY a write collapses to (filepath.Dir of an observed path),
// which is the granularity a write grant has.
//
// It answers about where the grant LANDS as well as how it is spelled, so the frontend
// names the same withheld writes Synthesize dropped: the floors resolve (a target
// granted write:~/proj drops a symlink to /etc inside it and writes through the link),
// and a report that did not would go quiet on exactly the case the resolution exists
// for.
// isSystemPath is asked on both spellings, though only the resolved one reaches
// Synthesize through here (the literal is already inside skip): a /usr write reported
// when it arrives through a link and passed over in silence when it is spelled straight
// is the same withheld class answering two ways.
func FlooredWrite(dir string) bool {
	if flooredWrite(dir) || isSystemPath(dir) {
		return true
	}
	resolved := pathresolve.Existing(dir)
	return resolved != dir && (isSystemPath(resolved) || flooredWrite(resolved))
}

// ScratchWrite is the same question for the sandbox's private tmpfs: a grant withheld
// because the name is not on the host, judged on both spellings.
func ScratchWrite(dir string) bool {
	if SandboxScratch(dir) {
		return true
	}
	resolved := pathresolve.Existing(dir)
	return resolved != dir && SandboxScratch(resolved)
}

func flooredWrite(dir string) bool {
	// A home container that lives under a system root (/var/home on an ostree layout,
	// where the user's own home IS /var/home/u) holds accounts, not system state, so the
	// home rules judge what is inside it rather than the system floor - which would
	// otherwise drop every write grant the profiler's own user makes on that layout.
	// The container itself is not exempt: a grant of it is every account at once.
	if inHomeContainer(dir) {
		return isForeignHomeTree(dir)
	}
	return isSystemWriteDir(dir) || isForeignHomeTree(dir)
}

// inHomeContainer reports whether dir sits strictly under a directory that user homes
// live in, so it names something within somebody's account rather than the container.
func inHomeContainer(dir string) bool {
	for _, c := range homeContainers {
		if strings.HasPrefix(dir, c+"/") {
			return true
		}
	}
	return false
}

// isForeignHomeTree reports whether a collapsed write-grant directory is a home
// directory the profiler does not own - another user's account, or the container
// holding every account.
//
// The collapse is what makes this reachable: an observed write to a single file becomes
// a grant of its directory, so a target that touches /home/other/.bashrc proposes a
// writable /home/other - their whole account, including the rc files that run as them
// at their next login. Nothing downstream catches it. The caller's broad clamp knows
// only the root, a top-level directory, and the profiler's OWN home, and the credential
// shields are built from the profiler's home too, so a second user's stores are not in
// the list at all.
//
// The profiler's own home is deliberately NOT floored. It is already dropped by that
// broad clamp, which also REPORTS it to the reviewer as an over-broad grant; dropping
// it earlier would take the grant away silently and leave the reviewer with less than
// they see today. The one exception is /root, which systemWriteRoots floors outright:
// under `sudo bento profile` that is the profiler's own home, but it is also root's
// account, and a proposal that hands a target write access to root's shell rc files is
// not one to soften for the convenience of seeing it reported.
func isForeignHomeTree(dir string) bool {
	if slices.Contains(homeContainers, dir) {
		return true
	}
	if !isHomeShapedTree(dir) || !slices.Contains(homeContainers, filepath.Dir(dir)) {
		return false
	}
	// Both anchors the shields use, since either can be this account's home: under sudo -H
	// $HOME and the passwd entry name different directories and only one of them is the
	// account being profiled.
	anchors, err := denylist.HomeAnchors()
	if err != nil {
		// With no usable home to compare against, every home is foreign - the fail-safe
		// direction, since the alternative proposes a whole account.
		return true
	}
	for _, home := range anchors {
		if dir == home {
			return false
		}
		// A symlinked home (/home -> /var/home) reaches the same account under two names,
		// and only one of them compares equal above. Resolved through pathresolve, the way
		// the shields and the clamp resolve their own anchors, so a home that does not
		// exist yet is not called someone else's account on a technicality.
		if dir == pathresolve.Existing(home) {
			return false
		}
	}
	return true
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
	// home; the anchor match is a cheap supplement for a home outside the usual
	// containers (an unusable home is skipped, as in clampShieldedGrants).
	if tree == "/" || filepath.Dir(tree) == "/" || isHomeShapedTree(tree) {
		return ""
	}
	if anchors, _ := denylist.HomeAnchors(); slices.Contains(anchors, tree) {
		return ""
	}
	return tree
}

// homeContainers are the directories user home directories sit directly under. A tree
// that is a home ($container/user) or a shallow child of one ($container/user/x) can
// enclose that user's credential stores, so it is too broad to prefix-drop.
var homeContainers = []string{"/home", "/var/home", "/Users"}

// HomeContainers returns those directories, so a frontend deciding which home a grant
// belongs to answers from the same list the write floors do. The two disagreeing is a
// grant floored here and reported as nobody's home there.
func HomeContainers() []string { return slices.Clone(homeContainers) }

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
