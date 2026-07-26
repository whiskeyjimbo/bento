package profile

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// mustSynthesize is Synthesize for the cases that must succeed, so a test asserting on
// the proposal does not restate the error check each time. The refusal itself has its
// own test.
func mustSynthesize(t *testing.T, entrypoint, interpreter string, obs Observation) *policy.Policy {
	t.Helper()
	p, err := Synthesize(entrypoint, interpreter, obs)
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	return p
}

func TestSynthesizeDropsInterpreterTree(t *testing.T) {
	// A version-managed interpreter lives under $HOME, so a system-prefix filter
	// alone would leave its whole runtime in the proposal.
	interp := "/home/u/.local/share/mise/installs/python/3.14/bin/python3.14"
	obs := Observation{
		Interpreter: interp,
		Reads: []string{
			interp,
			"/home/u/.local/share/mise/installs/python/3.14/lib/python3.14/os.py",
			"/etc/localtime",
			"/data/input.txt",
		},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Read, []string{"/data/input.txt"}) {
		t.Fatalf("read = %v, want just the script's own input", p.Read)
	}
}

func TestSynthesizeDropsScratchTmpPaths(t *testing.T) {
	// The sandbox's /tmp is a private tmpfs, so a randomly-named scratch file
	// there is not a grant a manifest should carry.
	obs := Observation{
		Reads:  []string{"/tmp/tmp8f3k/data", "/data/input.txt"},
		Writes: []string{"/tmp/tmpq1/scratch"},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Read, []string{"/data/input.txt"}) {
		t.Fatalf("read = %v, want /tmp scratch dropped", p.Read)
	}
	if len(p.Write) != 0 {
		t.Fatalf("write = %v, want /tmp scratch dropped", p.Write)
	}
}

func TestSynthesizeKeepsAbsolutePathsAndDirGranularWrites(t *testing.T) {
	// The observer anchors a relative open at the process's real working directory
	// (see resolveAt), so observations reaching Synthesize are absolute. An absolute
	// read is kept as observed; an absolute write becomes a grant of its directory.
	obs := Observation{
		Reads:  []string{"/work/input.txt"},
		Writes: []string{"/work/out/result.txt"},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Read, []string{"/work/input.txt"}) {
		t.Fatalf("read = %v, want /work/input.txt", p.Read)
	}
	if !reflect.DeepEqual(p.Write, []string{"/work/out"}) {
		t.Fatalf("write = %v, want the directory /work/out", p.Write)
	}
}

// A path that is still relative at Synthesize has no anchor it can trust - the
// observer emits absolute paths, so a relative one is a gap, not a workspace-
// relative file. Anchoring it at a guessed base (the run's starting directory) is
// exactly the mis-anchoring that produced grants naming files the run never opened,
// so it is dropped rather than turned into fiction.
func TestSynthesizeDropsRelativePaths(t *testing.T) {
	obs := Observation{
		Reads:  []string{"input.txt", "/work/real.txt"},
		Writes: []string{"out/result.txt"},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Read, []string{"/work/real.txt"}) {
		t.Errorf("read = %v, want only the absolute /work/real.txt (the relative one dropped)", p.Read)
	}
	if len(p.Write) != 0 {
		t.Errorf("write = %v, want the relative write dropped", p.Write)
	}
}

// bv2-2wy: a script that reads a credential store and also writes a file directly
// in $HOME must not have the read hidden. Synthesize must keep the read (rather than
// dropping it under the $HOME-level write dir), so the profiler's shield clamp can
// surface it before the broad write is itself dropped.
func TestSynthesizeKeepsReadCoveredByBroadWrite(t *testing.T) {
	obs := Observation{
		Reads:  []string{"/home/u/.ssh/id_rsa"},
		Writes: []string{"/home/u/results.csv"}, // -> writeDir /home/u, which covers the read
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	found := false
	for _, r := range p.Read {
		if r == "/home/u/.ssh/id_rsa" {
			found = true
		}
	}
	if !found {
		t.Fatalf("read = %v, want the ~/.ssh read preserved so the shield clamp can surface it", p.Read)
	}
}

func TestSynthesizeWriteIsDirGranularAndCoversReads(t *testing.T) {
	// A write to a file grants its directory. Synthesize itself no longer dedups the
	// reads it covers (the caller applies DropCovered after clamping shielded/broad
	// writes, so a read near a soon-dropped broad write stays visible); DropCovered
	// applied to a surviving narrow write still removes the covered reads.
	obs := Observation{
		Reads:  []string{"/data/shared.txt", "/data/nested/in.txt"},
		Writes: []string{"/data/out.txt"},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Write, []string{"/data"}) {
		t.Fatalf("write = %v, want the directory /data", p.Write)
	}
	if len(DropCovered(p.Read, p.Write)) != 0 {
		t.Fatalf("DropCovered = %v, want empty (all reads are under the writable /data)", DropCovered(p.Read, p.Write))
	}
}

func TestSynthesizeDropsSystemWriteGrants(t *testing.T) {
	// A write collapses to its parent directory. A target need only attempt a write
	// to a system tree for the observer to record it, so Synthesize must not propose a
	// writable one: approved, /etc/cron.d and /etc/sudoers.d are root code execution,
	// /var/spool/cron/crontabs is the cron spool, /boot is the kernel, and /opt and
	// /srv hold trees that get executed or served. Neither isSystemPath (a hand-list of
	// specific /etc files) nor the caller's top-level-dir clamp catches these.
	for _, w := range []string{
		"/etc/cron.d/evil",
		"/etc/sudoers.d/x",
		"/etc/systemd/system/y.service",
		"/etc/profile.d/z.sh",
		"/var/spool/cron/crontabs/user",
		"/var/lib/app/state.db",
		"/var/tmp/persist",
		"/boot/grub/grub.cfg",
		"/opt/app/run.sh",
		"/srv/www/index.html",
		"/root/.bashrc",
	} {
		p := mustSynthesize(t, "/work/run.py", "python3", Observation{Writes: []string{w}})
		if len(p.Write) != 0 {
			t.Errorf("write %s proposed the grant %v, want none (a writable system tree must not be proposed)", w, p.Write)
		}
	}
}

// The floors match a tree and what is under it, never a sibling that shares a name
// stem. /vartmp and /etcetera are ordinary paths, and silently dropping a write to one
// would hide from the reviewer a grant the run actually needs - the same rule
// isSystemPath follows for /etc/sslkeys vs /etc/ssl.
func TestSystemWriteFloorsDoNotOvermatchSiblings(t *testing.T) {
	for _, w := range []string{"/vartmp/out", "/etcetera/out", "/bootleg/out", "/opta/out", "/srvx/out", "/rootkit/out"} {
		p := mustSynthesize(t, "/work/run.py", "python3", Observation{Writes: []string{w}})
		if len(p.Write) != 1 {
			t.Errorf("write %s proposed %v, want the grant kept - a name-stem sibling is not a system tree", w, p.Write)
		}
	}
}

// A lexical floor is one symlink away from useless. converge mounts each accepted
// grant for the following round, so a target granted write:~/proj can drop a symlink
// to a system tree inside it and write through the link: the observer records the
// unresolved name, no floor matches it, and bwrap resolves at bind time - the reviewer
// approves a grant whose text says ~/proj and whose effect is a writable /etc. The
// floors must judge where the grant lands, not what it is spelled as.
// nonSystemTempDir returns a scratch directory that is NOT under a system tree.
// t.TempDir sits under /tmp, which Synthesize drops wholesale as sandbox scratch, so a
// symlink test rooted there passes no matter what the floors do - the containing grant
// was already skipped lexically. Anchoring at the test's own working directory keeps
// the path ordinary, so the floor is the only thing that can drop it.
func nonSystemTempDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(wd, "profiletest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// The floors judge resolved paths, and a working directory reached through a
	// symlink would otherwise make the "ordinary link is kept" case compare two
	// spellings of the same place.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestSynthesizeFloorsWritesThroughASymlink(t *testing.T) {
	proj := nonSystemTempDir(t)
	// Two shapes, because they fail differently: a link straight to the system tree,
	// and a link whose target is reached only through a path that does not exist yet -
	// EvalSymlinks fails outright on the latter, and the enforced run would create it.
	if err := os.Symlink("/etc", filepath.Join(proj, "cfg")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := os.Symlink("/usr", filepath.Join(proj, "sys")); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		filepath.Join(proj, "cfg", "cron.d", "evil"),
		filepath.Join(proj, "cfg", "not-there-yet", "sub", "evil"),
		filepath.Join(proj, "sys", "local", "bin", "evil"),
	} {
		p := mustSynthesize(t, "/work/run.py", "python3", Observation{Writes: []string{w}})
		if len(p.Write) != 0 {
			t.Errorf("write %s proposed the grant %v, want none - the floor must follow the symlink", w, p.Write)
		}
	}

	// A link that lands somewhere ordinary is untouched: resolving is only ever
	// additive, so an honest grant is never dropped by it.
	dest := nonSystemTempDir(t)
	if err := os.Symlink(dest, filepath.Join(proj, "data")); err != nil {
		t.Fatal(err)
	}
	p := mustSynthesize(t, "/work/run.py", "python3", Observation{Writes: []string{filepath.Join(proj, "data", "out.txt")}})
	if len(p.Write) != 1 {
		t.Errorf("write through a link to an ordinary directory proposed %v, want the grant kept", p.Write)
	}
}

func TestSynthesizeExecOnlyWhenObserved(t *testing.T) {
	if got := mustSynthesize(t, "/work/run.py", "", Observation{}).Exec; got != policy.ExecNone {
		t.Errorf("exec = %q, want none when nothing was spawned", got)
	}
	if got := mustSynthesize(t, "/work/run.py", "", Observation{Execed: true}).Exec; got != policy.ExecAll {
		t.Errorf("exec = %q, want all when a subprocess was spawned", got)
	}
}

func TestSynthesizeDedupesHostsAndSorts(t *testing.T) {
	obs := Observation{Hosts: []HostPort{
		{Host: "b.example", Port: "443"},
		{Host: "a.example", Port: "443"},
		{Host: "b.example", Port: "443"},
	}}
	p := mustSynthesize(t, "/work/run.py", "", obs)
	want := []policy.NetworkRule{
		{Host: "a.example", Port: "443"},
		{Host: "b.example", Port: "443"},
	}
	if !reflect.DeepEqual(p.Network, want) {
		t.Fatalf("network = %v, want deduped and sorted %v", p.Network, want)
	}
}

// A host symlink into procfs (/etc/mtab -> /proc/self/mounts on many distros,
// /dev/fd -> /proc/self/fd) has a script-owned looking name but resolves into /proc,
// and a grant of it is refused at run time (the sandbox has its own pid namespace
// and procfs). The filter must follow the symlink. resolvesIntoProc is what skip
// leans on for the case isSystemPath's prefix list cannot see. (The real /etc/mtab
// is under no system prefix; the temp symlink stands in for it, and is exercised
// directly here because t.TempDir lives under /tmp, which isSystemPath drops first.)
func TestResolvesIntoProc(t *testing.T) {
	dir := t.TempDir()
	mtab := filepath.Join(dir, "mtab")
	if err := os.Symlink("/proc/self/mounts", mtab); err != nil {
		t.Fatal(err)
	}
	if !resolvesIntoProc(mtab) {
		t.Errorf("a symlink to /proc/self/mounts must resolve into procfs")
	}
	ordinary := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(ordinary, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if resolvesIntoProc(ordinary) {
		t.Errorf("an ordinary file must not resolve into procfs")
	}
	// A path that does not exist (a write target not yet created) must not be
	// misclassified - EvalSymlinks errors, and the other filters handle it.
	if resolvesIntoProc(filepath.Join(dir, "missing")) {
		t.Errorf("a nonexistent path must not resolve into procfs")
	}
	// A symlink to exactly /proc (no trailing component) must resolve into procfs too.
	procRoot := filepath.Join(dir, "procroot")
	if err := os.Symlink("/proc", procRoot); err != nil {
		t.Fatal(err)
	}
	if !resolvesIntoProc(procRoot) {
		t.Errorf("a symlink to /proc itself must resolve into procfs")
	}
}

// The defect-1 scenario as a real distro presents it: /etc/mtab is a host symlink
// into procfs, and its name is under no system prefix, so only resolvesIntoProc -
// wired into skip - keeps it out of the proposal. Uses the host's real /etc/mtab so
// the whole skip path is exercised, not just the helper (t.TempDir lives under /tmp,
// which isSystemPath would drop first, masking the wiring).
func TestSynthesizeDropsMtabViaSkipWiring(t *testing.T) {
	if !resolvesIntoProc("/etc/mtab") {
		t.Skip("this host's /etc/mtab is not a symlink into procfs")
	}
	obs := Observation{Reads: []string{"/etc/mtab", "/srv/app/config.yaml"}}
	p := mustSynthesize(t, "/srv/app/run.py", "python3", obs)
	for _, r := range p.Read {
		if r == "/etc/mtab" {
			t.Errorf("/etc/mtab was proposed as a grant; skip is not wired to resolvesIntoProc: %v", p.Read)
		}
	}
	if !reflect.DeepEqual(p.Read, []string{"/srv/app/config.yaml"}) {
		t.Errorf("read = %v, want only the ordinary file kept", p.Read)
	}
}

// The runtime directories are always-shielded at run time (denylist.Runtime), so a
// grant naming them is refused - the profiler must not propose one. It observes an
// attempted access even though the shield blocked it (the observer records the path
// from the syscall, not the result), so both a read under /run and a write to a file
// directly in /run (which collapses to a grant of /run itself) must be dropped, as
// must /var/run, the pre-usrmerge spelling.
func TestSynthesizeDropsRuntimeDirGrants(t *testing.T) {
	obs := Observation{
		Reads:  []string{"/run/docker.sock", "/var/run/nscd/socket", "/data/keep.txt"},
		Writes: []string{"/run/app.pid", "/var/run/app/lock"},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Read, []string{"/data/keep.txt"}) {
		t.Errorf("read = %v, want only the non-runtime path kept", p.Read)
	}
	if len(p.Write) != 0 {
		t.Errorf("write = %v, want the runtime-dir writes dropped (a grant of /run is refused at run time)", p.Write)
	}
}

// The runtime install root is dropped as itself, not just as a prefix of the paths
// beneath it. A read of the root is the same runtime noise as a read of its stdlib; a
// write inside it would collapse to a grant of the root, and a write named at the root
// (mkdir, unlink, and rename are recorded against the entry, since they need write on
// the parent) would collapse to the tree holding every installed version. Neither
// escaping grant is clamped downstream - they are neither top-level nor the home dir -
// so approving such a manifest hands the target a writable interpreter tree.
func TestSynthesizeDropsRuntimeRootItself(t *testing.T) {
	root := "/opt/toolchains/python/3.14"
	obs := Observation{
		Interpreter: root + "/bin/python3.14",
		Reads:       []string{root, root + "/lib/python3.14/os.py", "/data/input.txt"},
		Writes:      []string{root + "/scratch.log", root},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Read, []string{"/data/input.txt"}) {
		t.Errorf("read = %v, want just the script's own input (the runtime root is noise)", p.Read)
	}
	if len(p.Write) != 0 {
		t.Errorf("write = %v, want no writable grant on the interpreter's install root or its parent", p.Write)
	}
}

// runtimeTree returns a genuine install root so its whole tree can be dropped, but
// must refuse a tree broad enough to enclose the user's credential stores - the
// filesystem root, a top-level dir, a home dir, or a shallow child of a home (~/.local
// for pipx/pip --user, ~/miniconda3). Prefixing such a tree out of the proposal would
// silently swallow the reads (~/.ssh/id_rsa, ~/.local/share/keyrings) the reviewer
// must see. The home-shape test is structural, not keyed on the profiler's own $HOME.
func TestRuntimeTreeRejectsBroadTrees(t *testing.T) {
	keep := map[string]string{
		"/opt/py/bin/python3":                                           "/opt/py",
		"/home/u/proj/.venv/bin/python":                                 "/home/u/proj/.venv",
		"/home/u/.local/share/mise/installs/python/3.14/bin/python3.14": "/home/u/.local/share/mise/installs/python/3.14",
	}
	for interp, want := range keep {
		if got := runtimeTree(interp); got != want {
			t.Errorf("runtimeTree(%q) = %q, want %q (a genuine install root)", interp, got, want)
		}
	}
	for _, interp := range []string{
		"/python", "/opt/python",
		"/home/u/bin/python", "/home/u/.local/bin/python", "/home/u/miniconda3/bin/python",
		"/root/bin/python", "/root/.local/bin/python",
		"/Users/u/bin/python", "/var/home/u/bin/python",
	} {
		if got := runtimeTree(interp); got != "" {
			t.Errorf("runtimeTree(%q) = %q, want empty (too broad to prefix-drop)", interp, got)
		}
	}
}

// A version manager can put the interpreter shim directly under $HOME (~/bin/python),
// so the computed runtime tree is the home dir itself. Dropping every read under it
// would silently swallow ~/.ssh/id_rsa before the reviewer or the shield clamp sees
// it, so the home dir must not be used as a runtime prefix.
func TestSynthesizeDoesNotDropHomeAsRuntimeTree(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		t.Skip("no usable home directory to exercise the home-tree guard")
	}
	secret := filepath.Join(home, ".ssh", "id_rsa")
	obs := Observation{
		Interpreter: filepath.Join(home, "bin", "python"),
		Reads:       []string{secret, filepath.Join(home, "project", "input.txt")},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	found := false
	for _, r := range p.Read {
		if r == secret {
			found = true
		}
	}
	if !found {
		t.Fatalf("read = %v, want %q surfaced (home must not be dropped as a runtime tree)", p.Read, secret)
	}
}

// The /etc runtime entries are exact files or directories, not free prefixes: a
// neighbor sharing a name stem (/etc/passwd.bak, /etc/hosts.allow) or a sibling
// directory (/etc/sslkeys, distinct from /etc/ssl) is a path the reviewer must see,
// not runtime noise to drop.
func TestIsSystemPathDoesNotOvermatchEtcSiblings(t *testing.T) {
	for _, p := range []string{
		"/etc/passwd.bak", "/etc/passwd-", "/etc/hosts.allow", "/etc/hosts.deny",
		"/etc/group-", "/etc/sslkeys/priv", "/etc/pki-backup/key",
	} {
		if isSystemPath(p) {
			t.Errorf("isSystemPath(%q) = true, want false (an /etc sibling must surface)", p)
		}
	}
	for _, p := range []string{
		"/etc/passwd", "/etc/hosts", "/etc/resolv.conf", "/etc/localtime",
		"/etc/ssl", "/etc/ssl/certs/ca.pem", "/etc/pki/tls/cert.pem",
		"/etc/ld.so.cache", "/etc/ld.so.conf.d/x.conf",
	} {
		if !isSystemPath(p) {
			t.Errorf("isSystemPath(%q) = false, want true (a genuine runtime entry)", p)
		}
	}
}

// The bare-directory match is general: a write to a file directly inside any
// directory-prefix system path collapses (via writeDir) to the bare directory, which
// must still be recognized as a system path.
func TestIsSystemPathMatchesBareDirectory(t *testing.T) {
	for _, p := range []string{"/run", "/var/run", "/proc", "/sys", "/dev", "/tmp", "/nix/store"} {
		if !isSystemPath(p) {
			t.Errorf("isSystemPath(%q) = false, want true (bare directory of a prefix entry)", p)
		}
	}
	// A path that merely shares a name prefix must not match (no false positive).
	for _, p := range []string{"/running", "/tmpfoo", "/devices"} {
		if isSystemPath(p) {
			t.Errorf("isSystemPath(%q) = true, want false (not a system path)", p)
		}
	}
}

// A version-managed runtime is reached through a symlinked name, so the target's
// stdlib reads carry that name while the resolved interpreter path names a store
// directory the reads never mention. Dropping by the resolved tree alone leaves the
// whole stdlib in the proposal; both trees must drop, and the script's own file must
// still survive.
func TestSynthesizeDropsRuntimeReachedByItsUnresolvedName(t *testing.T) {
	const named = "/opt/pyenv/versions/3.12"
	const store = "/nix/store/abc-python3-3.12"
	obs := Observation{
		Interpreter:     store + "/bin/python3",
		InterpreterName: named + "/bin/python3",
		Reads: []string{
			named + "/lib/python3.12/os.py",
			store + "/lib/python3.12/encodings/__init__.py",
			"/data/input.txt",
		},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Read, []string{"/data/input.txt"}) {
		t.Errorf("read = %v, want only the script's own input; both runtime trees are noise", p.Read)
	}
}

// An observation with a seccomp kill is missing everything the killed process did, and
// re-profiling reproduces it exactly, so there is no proposal to make - only one that
// would look complete and then become enforcement policy. Refusing in Synthesize rather
// than in a frontend is what makes that true for every caller: the check used to live
// in cmd/bento alone, so an embedder assembling its own proposal got a full policy,
// Exec:all included, out of a run it could not see.
func TestSynthesizeRefusesASeccompKilledObservation(t *testing.T) {
	obs := Observation{
		Reads:         []string{"/work/data.txt"},
		Writes:        []string{"/work/out.txt"},
		Execed:        true,
		SeccompKilled: true,
	}
	p, err := Synthesize("/work/run.py", "python3", obs)
	if !errors.Is(err, ErrSeccompKilled) {
		t.Fatalf("err = %v, want ErrSeccompKilled", err)
	}
	if p != nil {
		t.Errorf("policy = %+v, want none - a refused observation must not yield a proposal to use by mistake", p)
	}

	// Every other shortfall leaves an observation that is merely incomplete, which the
	// frontend warns about and a human fixes by profiling again. Refusing those too
	// would stop `bento profile` on any script that exits nonzero.
	for _, partial := range []Observation{{ExitCode: 1}, {Signaled: true, Signal: 9}, {Dropped: 3}} {
		if _, err := Synthesize("/work/run.py", "python3", partial); err != nil {
			t.Errorf("Synthesize(%+v) = %v, want a proposal - an incomplete run is a warning, not a refusal", partial, err)
		}
	}
}

// A write collapses to its parent directory, so one touched file in another user's home
// proposes that whole account - including the rc files that run as them at their next
// login. Nothing downstream catches it: the caller's broad clamp knows only the root, a
// top-level directory, and the profiler's OWN home, and the credential shields are built
// from the profiler's home too, so a second user's stores are not in the list at all.
func TestSynthesizeDropsForeignHomeWriteGrants(t *testing.T) {
	for _, w := range []string{"/home/other/.bashrc", "/var/home/other/.profile", "/Users/other/.zshrc", "/root/.bashrc"} {
		p := mustSynthesize(t, "/work/run.py", "python3", Observation{Writes: []string{w}})
		if len(p.Write) != 0 {
			t.Errorf("write %s proposed the grant %v, want none - a whole foreign account must not be proposed", w, p.Write)
		}
	}

	// A directory INSIDE another user's home is not floored here: it is an ordinary
	// grant the reviewer can judge, and the enforcer's own shields still cover the
	// credential stores under it. Only the account root is the over-broad collapse.
	p := mustSynthesize(t, "/work/run.py", "python3", Observation{Writes: []string{"/home/other/shared/out.txt"}})
	if len(p.Write) != 1 {
		t.Errorf("write inside a foreign home proposed %v, want the grant kept", p.Write)
	}

	// The profiler's own home stays, because the caller's broad clamp drops it AND
	// reports it to the reviewer as over-broad; flooring it here would take it away
	// silently and show the reviewer less than they see today.
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		t.Skip("no usable home directory to distinguish own from foreign")
	}
	p = mustSynthesize(t, "/work/run.py", "python3", Observation{Writes: []string{filepath.Join(home, "out.txt")}})
	if len(p.Write) != 1 || p.Write[0] != filepath.Clean(home) {
		t.Errorf("write = %v, want the profiler's own home kept for the caller's broad clamp to report", p.Write)
	}
}
