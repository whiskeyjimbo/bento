package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/policy"
)

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
	p := Synthesize("/work/run.py", "python3", obs)
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
	p := Synthesize("/work/run.py", "python3", obs)
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
	p := Synthesize("/work/run.py", "python3", obs)
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
	p := Synthesize("/work/run.py", "python3", obs)
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
	p := Synthesize("/work/run.py", "python3", obs)
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
	p := Synthesize("/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Write, []string{"/data"}) {
		t.Fatalf("write = %v, want the directory /data", p.Write)
	}
	if len(DropCovered(p.Read, p.Write)) != 0 {
		t.Fatalf("DropCovered = %v, want empty (all reads are under the writable /data)", DropCovered(p.Read, p.Write))
	}
}

func TestSynthesizeDropsSystemWriteGrants(t *testing.T) {
	// A write collapses to its parent directory. A target need only attempt a write
	// to a system config tree for the observer to record it, so Synthesize must not
	// propose a writable /etc/cron.d (and friends): approved, it is root code
	// execution. Neither isSystemPath (a hand-list of specific /etc files) nor the
	// caller's top-level-dir clamp catches these second-level directories.
	obs := Observation{
		Writes: []string{
			"/etc/cron.d/evil",
			"/etc/sudoers.d/x",
			"/etc/systemd/system/y.service",
			"/etc/profile.d/z.sh",
		},
	}
	p := Synthesize("/work/run.py", "python3", obs)
	if len(p.Write) != 0 {
		t.Fatalf("write = %v, want none (writable system config dirs must not be proposed)", p.Write)
	}
}

func TestSynthesizeExecOnlyWhenObserved(t *testing.T) {
	if got := Synthesize("/work/run.py", "", Observation{}).Exec; got != policy.ExecNone {
		t.Errorf("exec = %q, want none when nothing was spawned", got)
	}
	if got := Synthesize("/work/run.py", "", Observation{Execed: true}).Exec; got != policy.ExecAll {
		t.Errorf("exec = %q, want all when a subprocess was spawned", got)
	}
}

func TestSynthesizeDedupesHostsAndSorts(t *testing.T) {
	obs := Observation{Hosts: []HostPort{
		{Host: "b.example", Port: "443"},
		{Host: "a.example", Port: "443"},
		{Host: "b.example", Port: "443"},
	}}
	p := Synthesize("/work/run.py", "", obs)
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
	p := Synthesize("/srv/app/run.py", "python3", obs)
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
	p := Synthesize("/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Read, []string{"/data/keep.txt"}) {
		t.Errorf("read = %v, want only the non-runtime path kept", p.Read)
	}
	if len(p.Write) != 0 {
		t.Errorf("write = %v, want the runtime-dir writes dropped (a grant of /run is refused at run time)", p.Write)
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
	p := Synthesize("/work/run.py", "python3", obs)
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
