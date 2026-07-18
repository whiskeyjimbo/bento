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

func TestSynthesizeWriteIsDirGranularAndCoversReads(t *testing.T) {
	// A write to a file grants its directory, and a read at or below that
	// directory is already covered, so it is not listed again.
	obs := Observation{
		Reads:  []string{"/data/shared.txt", "/data/nested/in.txt"},
		Writes: []string{"/data/out.txt"},
	}
	p := Synthesize("/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Write, []string{"/data"}) {
		t.Fatalf("write = %v, want the directory /data", p.Write)
	}
	if len(p.Read) != 0 {
		t.Fatalf("read = %v, want empty (all reads are under the writable /data)", p.Read)
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
}
