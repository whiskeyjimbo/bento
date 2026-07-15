package profile

import (
	"reflect"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
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

func TestSynthesizeAbsolutizesRelativePaths(t *testing.T) {
	// The script runs with its directory as the working directory, so a relative
	// path it opened must be anchored there or the manifest would mean something
	// else at run time. A write becomes a grant of its directory.
	obs := Observation{
		Reads:  []string{"input.txt"},
		Writes: []string{"out/result.txt"},
	}
	p := Synthesize("/work/run.py", "python3", obs)
	if !reflect.DeepEqual(p.Read, []string{"/work/input.txt"}) {
		t.Fatalf("read = %v, want /work/input.txt", p.Read)
	}
	if !reflect.DeepEqual(p.Write, []string{"/work/out"}) {
		t.Fatalf("write = %v, want the directory /work/out", p.Write)
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
