package profile

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

func TestAdversarialSynthesize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		entrypoint  string
		interpreter string
		obs         Observation
		wantRead    []string
		wantWrite   []string
		wantExec    policy.ExecMode
		wantNet     []policy.NetworkRule
	}{
		{
			name:        "drop_relative_paths",
			entrypoint:  "/app/main.py",
			interpreter: "python3",
			obs: Observation{
				Reads:  []string{"relative/read.txt", "./local.txt"},
				Writes: []string{"relative/write.txt", "../out.txt"},
			},
			wantRead:  nil,
			wantWrite: nil,
			wantExec:  policy.ExecNone,
		},
		{
			name:        "drop_system_directory_reads",
			entrypoint:  "/app/main.py",
			interpreter: "python3",
			obs: Observation{
				Reads: []string{
					"/usr/lib/libc.so",
					"/lib64/ld-linux.so",
					"/etc/ssl/certs/ca.pem",
					"/proc/cpuinfo",
					"/sys/fs/cgroup",
					"/tmp/scratch.tmp",
					"/etc/passwd",
					"/etc/resolv.conf",
				},
			},
			wantRead:  nil,
			wantWrite: nil,
			wantExec:  policy.ExecNone,
		},
		{
			name:        "preserve_neighbor_system_files",
			entrypoint:  "/app/main.py",
			interpreter: "python3",
			obs: Observation{
				Reads: []string{
					"/etc/passwd.bak",
					"/etc/hosts.allow",
					"/etc/sslkeys",
				},
			},
			wantRead:  []string{"/etc/hosts.allow", "/etc/passwd.bak", "/etc/sslkeys"},
			wantWrite: nil,
			wantExec:  policy.ExecNone,
		},
		{
			name:        "floor_system_write_directories",
			entrypoint:  "/app/main.py",
			interpreter: "python3",
			obs: Observation{
				Writes: []string{
					"/etc/cron.d/malicious_job",
					"/etc/sudoers.d/backdoor",
					"/etc/passwd",
				},
			},
			wantRead:  nil,
			wantWrite: nil,
			wantExec:  policy.ExecNone,
		},
		{
			name:        "preserve_home_credential_read_when_interpreter_in_home",
			entrypoint:  "/home/user/app/main.py",
			interpreter: "/home/user/bin/custom_python",
			obs: Observation{
				Interpreter: "/home/user/bin/custom_python",
				Reads: []string{
					"/home/user/.ssh/id_rsa",
				},
			},
			wantRead:  []string{"/home/user/.ssh/id_rsa"},
			wantWrite: nil,
			wantExec:  policy.ExecNone,
		},
		{
			name:        "deduplicate_and_sort_network_hosts",
			entrypoint:  "/app/main.py",
			interpreter: "python3",
			obs: Observation{
				Hosts: []HostPort{
					{Host: "a.example", Port: "443"},
					{Host: "a.example", Port: "443"},
					{Host: "a.example4", Port: "43"},
					{Host: "", Port: "80"},
				},
			},
			wantRead:  nil,
			wantWrite: nil,
			wantExec:  policy.ExecNone,
			wantNet: []policy.NetworkRule{
				{Host: "a.example4", Port: "43"},
				{Host: "a.example", Port: "443"},
			},
		},
		{
			name:        "propose_exec_all_when_execed",
			entrypoint:  "/app/main.py",
			interpreter: "python3",
			obs: Observation{
				Execed: true,
			},
			wantRead:  nil,
			wantWrite: nil,
			wantExec:  policy.ExecAll,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := mustSynthesize(t, tc.entrypoint, tc.interpreter, tc.obs)
			if p == nil {
				t.Fatal("Synthesize returned nil policy")
			}
			if !slices.Equal(p.Read, tc.wantRead) {
				t.Errorf("Read = %v; want %v", p.Read, tc.wantRead)
			}
			if !slices.Equal(p.Write, tc.wantWrite) {
				t.Errorf("Write = %v; want %v", p.Write, tc.wantWrite)
			}
			if p.Exec != tc.wantExec {
				t.Errorf("Exec = %v; want %v", p.Exec, tc.wantExec)
			}
			if !reflect.DeepEqual(p.Network, tc.wantNet) {
				t.Errorf("Network = %v; want %v", p.Network, tc.wantNet)
			}
		})
	}
}

func TestAdversarialDropCovered(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		reads     []string
		writeDirs []string
		wantReads []string
	}{
		{
			name:      "drop_exact_match",
			reads:     []string{"/data/file.txt"},
			writeDirs: []string{"/data/file.txt"},
			wantReads: nil,
		},
		{
			name:      "drop_nested_child",
			reads:     []string{"/data/dir/file.txt", "/data/dir/sub/file2.txt"},
			writeDirs: []string{"/data/dir"},
			wantReads: nil,
		},
		{
			name:      "preserve_sibling_stem",
			reads:     []string{"/data/dir-sibling/file.txt"},
			writeDirs: []string{"/data/dir"},
			wantReads: []string{"/data/dir-sibling/file.txt"},
		},
		{
			name:      "preserve_parent_directory",
			reads:     []string{"/data"},
			writeDirs: []string{"/data/dir"},
			wantReads: []string{"/data"},
		},
		{
			name:      "handle_nil_slices",
			reads:     nil,
			writeDirs: nil,
			wantReads: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DropCovered(tc.reads, tc.writeDirs)
			if !slices.Equal(got, tc.wantReads) {
				t.Fatalf("DropCovered(%v, %v) = %v; want %v", tc.reads, tc.writeDirs, got, tc.wantReads)
			}
		})
	}
}

func FuzzProfileSynthesize(f *testing.F) {
	f.Add("/bin/app", "python3", "/data/in.txt", "/data/out.txt", "api.example.com", "443", true)
	f.Add("", "", "", "", "", "", false)
	f.Add("\x00", "\x1b[31m", "relative/path", "/etc/cron.d/job", "\u202E", "80", false)

	f.Fuzz(func(t *testing.T, entry, interp, read, write, host, port string, execed bool) {
		obs := Observation{
			Reads:  []string{read},
			Writes: []string{write},
			Hosts:  []HostPort{{Host: host, Port: port}},
			Execed: execed,
		}
		p := mustSynthesize(t, entry, interp, obs)
		if p == nil {
			t.Fatal("Synthesize returned nil Policy")
		}

		// Soundness, the narrowing half of the one-sided invariant: approve stamps this
		// proposal, so a grant the observation does not justify is a permission nobody
		// asked for. Ancestor-or-equal rather than membership, because a write collapses
		// to its directory - the observed /data/out.txt is proposed as /data.
		// The root is spelled with its own separator, so the ordinary prefix test would
		// read "/" as justifying nothing at all - and a grant of "/" is the one this most
		// has to judge on its merits rather than on a string artifact.
		justified := func(grant string, observed ...string) bool {
			prefix := strings.TrimSuffix(grant, "/") + "/"
			for _, o := range observed {
				// Cleaned, because the grant is: "//0/" is observed and "/0" proposed, and
				// the difference is spelling rather than reach.
				if !filepath.IsAbs(o) {
					continue
				}
				o = filepath.Clean(o)
				if o == grant || strings.HasPrefix(o, prefix) {
					return true
				}
			}
			return false
		}
		for _, g := range p.Read {
			if !justified(g, read) {
				t.Errorf("read grant %q is not justified by the observed read %q", g, read)
			}
		}
		for _, g := range p.Write {
			if !justified(g, write) {
				t.Errorf("write grant %q is not justified by the observed write %q", g, write)
			}
		}

		// A path carrying a deceiving rune is what Unrepresentable withholds, and the
		// seeds feed one as a host and /etc/cron.d/job as a write. A grant that round-trips
		// one unflagged is a manifest whose text does not read as what it grants.
		for _, g := range slices.Concat(p.Read, p.Write) {
			if Unrepresentable(g) {
				t.Errorf("grant %q carries a deceiving rune and was proposed anyway", g)
			}
		}

		// A proposal the validator refuses is one nobody can approve, and the two are
		// separately maintained - the network rules are already screened against it here,
		// the paths are not.
		//
		// The entrypoint and interpreter are swapped for real ones first. Synthesize passes
		// both through verbatim from its caller, which has a resolved path for each, so a
		// fuzzed entrypoint only ever proves that Validate rejects the fuzzer's own string -
		// it says nothing about what Synthesize derived.
		grants := *p
		grants.Entrypoint, grants.Interpreter = "/bin/app", "python3"
		if err := grants.Validate(); err != nil {
			t.Errorf("the synthesized grants do not validate: %v", err)
		}

		// The observation is the whole input, so synthesizing twice must agree: a
		// proposal that moves between rounds invalidates the approval stamped on the
		// first one.
		again := mustSynthesize(t, entry, interp, obs)
		if !slices.Equal(p.Read, again.Read) || !slices.Equal(p.Write, again.Write) || !slices.Equal(p.Network, again.Network) {
			t.Errorf("Synthesize is not idempotent over one observation:\n first: %+v\n again: %+v", p, again)
		}
	})
}
