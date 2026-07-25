package profile

import (
	"reflect"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/policy"
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := Synthesize(tc.entrypoint, tc.interpreter, tc.obs)
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
		tc := tc
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
		p := Synthesize(entry, interp, obs)
		if p == nil {
			t.Fatal("Synthesize returned nil Policy")
		}
	})
}
