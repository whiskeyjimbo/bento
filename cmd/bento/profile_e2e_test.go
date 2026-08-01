//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/policy"
)

// The linux backend confines a target by re-executing this binary as a hidden launch
// stage, so the test process must dispatch those stages - the embedder contract from
// backend.DispatchReexec's own docs. Without it, a profiling round re-execs the test
// binary and it runs the suite again instead of the launcher.
func TestMain(m *testing.M) {
	backend.DispatchReexec()
	os.Exit(m.Run())
}

func requireSandbox(t *testing.T) {
	t.Helper()
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		skipMissingDep(t, "bwrap not installed")
	}
	// --proc is part of the guard, not decoration: a container that permits the user
	// namespace but masks paths under /proc refuses the procfs mount every real sandbox
	// makes, and a guard that only unshares would let these tests run on to fail there
	// instead of skipping.
	if err := exec.Command(bwrap, "--unshare-user", "--unshare-net", "--bind", "/", "/", "--proc", "/proc", "/bin/true").Run(); err != nil {
		skipMissingDep(t, "the bwrap sandbox cannot be built on this host (user namespace or /proc mount refused)")
	}
}

// skipMissingDep skips for a missing host dependency, or fails when
// BENTO_REQUIRE_TEST_DEPS is set. A behavioral test that self-skips reports a pass having
// asserted nothing, so on a host without bwrap or unprivileged user namespaces a run is
// indistinguishable from one that exercised the shield; the variable is how a host that
// is supposed to have them - CI, and `make test` - says so.
func skipMissingDep(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("BENTO_REQUIRE_TEST_DEPS") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// The mechanism the whole convergence loop rests on, end to end under real bwrap: a
// content-branching script reads a config to decide what to do next. Under default-deny
// (round 1) that read fails, so it never attempts the downstream path - the manifest
// under-reports. Grant the config so the next round mounts it with real content, and the
// script proceeds and attempts the downstream path, which is now recorded. This proves
// "mount an accepted grant -> the target proceeds -> new paths appear", which converge()
// orchestrates and the unit tests exercise with a fake round.
func TestProfileRoundGrantRevealsDownstream(t *testing.T) {
	requireSandbox(t)

	// HOME lives under the real home (not /tmp, which the sandbox always overmounts with
	// its own tmpfs) so a grant can bind its real content back in.
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	home, err := os.MkdirTemp(realHome, "bento-converge-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)

	cfgDir := filepath.Join(home, ".config", "tool")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(cfgDir, "config")
	data := filepath.Join(cfgDir, "data")
	if err := os.WriteFile(cfg, []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(data, []byte("downstream\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "branch.sh")
	// Opens its config (an openat the observer records); only if that open succeeds does
	// it reach the downstream data path. A `[ -r ]` test would use faccessat, which the
	// observer does not record - the branch must hinge on a real open.
	src := "if cat \"$HOME/.config/tool/config\" >/dev/null 2>&1; then cat \"$HOME/.config/tool/data\"; fi\n"
	if err := os.WriteFile(script, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}

	cfgRun := profileConfig{
		ctx: context.Background(), script: script, interpreter: "sh",
		env: map[string]string{"HOME": home}, targetStdin: nil,
	}
	base := discoveryPolicy(script, "sh", nil)

	// Round 1: default-deny. The config read fails, so the downstream path is never
	// attempted and must not appear in the proposal.
	round1, _, err := profileRound(cfgRun, base)
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	if !hasPath(round1.Read, cfg) {
		t.Errorf("round 1 must record the attempted config read %q; got %v", cfg, round1.Read)
	}
	if hasPath(round1.Read, data) {
		t.Fatalf("round 1 under default-deny must NOT reach the downstream path %q; got %v", data, round1.Read)
	}

	// Round 2: grant the config so it is mounted with real content. The script now reads
	// it, proceeds, and attempts the downstream path, which is recorded.
	granted := &policy.Policy{
		Entrypoint: script, Interpreter: "sh", Exec: policy.ExecAll,
		Network: base.Network, Read: append(append([]string{}, base.Read...), cfg),
	}
	round2, _, err := profileRound(cfgRun, granted)
	if err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if !hasPath(round2.Read, data) {
		t.Errorf("granting the config must let the script reach the downstream path %q; got %v", data, round2.Read)
	}
}

// The non-interactive retry, driven through the command rather than through
// profileRound: a target that died only because a granted write directory does not
// exist yet is profiled a second time with it created, and under --allow-network it is
// not, because that pass would repeat the target's real egress. retryWriteDirs pins the
// decision; this pins that the call site honors it. The two runs differ only in the
// flag, so the envelope's complete - the same condition as the exit code - is the whole
// assertion: drop the skip branch and the --allow-network case turns complete too.
func TestProfileRetriesMissingWriteDirUnlessEgressForwarded(t *testing.T) {
	requireSandbox(t)

	for _, tc := range []struct {
		name         string
		allowNetwork bool
		wantComplete bool
	}{
		{"default-deny egress", false, true},
		{"forwarded egress", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Under the real home, not t.TempDir(): the sandbox overmounts /tmp with its own
			// tmpfs, so a write discovered there is withheld as scratch and never reaches the
			// proposal this turns on.
			realHome, err := os.UserHomeDir()
			if err != nil {
				t.Skip("no home directory")
			}
			dir, err := os.MkdirTemp(realHome, "bento-retry-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)

			// Writes into a subdirectory of its own directory - which profiling grants write
			// to, so the proposal carries it - and dies because nothing created it. That is
			// exactly the shape the retry exists for.
			script := filepath.Join(dir, "write.sh")
			missing := filepath.Join(dir, "outdir")
			if err := os.WriteFile(script, []byte("echo hi > \"$(dirname \"$0\")/outdir/file\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}

			args := []string{"--json", "--out", filepath.Join(t.TempDir(), "m.yaml")}
			if tc.allowNetwork {
				args = append(args, "--allow-network")
			}
			out, runErr := runProfileNonInteractively(t, append(args, script)...)

			var env struct {
				Complete bool `json:"complete"`
			}
			if err := json.Unmarshal([]byte(out), &env); err != nil {
				t.Fatalf("decoding the envelope: %v\n%s", err, out)
			}
			if env.Complete != tc.wantComplete {
				t.Errorf("complete = %v, want %v (exit %v)\n%s", env.Complete, tc.wantComplete, runErr, out)
			}
			// The envelope alone cannot say whether the retry ran or the first pass merely
			// finished; the directory on the host can, since only the retry creates it.
			if _, err := os.Lstat(missing); os.IsNotExist(err) == tc.wantComplete {
				t.Errorf("Lstat(%q) = %v, want the directory to exist only when the retry ran", missing, err)
			}
		})
	}
}

// runProfileNonInteractively drives the profile command with stdin pointed at /dev/null,
// so it takes the single-pass branch whatever the `go test` invocation inherited - a run
// from a terminal would otherwise reach the convergence loop and block on its prompts.
func runProfileNonInteractively(t *testing.T, args ...string) (string, error) {
	t.Helper()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	saved := os.Stdin
	os.Stdin = devnull
	defer func() { os.Stdin = saved }()
	return runCapturingStdout(t, newProfileCmd(), args...)
}
