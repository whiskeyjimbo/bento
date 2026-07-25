//go:build linux

package main

import (
	"context"
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
		t.Skip("bwrap not installed")
	}
	if err := exec.Command(bwrap, "--unshare-user", "--unshare-net", "--bind", "/", "/", "/bin/true").Run(); err != nil {
		t.Skip("unprivileged user namespaces unavailable on this host")
	}
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
	round1, err := profileRound(cfgRun, base)
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
	round2, err := profileRound(cfgRun, granted)
	if err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if !hasPath(round2.Read, data) {
		t.Errorf("granting the config must let the script reach the downstream path %q; got %v", data, round2.Read)
	}
}
