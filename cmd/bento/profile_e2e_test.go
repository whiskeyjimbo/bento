//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
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
	base := discoveryPolicy(script, "sh", nil, nil)

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

// `bento profile ./s.sh > out.txt` has to capture what `bento run` would, so the
// target's stdout goes to this command's stdout - except under --json, where stdout
// carries the envelope alone and merging the target's output into it would corrupt the
// machine contract.
func TestProfilePassesTheTargetsStdoutThroughUnlessJSON(t *testing.T) {
	requireSandbox(t)

	for _, tc := range []struct {
		name    string
		args    []string
		wantOut bool
	}{
		{"default", nil, true},
		{"json", []string{"--json"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "hello.sh")
			if err := os.WriteFile(script, []byte("echo THIS_IS_STDOUT\necho THIS_IS_STDERR >&2\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, tc.args...), "--out", filepath.Join(dir, "m.yaml"), script)
			out, err := runProfileNonInteractively(t, args...)
			if err != nil {
				t.Fatalf("profile: %v\n%s", err, out)
			}
			if got := strings.Contains(out, "THIS_IS_STDOUT"); got != tc.wantOut {
				t.Errorf("target stdout on this command's stdout = %v, want %v\n%s", got, tc.wantOut, out)
			}
			// The target's stderr stays on stderr in both modes; finding it here would mean
			// the routing merged the streams rather than separating them.
			if strings.Contains(out, "THIS_IS_STDERR") {
				t.Errorf("the target's stderr must not reach stdout\n%s", out)
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

// The 127 warning's claims about the world, under real bwrap. The unit tests pin which
// branch fires for a given Observation; nothing there can tell whether the branch is
// TRUE - whether a bare name really is lost by the search path, and whether an absolute
// one really does get recorded. Three messages shipped that were confidently wrong about
// exactly that (one fired on a script already calling the tool by absolute path, one
// offered a read grant that cannot affect a search path, one promised a proposal it does
// not always produce), and the whole unit suite was green for all of them. Same reason
// examples/probe/verify.sh exists: nothing else executes the advice we print.
//
// So each case asserts the proposal, not only the prose - the read list is where "the
// observer has nothing to record" is either true or false.
func TestProfileWarnsOnlyWhenTheSearchPathLostTheTool(t *testing.T) {
	requireSandbox(t)

	// A sibling of the script's directory: real on the host, and absent inside the
	// sandbox, since discoveryPolicy grants the script's own directory and nothing else.
	// That is the shape that sets Execed - the exec is attempted and fails - as opposed
	// to a bare name, which never reaches execve at all.
	toolDir := t.TempDir()
	tool := filepath.Join(toolDir, "bentotool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho TOOL-RAN\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	profile := func(t *testing.T, name, src string) (*policy.Policy, roundStatus) {
		t.Helper()
		dir := t.TempDir()
		script := filepath.Join(dir, name)
		if err := os.WriteFile(script, []byte(src), 0o755); err != nil {
			t.Fatal(err)
		}
		cfg := profileConfig{
			ctx: context.Background(), script: script, interpreter: "sh",
			env: map[string]string{}, targetStdin: nil,
		}
		got, status, err := profileRound(cfg, discoveryPolicy(script, "sh", nil, nil))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return got, status
	}

	// The control. Without it the bare-name case could pass because the tool is broken
	// rather than because the search path lost it - the same copy, reachable by path,
	// has to run clean.
	t.Run("reachable by path", func(t *testing.T) {
		dir := t.TempDir()
		local := filepath.Join(dir, "bentotool")
		if err := os.WriteFile(local, []byte("#!/bin/sh\necho TOOL-RAN\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(dir, "local.sh")
		if err := os.WriteFile(script, []byte("./bentotool\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cfg := profileConfig{
			ctx: context.Background(), script: script, interpreter: "sh",
			env: map[string]string{}, targetStdin: nil,
		}
		_, status, err := profileRound(cfg, discoveryPolicy(script, "sh", nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		if status.unfinished != "" {
			t.Fatalf("a tool that runs must not warn at all; got %q", status.unfinished)
		}
	})

	// Bare name. The sandbox searches SandboxPath and nowhere else, so the tool's real
	// directory is never named - which is precisely why the message says another round
	// changes nothing, and why the read list must not contain it.
	t.Run("lost by the search path", func(t *testing.T) {
		got, status := profile(t, "bare.sh", "bentotool\n")
		if !strings.Contains(status.unfinished, enforce.SandboxPath) {
			t.Errorf("a bare name lost by the search path must name PATH; got %q", status.unfinished)
		}
		if hasPath(got.Read, tool) {
			t.Errorf("a bare name never names %q, so it cannot be recorded; got %v", tool, got.Read)
		}
	})

	// Absolute path to the same tool. The exec IS attempted, so the observer records the
	// target and proposes it - the message's claim that profiling again changes nothing
	// would be false here, which is why this case must fall through to the generic
	// wording. Asserting the read list is what catches an Execed gate that stopped
	// working, rather than only catching the wrong string.
	t.Run("named but not mounted", func(t *testing.T) {
		got, status := profile(t, "abs.sh", tool+"\n")
		if strings.Contains(status.unfinished, enforce.SandboxPath) {
			t.Errorf("an exec'd path is not a search-path miss; got %q", status.unfinished)
		}
		if !hasPath(got.Read, tool) {
			t.Errorf("an attempted exec of %q must be recorded and proposed; got %v", tool, got.Read)
		}
	})
}
