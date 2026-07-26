//go:build linux

package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The degraded tier's limit scope is only reachable through runDegraded, which
// enforce.Run selects only on a userns-blocked host - so the end-to-end test skips
// everywhere else and the scope wiring would go unproven on a normal machine. This
// calls runDegraded directly (it does not consult usableNamespaces itself) to pin the
// three facts the reverted first attempt got wrong: the scoped launcher actually
// reaches the systemd user bus with the sanitized policy environment, the target really
// runs (a scope that fails to create must not read as a clean exit), and the bus
// variables added for systemd-run are stripped again before the target sees them.
func TestDegradedRunAppliesLimitsWithSanitizedEnv(t *testing.T) {
	requireDegraded(t)
	if ok, reason := canCreateScope(); !ok {
		t.Skip("no usable systemd user scope: " + reason)
	}
	if _, added := withScopeBusVars(nil, nil); len(added) == 0 {
		t.Skip("host sets no session bus variables; the sanitized-env case cannot be exercised")
	}

	bin := buildEnvDumpProbe(t)
	outDir := t.TempDir()
	dump := filepath.Join(outDir, "environ")

	p := &policy.Policy{
		Entrypoint: bin,
		Write:      []string{outDir},
		Exec:       policy.ExecNone,
		Limits:     policy.Limits{Memory: "256M"},
	}
	env := map[string]string{"BENTO_DUMP": dump, "BENTO_TEST_VAR": "policy-value"}

	var out strings.Builder
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p,
		enforce.Process{Stdout: &out, Stderr: &out, Env: env})
	if err != nil {
		t.Fatalf("scoped degraded run failed: %v\noutput:\n%s", err, out.String())
	}
	// The probe exits 7, so a scope that swallowed the target (systemd-run's own exit
	// status) cannot pass as a successful run.
	if res.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7 (the target's own); output:\n%s", res.ExitCode, out.String())
	}

	b, err := os.ReadFile(dump)
	if err != nil {
		t.Fatalf("the target never ran under the scope: %v\noutput:\n%s", err, out.String())
	}
	got := string(b)
	if !strings.Contains(got, "BENTO_TEST_VAR=policy-value") {
		t.Errorf("target lost the policy environment: %q", got)
	}
	for _, name := range scopeBusVars {
		if strings.Contains(got, name+"=") {
			t.Errorf("%s leaked to the target; it is added for systemd-run only and must be stripped before exec: %q", name, got)
		}
	}

	if s := res.Report.StateOf(enforce.LayerLimits); s != enforce.Enforced {
		t.Errorf("limits layer = %v, want Enforced now that the degraded tier applies them", s)
	}
}

// Everything above would still pass with the scope wrapping removed - the report reads
// the host's capability, not this run - so the cap has to be proven to BIND. The probe
// touches far more memory than the limit allows and must be OOM-killed by the cgroup;
// unwrapped it would allocate happily and exit 7. This is the assertion that fails if
// the degraded tier ever goes back to running the target directly while still reporting
// LayerLimits=Enforced.
func TestDegradedRunMemoryLimitActuallyBinds(t *testing.T) {
	requireDegraded(t)
	if ok, reason := canCreateScope(); !ok {
		t.Skip("no usable systemd user scope: " + reason)
	}

	p := &policy.Policy{
		Entrypoint: buildEnvDumpProbe(t),
		Exec:       policy.ExecNone,
		Limits:     policy.Limits{Memory: "48M"},
	}
	var out strings.Builder
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p,
		enforce.Process{Stdout: &out, Stderr: &out, Env: map[string]string{"BENTO_ALLOC": "512"}})
	if err != nil {
		t.Fatalf("scoped degraded run failed: %v\noutput:\n%s", err, out.String())
	}
	// 128+SIGKILL: the cgroup OOM killer, the only thing that stops this probe.
	if res.ExitCode != 137 {
		t.Fatalf("exit code = %d, want 137 (OOM-killed at the 48M cap); the memory limit did not bind\noutput:\n%s", res.ExitCode, out.String())
	}
}

// buildEnvDumpProbe compiles a static probe that writes its own environment to the
// path named by BENTO_DUMP and exits 7, or - with BENTO_ALLOC set to a megabyte count -
// touches that much memory first, so a bound cap kills it before it can exit. Static
// (CGO off) so it needs no libc in the read set.
func buildEnvDumpProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		skipMissingDep(t, "go toolchain not available to build the probe")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "probe.go")
	const prog = `package main

import (
	"os"
	"strconv"
	"strings"
)

func main() {
	if mb, err := strconv.Atoi(os.Getenv("BENTO_ALLOC")); err == nil {
		// Touch every page: an untouched allocation is not charged to the cgroup.
		var held [][]byte
		for i := 0; i < mb; i++ {
			b := make([]byte, 1<<20)
			for j := range b {
				b[j] = byte(j)
			}
			held = append(held, b)
		}
		_ = held
	}
	os.WriteFile(os.Getenv("BENTO_DUMP"), []byte(strings.Join(os.Environ(), "\n")), 0o644)
	os.Exit(7)
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "envdump")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "HOME="+toolchainHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the env-dump probe: %v\n%s", err, out)
	}
	return bin
}
