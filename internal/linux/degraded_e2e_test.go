package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

// TestDegradedEndToEndOnClampedHost drives the WHOLE degraded path through the
// public enforce.Run orchestrator on a host where bubblewrap cannot create a user
// namespace: the probe reports the filesystem layer Degraded, admission refuses by
// default and permits under --allow-degraded, and enforce.Run selects the no-bwrap
// tier which then confines. It only runs where userns is actually blocked (a
// clamped container or an Ubuntu AppArmor-restricted host); on a normal host it
// skips, because there enforce.Run would take the bwrap path instead. The Docker
// runner in test/degraded-e2e.sh creates the clamped environment.
func TestDegradedEndToEndOnClampedHost(t *testing.T) {
	requireDegraded(t)
	if nsOK, _ := usableNamespaces(context.Background()); nsOK {
		t.Skip("user namespaces work here; the degraded end-to-end path only runs on a userns-blocked host")
	}

	e := enforcerUsing(testBento(t))

	// The probe must see the clampdown: filesystem Degraded (Landlock-only), network
	// Unavailable (no netns to fence egress).
	report := e.Probe(context.Background())
	if got := report.StateOf(enforce.LayerFilesystem); got != enforce.Degraded {
		t.Fatalf("filesystem layer = %v, want Degraded on a clamped host", got)
	}
	if got := report.StateOf(enforce.LayerNetwork); got != enforce.Unavailable {
		t.Errorf("network layer = %v, want Unavailable on a clamped host (no netns)", got)
	}

	bin := buildDegradedProbe(t)
	grantedDir := t.TempDir()
	grantedFile := filepath.Join(grantedDir, "ok.txt")
	if err := os.WriteFile(grantedFile, []byte("granted"), 0o644); err != nil {
		t.Fatal(err)
	}
	ungrantedFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(ungrantedFile, []byte("do-not-read"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: bin, Read: []string{grantedDir}, Exec: policy.ExecNone}
	env := map[string]string{"GRANTED": grantedFile, "UNGRANTED": ungrantedFile}

	// Default posture refuses: a degraded core layer is not silently accepted.
	_, err := enforce.Run(context.Background(), e, p, enforce.Process{Env: env}, enforce.Options{})
	var refusal *enforce.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("default run on a clamped host must refuse; got %v", err)
	}

	// --allow-degraded runs it through the no-bwrap tier, which confines.
	var out strings.Builder
	res, err := enforce.Run(context.Background(), e, p,
		enforce.Process{Stdout: &out, Stderr: &out, Env: env},
		enforce.Options{AllowDegraded: true})
	if err != nil {
		t.Fatalf("--allow-degraded run failed: %v\noutput:\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"GRANTED_READ_OK", "UNGRANTED_READ_DENIED", "SOCKET_BLOCKED", "EXEC_BLOCKED"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q; exit=%d output:\n%s", want, res.ExitCode, got)
		}
	}
	// The result must still report the filesystem layer as Degraded, so the caller can
	// surface the reduced confinement.
	if s := res.Report.StateOf(enforce.LayerFilesystem); s != enforce.Degraded {
		t.Errorf("result filesystem layer = %v, want Degraded", s)
	}
}
