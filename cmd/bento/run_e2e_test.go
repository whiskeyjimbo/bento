//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// writeRunnableManifest writes a manifest whose entrypoint is a real script beside it,
// stamped as approved over the policy AS WRITTEN. The grants are deliberately relative:
// that is what makes the ordering assertion below sharp, since resolving them changes
// the fingerprint the stamp was taken over.
func writeRunnableManifest(t *testing.T, script string, p *policy.Policy) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := manifest.Marshal(p, manifest.Provenance{Approves: p.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bento.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runCmd drives the real run command through cobra, so the whole of RunE's admission
// sequence runs in the order the command actually uses - which is the part unit tests of
// the individual predicates cannot cover.
func runCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newRunCmd()
	cmd.SetArgs(args)
	cmd.SetOut(os.Stderr)
	cmd.SetErr(os.Stderr)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	return cmd.Execute()
}

// THE ORDERING INVARIANT: requireApproval reads the manifest as written, and
// manifest.Resolve rewrites its relative grants to absolute paths - so resolving before
// checking approval would change the fingerprint out from under the stamp and refuse
// every approved manifest that uses a relative grant. Nothing else in the tree runs an
// approved manifest through `run` at all, so this is what fails if the two ever swap.
func TestRunHonorsApprovalBeforeResolvingGrants(t *testing.T) {
	requireSandbox(t)

	dataDir := "./data"
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
		Read:        []string{dataDir},
	})
	if err := os.Mkdir(filepath.Join(filepath.Dir(m), "data"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A completed run returns the target's own code as an exitError, so 0 is success
	// here and any refusal on the way in is a different error entirely.
	if got := asExitError(t, runCmd(t, m)).code; got != 0 {
		t.Fatalf("an approved manifest with a relative grant must run; exit = %d", got)
	}
}

// The other half of the same order: the stamp is checked against the manifest's own
// bytes, so an edit after approval is still caught here - a run that only ever saw
// resolved grants could not tell the two apart.
func TestRunRefusesAManifestEditedAfterApproval(t *testing.T) {
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
		Read:        []string{"./data"},
	})
	edited, err := manifest.Marshal(
		&policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh", Read: []string{"./data", "/etc"}},
		manifest.Provenance{Approves: "sha256:stale"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m, edited, 0o644); err != nil {
		t.Fatal(err)
	}

	err = runCmd(t, m)
	if err == nil {
		t.Fatal("a manifest edited after approval must be refused")
	}
	if !strings.Contains(err.Error(), "changed since it was approved") {
		t.Errorf("refusal = %v, want the drift refusal", err)
	}
}

// --env is screened twice on the way in: parseEnvFlags takes the spelling, ResolveEnv
// takes the name against the manifest's allowlist. Both refusals are raised before the
// sandbox exists, so neither needs one.
func TestRunRefusesBadEnvFlags(t *testing.T) {
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
		Env:         []string{"ALLOWED"},
	})

	for name, tc := range map[string]struct{ flag, want string }{
		"no equals":  {"NOTAPAIR", "want NAME=VALUE"},
		"empty name": {"=value", "want NAME=VALUE"},
		"undeclared": {"OTHER=v", "not in the manifest's env allowlist"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runCmd(t, "--env", tc.flag, m)
			if err == nil {
				t.Fatalf("--env %q must be refused", tc.flag)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal = %v, want it to name %q", err, tc.want)
			}
		})
	}
}
