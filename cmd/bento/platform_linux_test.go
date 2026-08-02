package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// refuseThisPlatform makes checkPlatform answer as it does on a host with no backend, so
// the three commands that raise that refusal inside their own RunE can be watched doing
// it. Nothing else can: on Linux the check passes, so the calls are otherwise
// unobservable and deleting one breaks nothing.
func refuseThisPlatform(t *testing.T) {
	t.Helper()
	saved := checkPlatform
	checkPlatform = func() error { return errors.New("no sandbox backend for zos yet") }
	t.Cleanup(func() { checkPlatform = saved })
}

// Every command that builds or probes a sandbox refuses on a host with no backend, and
// answers --json with the document its own consumers were told to expect rather than the
// empty stdout a machine gate cannot tell from a crash. The three shapes differ on
// purpose, so they are asserted apart: run writes one object on its event stream, profile
// a single indented document, and doctor its own report with nothing in it.
//
// The manifest path need not exist. The refusal is raised before it is opened, which is
// half of what this pins - a host bento cannot run on is not a fact about the manifest.
func TestSandboxCommandsRefuseAHostWithNoBackend(t *testing.T) {
	t.Run("run", func(t *testing.T) {
		refuseThisPlatform(t)
		out, err := runCapturingStdout(t, newRunCmd(), "--json", "nonexistent.manifest.yaml")
		if got := asExitError(t, err).code; got != bentoFailed {
			t.Errorf("exit = %d, want %d - bento declined, the target never ran", got, bentoFailed)
		}
		var got streamRefusalJSON
		if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
			t.Fatalf("run --json must answer on its event stream: %v (stdout %q)", err, out)
		}
		if got.Event != "refusal" || !strings.Contains(got.Reason, "no sandbox backend") {
			t.Errorf("the stream must carry the refusal and its reason; got %+v", got)
		}
	})

	t.Run("profile", func(t *testing.T) {
		refuseThisPlatform(t)
		out, err := runCapturingStdout(t, newProfileCmd(), "--json", "./script.py")
		if got := asExitError(t, err).code; got != bentoFailed {
			t.Errorf("exit = %d, want %d", got, bentoFailed)
		}
		var got refusalJSON
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("profile --json must answer with one document: %v (stdout %q)", err, out)
		}
		if !got.Refused || !strings.Contains(got.Reason, "no sandbox backend") {
			t.Errorf("the document must say it refused and why; got %+v", got)
		}
	})

	// doctor's is not the refusal envelope: a CI gate reading `ready` must get false
	// because doctor said so, not because the key went missing. layers must be an empty
	// list and not a zero report, which marshals as fully_enforced on a host nobody probed.
	t.Run("doctor", func(t *testing.T) {
		refuseThisPlatform(t)
		out, err := runCapturingStdout(t, newDoctorCmd(), "--json")
		if err == nil || !strings.Contains(err.Error(), "no sandbox backend") {
			t.Fatalf("err = %v, want the platform refusal on stderr and a non-zero exit", err)
		}
		var got struct {
			Layers        []struct{} `json:"layers"`
			FullyEnforced bool       `json:"fully_enforced"`
			Ready         bool       `json:"ready"`
			Reason        string     `json:"reason"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("doctor --json must stay parseable where it refuses: %v (stdout %q)", err, out)
		}
		if got.Ready || got.FullyEnforced || got.Layers == nil || len(got.Layers) != 0 {
			t.Errorf("a host with no backend enforces nothing; got %+v", got)
		}
		if got.Reason == "" {
			t.Error("the reason there is nothing to report is the only thing this document says")
		}

		// The envelope buys the machine consumer a parseable stdout and nothing else: a
		// human and a script probing the same broken host must be told the same thing and
		// exit the same way, or a CI gate reading the status learns something --json
		// invented. Asserting the message is what makes the two comparable, since the
		// refusal carries no exit code of its own.
		_, plain := runCapturingStdout(t, newDoctorCmd())
		if plain == nil || plain.Error() != err.Error() {
			t.Errorf("without --json doctor answered %v, want the same refusal as %v", plain, err)
		}
	})
}
