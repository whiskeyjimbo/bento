package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// refuseThisPlatform makes checkPlatform answer as it does on a host with no backend, so
// the three commands that raise that refusal inside their own RunE can be watched doing
// it. Nothing else can: on Linux the check passes, so the calls are otherwise
// unobservable and deleting one breaks nothing.
//
// It builds its reason from platformName for the same reason the real one does, so a test
// that swaps the platform seam cannot end up with a refusal naming one host and a platform
// field naming another.
func refuseThisPlatform(t *testing.T) {
	t.Helper()
	saved := checkPlatform
	checkPlatform = func() error { return fmt.Errorf("no sandbox backend for %s yet", platformName()) }
	t.Cleanup(func() { checkPlatform = saved })
}

// version names the platform and what it can enforce there. A cross-build for a platform
// with no backend is the case this exists for: it compiles clean and then refuses run,
// profile and doctor. Doctor is the command that would have explained why, and it is one
// of the three - only its --json envelope still names the platform, which a human reading
// a refusal never sees.
func TestVersionNamesWhatThisBuildCanEnforce(t *testing.T) {
	t.Run("a host with no backend", func(t *testing.T) {
		refuseThisPlatform(t)
		onPlatform(t, "darwin/amd64")
		out := versionBanner()
		if !strings.Contains(out, "Platform: darwin/amd64") {
			t.Errorf("version = %q, want the platform named", out)
		}
		if !strings.Contains(out, "No sandbox backend here") || !strings.Contains(out, "validate and approve work") {
			t.Errorf("version = %q, want it to say what a build with no backend still does", out)
		}
	})

	// A Linux build on another architecture is the opposite failure: everything works, so
	// nothing in the output would otherwise say it is unverified.
	t.Run("an unverified linux architecture", func(t *testing.T) {
		onPlatform(t, "linux/arm64")
		out := versionBanner()
		if !strings.Contains(out, "planned, not verified") || !strings.Contains(out, verifiedPlatform) {
			t.Errorf("version = %q, want linux/arm64 called unverified against %s", out, verifiedPlatform)
		}
	})

	// The verified host earns the platform line and nothing after it; a caveat here would
	// teach an operator to read past the ones that matter.
	t.Run("the verified platform", func(t *testing.T) {
		onPlatform(t, verifiedPlatform)
		pureLookup(t, true)
		out := versionBanner()
		if want := "Platform: " + verifiedPlatform + "\n"; !strings.HasSuffix(out, want) {
			t.Errorf("version = %q, want it to end at %q", out, want)
		}
	})

	// A `go install` on a host with a C toolchain produces this build, and it is otherwise
	// indistinguishable: same platform, same version string, same shield count.
	t.Run("a build resolving passwd through libc NSS", func(t *testing.T) {
		onPlatform(t, verifiedPlatform)
		pureLookup(t, false)
		out := versionBanner()
		if !strings.Contains(out, "libc NSS") || !strings.Contains(out, "CGO_ENABLED=0") {
			t.Errorf("version = %q, want the NSS anchor caveat and how to rebuild", out)
		}
	})

	// The subcommand and the root flag are the same question, and the operator who has a
	// binary that refuses everything will reach for either. The flag answers through
	// cobra's own version template rather than the subcommand's Run, so nothing but this
	// keeps the two from drifting apart.
	t.Run("--version answers the same as the subcommand", func(t *testing.T) {
		refuseThisPlatform(t)
		onPlatform(t, "darwin/amd64")
		want := versionBanner()
		if got := executeCapturingOut(t, newRootCmd(), "--version"); got != want {
			t.Errorf("--version = %q, want %q", got, want)
		}
		if got := executeCapturingOut(t, newVersionCmd()); got != want {
			t.Errorf("version = %q, want %q", got, want)
		}
	})
}

// executeCapturingOut runs cmd against cobra's own output writer, which is where both
// version answers land - unlike runCapturingStdout, which captures os.Stdout for the
// commands that write there directly.
func executeCapturingOut(t *testing.T, cmd *cobra.Command, args ...string) string {
	t.Helper()
	var buf strings.Builder
	cmd.SetArgs(args)
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("%s: %v", cmd.Name(), err)
	}
	return buf.String()
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
		// Both seams answer for the same host: an envelope whose reason names zos while
		// its platform field names the build's own would be a document no real host
		// produces, and the assertion below would pass on it.
		onPlatform(t, "zos/s390x")
		out, err := runCapturingStdout(t, newDoctorCmd(), "--json")
		if err == nil || !strings.Contains(err.Error(), "no sandbox backend") {
			t.Fatalf("err = %v, want the platform refusal on stderr and a non-zero exit", err)
		}
		var got struct {
			Layers        []struct{} `json:"layers"`
			FullyEnforced bool       `json:"fully_enforced"`
			Ready         bool       `json:"ready"`
			Reason        string     `json:"reason"`
			Platform      string     `json:"platform"`
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
		// The platform is the one thing this document can still state as fact, and the
		// host with no backend is where it matters most.
		if got.Platform != "zos/s390x" {
			t.Errorf("the envelope must name the platform it found no backend for; got %q", got.Platform)
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
		// The refusal is the whole of the human's answer - there is no platform line to
		// carry the rest - so it has to name the pair the envelope's platform field does.
		// GOOS alone would tell them less than the script beside them was told.
		if !strings.Contains(plain.Error(), got.Platform) {
			t.Errorf("the refusal %q must name %q, the platform --json reported", plain, got.Platform)
		}
	})
}
