//go:build linux

package linux

import (
	"errors"
	"strings"
	"testing"
)

// bwrap's own words are what make an unknown verdict diagnosable, so they stay in the
// reason - but the reason travels into the doctor report, into the refusal message a run
// prints, and from there into whatever collects those. What bwrap wrote is unbounded in
// both length and content, and on a misconfigured host it can include environment content.
//
// The bar is to keep the diagnosis and lose the leak, which is why the classification is
// asserted alongside: a scrub applied before the match could truncate past the words a
// refusal is recognised by and turn a host that answered into an unknown verdict - which
// refuses outright where blocked offers the degraded tier.
func TestProbeReasonsDoNotEchoUnboundedOutput(t *testing.T) {
	t.Run("an environment value in the output", func(t *testing.T) {
		const secret = "hunter2-not-for-the-report"
		out := "bwrap: something went wrong, environment was AWS_SECRET_ACCESS_KEY=" + secret

		ns, reason := classifyUnshare(&usernsError{output: out, err: errors.New("exit status 1")})
		if ns != namespacesUnknown {
			t.Fatalf("ns = %v, want unknown for output that names no namespace refusal", ns)
		}
		if strings.Contains(reason, secret) {
			t.Errorf("the reason reproduces an environment value verbatim: %q", reason)
		}
		if !strings.Contains(reason, "AWS_SECRET_ACCESS_KEY") {
			t.Errorf("the reason lost the variable's name along with its value, which is the half worth keeping: %q", reason)
		}
	})

	// The proxy pair is conventionally lowercase and carries credentials in a URL, so it is
	// the most realistic leak of this class rather than an edge of it.
	t.Run("a lowercase proxy variable", func(t *testing.T) {
		const secret = "user:hunter2@proxy.internal"
		out := "bwrap: something went wrong, http_proxy=http://" + secret + "/"

		_, reason := classifyUnshare(&usernsError{output: out, err: errors.New("exit status 1")})
		if strings.Contains(reason, "hunter2") {
			t.Errorf("the reason reproduces proxy credentials verbatim: %q", reason)
		}
		if !strings.Contains(reason, "http_proxy") {
			t.Errorf("the reason lost the variable's name along with its value, which is the half worth keeping: %q", reason)
		}
	})

	t.Run("output far longer than a diagnosis", func(t *testing.T) {
		out := "bwrap: " + strings.Repeat("x", 10000)

		_, reason := classifyUnshare(&usernsError{output: out, err: errors.New("exit status 1")})
		if len(reason) > len(unknownProbeBase())+probeOutputCap+64 {
			t.Errorf("the reason is %d bytes; bwrap's output is meant to be capped at %d", len(reason), probeOutputCap)
		}
	})

	// The positive control, and the reason the scrub is applied to the shown copy only: a
	// refusal must still be recognised as one after a leak-shaped prefix pushes the words
	// that identify it past the cap.
	t.Run("a real refusal behind a long prefix", func(t *testing.T) {
		out := "bwrap: " + strings.Repeat("NOISE_VAR=x ", 200) + "No permissions to create new namespace"

		ns, reason := classifyUnshare(&usernsError{output: out, err: errors.New("exit status 1")})
		if ns != namespacesBlocked {
			t.Fatalf("ns = %v, want blocked; the host refused the namespace and the scrub must not reclassify that as unknown", ns)
		}
		if strings.Contains(reason, "NOISE_VAR=x") {
			t.Errorf("the reason reproduces the assignment values: %q", reason)
		}
	})
}

// unknownProbeBase is the fixed half of the unknown verdict's reason, so the length
// assertion above bounds what came from bwrap rather than the whole sentence.
func unknownProbeBase() string {
	_, reason := classifyUnshare(&usernsError{output: "", err: errors.New("exit status 1")})
	return reason
}
