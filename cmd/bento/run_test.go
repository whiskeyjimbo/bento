package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// asExitError unwraps the *exitError a command returns to carry a target's exit
// code up to main, failing the test if the error is any other shape.
func asExitError(t *testing.T, err error) *exitError {
	t.Helper()
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("err = %v (%T), want *exitError", err, err)
	}
	return ee
}

// The whole reason writeRunResult exists: a target's exit code passes through
// untouched as exitError{code}, distinct from bento's own "could not run" code, so a
// caller can tell "the script exited 7" from "bento refused". Zero passes through too -
// it must still be an exitError, not a nil error, so main unwinds cleanup before exit.
func TestWriteRunResultPassesTargetExitCode(t *testing.T) {
	for _, code := range []int{0, 1, 7, 42, bentoFailed} {
		var stdout, stderr bytes.Buffer
		err := writeRunResult(&stdout, &stderr, false, validPolicy(),
			enforce.Result{ExitCode: code}, "", "", nil)
		if got := asExitError(t, err).code; got != code {
			t.Errorf("target exit %d passed up as %d", code, got)
		}
	}
}

// A refusal means bento itself could not run the script, so it must map to
// bentoFailed (125) in --json mode - never to the target's code, which never ran.
// The envelope carries refused/reason/report so a machine consumer sees the refusal.
func TestWriteRunResultRefusalJSON(t *testing.T) {
	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Degraded, "userns blocked")
	refusal := &enforce.Refusal{Report: report, Reason: "a core guarantee cannot be fully enforced on this host"}

	var stdout, stderr bytes.Buffer
	// A non-zero target code in the (unused) Result must not leak through: a refused
	// run never produced one.
	err := writeRunResult(&stdout, &stderr, true, validPolicy(),
		enforce.Result{ExitCode: 7}, "", "", refusal)
	if got := asExitError(t, err).code; got != bentoFailed {
		t.Fatalf("refusal exit code = %d, want %d", got, bentoFailed)
	}

	var env struct {
		Refused bool       `json:"refused"`
		Reason  string     `json:"reason"`
		Report  reportJSON `json:"report"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("refusal envelope is not valid JSON: %v\n%s", err, stdout.String())
	}
	if !env.Refused || env.Reason != refusal.Reason {
		t.Errorf("refusal envelope = %+v, want refused=true reason=%q", env, refusal.Reason)
	}
	if len(env.Report.Layers) == 0 {
		t.Error("refusal envelope must carry the report so a consumer sees which layer fell short")
	}
}

// Without --json a refusal returns the refusal error itself (main renders it and
// exits bentoFailed), not an exitError carrying a target code, and writes no JSON.
func TestWriteRunResultRefusalHuman(t *testing.T) {
	refusal := &enforce.Refusal{Reason: "strict mode requires every layer to be fully enforced"}
	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, false, validPolicy(),
		enforce.Result{ExitCode: 7}, "", "", refusal)

	var ee *exitError
	if errors.As(err, &ee) {
		t.Fatalf("human refusal must not be an exitError; got code %d", ee.code)
	}
	if !errors.Is(err, error(refusal)) {
		t.Errorf("human refusal must return the refusal itself; got %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("human refusal must not write JSON to stdout; got %q", stdout.String())
	}
}

// A setup failure that is not a refusal (a nil-enforcer, a validation error) is
// returned verbatim in both modes, so main reports it and exits bentoFailed. It must
// never be swallowed into a success envelope.
func TestWriteRunResultSetupErrorPropagates(t *testing.T) {
	setupErr := errors.New("enforce: nil enforcer")
	for _, asJSON := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		err := writeRunResult(&stdout, &stderr, asJSON, validPolicy(),
			enforce.Result{}, "", "", setupErr)
		if !errors.Is(err, setupErr) {
			t.Errorf("json=%v: setup error must propagate verbatim; got %v", asJSON, err)
		}
		var ee *exitError
		if errors.As(err, &ee) {
			t.Errorf("json=%v: setup error must not become an exitError; got code %d", asJSON, ee.code)
		}
	}
}

// The --json success envelope is the machine contract: it carries the target's real
// exit code and its captured streams, and the command still returns exitError{code}
// so the process exits with the target's code.
func TestWriteRunResultSuccessJSON(t *testing.T) {
	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	res := enforce.Result{
		ExitCode: 3, Report: report, EgressConnections: 2,
		ShieldedGrants: []string{"/home/u/.ssh"},
		Shields:        []enforce.ShieldApplied{{Path: "/home/u/.aws", Kind: "hidden"}, {Path: "/work/.git/hooks", Kind: "read-only"}},
	}

	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, true, validPolicy(), res, "hello-stdout", "warn-stderr", nil)
	if got := asExitError(t, err).code; got != 3 {
		t.Fatalf("success exit code = %d, want 3", got)
	}

	var env struct {
		ExitCode          int      `json:"exit_code"`
		Stdout            string   `json:"stdout"`
		Stderr            string   `json:"stderr"`
		EgressConnections int      `json:"egress_connections"`
		ShieldedGrants    []string `json:"shielded_grants"`
		Shields           []struct {
			Path string `json:"path"`
			Kind string `json:"kind"`
		} `json:"shields"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("success envelope is not valid JSON: %v\n%s", err, stdout.String())
	}
	if env.ExitCode != 3 || env.Stdout != "hello-stdout" || env.Stderr != "warn-stderr" {
		t.Errorf("success envelope = %+v, want exit 3 with captured streams", env)
	}
	if env.EgressConnections != 2 || len(env.ShieldedGrants) != 1 {
		t.Errorf("success envelope dropped egress/shielded-grant fields: %+v", env)
	}
	if len(env.Shields) != 2 || env.Shields[0].Path != "/home/u/.aws" || env.Shields[0].Kind != "hidden" || env.Shields[1].Kind != "read-only" {
		t.Errorf("success envelope dropped or mangled the shield audit: %+v", env.Shields)
	}
}

// The human run prints one concise line confirming the boundary engaged, with counts
// by kind, so an operator sees the sandbox worked without a per-path dump (that is the
// --json list). A run whose grants reached no shield stays silent.
func TestWriteRunResultShieldSummaryHuman(t *testing.T) {
	res := enforce.Result{
		ExitCode: 0,
		Shields:  []enforce.ShieldApplied{{Path: "/home/u/.ssh", Kind: "hidden"}, {Path: "/home/u/.aws", Kind: "hidden"}, {Path: "/work/.git/hooks", Kind: "read-only"}},
	}
	var stdout, stderr bytes.Buffer
	_ = writeRunResult(&stdout, &stderr, false, validPolicy(), res, "", "", nil)
	got := stderr.String()
	if !strings.Contains(got, "3 credential/host-service path(s) shielded") || !strings.Contains(got, "2 hidden, 1 read-only") {
		t.Errorf("shield summary line missing or wrong: %q", got)
	}

	var none bytes.Buffer
	_ = writeRunResult(&none, &none, false, validPolicy(), enforce.Result{ExitCode: 0}, "", "", nil)
	if strings.Contains(none.String(), "sandbox engaged") {
		t.Errorf("a run that shielded nothing must not print the summary: %q", none.String())
	}
}

// A --json run whose exit code is a target code that happens to equal bentoFailed is
// still a run, not a refusal: the code must pass through the success envelope, not be
// re-minted as a bento refusal. Guards the asymmetry between the two envelopes.
func TestWriteRunResultSuccessDoesNotForgeRefusal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, true, validPolicy(),
		enforce.Result{ExitCode: bentoFailed}, "", "", nil)
	if got := asExitError(t, err).code; got != bentoFailed {
		t.Fatalf("exit code = %d, want %d passed through", got, bentoFailed)
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, refused := env["refused"]; refused {
		t.Error("a successful run must emit the success envelope, never the refusal envelope")
	}
	if _, ok := env["exit_code"]; !ok {
		t.Error("success envelope must carry exit_code")
	}
}

// A --json envelope write that fails (a redirected stdout that is full or gone) must
// NOT be re-minted as a bento refusal: the script already ran, so its exit code still
// passes through and the failure is only a warning on stderr. Overwriting it with
// bentoFailed would lie that bento could not run the script.
func TestWriteRunResultJSONWriteFailureKeepsExitCode(t *testing.T) {
	var stderr bytes.Buffer
	err := writeRunResult(failWriter{}, &stderr, true, validPolicy(),
		enforce.Result{ExitCode: 5}, "out", "err", nil)
	if got := asExitError(t, err).code; got != 5 {
		t.Fatalf("a failed JSON write must still pass the target code; got %d, want 5", got)
	}
	if !strings.Contains(stderr.String(), "could not encode the JSON result") {
		t.Errorf("a failed JSON write must warn on stderr; got %q", stderr.String())
	}
}

// In human mode writeRunResult must surface every non-silent notice: the shielded-grant
// exposure warning (a credential store the policy opted into), the degradation report,
// and the egress-bypass hint. Dropping any call would silence a warning the tool exists
// to make loud, so pin that all three reach stderr.
func TestWriteRunResultHumanSurfacesWarnings(t *testing.T) {
	var report enforce.Report
	report.Add(enforce.LayerExec, enforce.Unavailable, "no seccomp on this host")
	res := enforce.Result{
		ExitCode:       1, // non-zero + zero egress triggers the egress-bypass hint
		Report:         report,
		ShieldedGrants: []string{"/home/u/.ssh"},
	}
	netPolicy := &policy.Policy{Entrypoint: "./x", Network: []policy.NetworkRule{{Host: "a.com", Port: "443"}}}

	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, false, netPolicy, res, "", "", nil)
	if got := asExitError(t, err).code; got != 1 {
		t.Fatalf("exit code = %d, want 1", got)
	}
	out := stderr.String()
	for _, want := range []string{"/home/u/.ssh", "does not enforce everything", "egress proxy"} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q; got:\n%s", want, out)
		}
	}
	if stdout.Len() != 0 {
		t.Errorf("human mode must not write to stdout; got %q", stdout.String())
	}
}

// The success envelope omits shielded_grants entirely for the common run that opts into
// none (omitempty), so a machine consumer keying on the field's presence is not misled.
func TestWriteRunResultSuccessOmitsEmptyShieldedGrants(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), enforce.Result{ExitCode: 0}, "", "", nil)
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, present := env["shielded_grants"]; present {
		t.Error("shielded_grants must be omitted when empty (omitempty), not emitted as null/[]")
	}
}

// failWriter is a stdout that always fails, so a test can drive the JSON-encode error
// path of writeRunResult.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("stdout is gone") }

// validPolicy is the minimal policy writeRunResult needs (writeEgressHint reads its
// Network); no network means the hint stays quiet.
func validPolicy() *policy.Policy { return &policy.Policy{Entrypoint: "./x"} }

// A strict run whose guarantee lapsed while the target ran is neither a refusal (the
// script did run, and its output is reported) nor a clean run (the posture strict was
// asked for did not hold). Passing the script's own code through would report a clean
// run over a lapsed guarantee, so it gets its own code, and --json says so in the
// envelope rather than leaving a machine consumer reading an ordinary completed run.
func TestWriteRunResultStrictShortfall(t *testing.T) {
	var report enforce.Report
	report.Add(enforce.LayerNetwork, enforce.Degraded, "the egress proxy stopped serving")
	shortfall := &enforce.Shortfall{Report: report, Short: report.Degradations()}

	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, false, validPolicy(),
		enforce.Result{ExitCode: 0, Report: report}, "", "", shortfall)
	if got := asExitError(t, err).code; got != strictShortfall {
		t.Fatalf("shortfall exit code = %d, want %d - never the target's own code", got, strictShortfall)
	}
	if !strings.Contains(stderr.String(), "did not hold for the whole run") {
		t.Errorf("a strict shortfall must be named on stderr; got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	err = writeRunResult(&stdout, &stderr, true, validPolicy(),
		enforce.Result{ExitCode: 7, Report: report}, "out", "", shortfall)
	if got := asExitError(t, err).code; got != strictShortfall {
		t.Fatalf("shortfall exit code = %d, want %d in --json too", got, strictShortfall)
	}
	var env struct {
		ExitCode        int    `json:"exit_code"`
		Stdout          string `json:"stdout"`
		Refused         bool   `json:"refused"`
		StrictShortfall bool   `json:"strict_shortfall"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if !env.StrictShortfall {
		t.Error("the envelope must mark the strict shortfall")
	}
	if env.Refused {
		t.Error("a shortfall is not a refusal: the target ran")
	}
	// The run happened, so the envelope still reports what it produced.
	if env.ExitCode != 7 || env.Stdout != "out" {
		t.Errorf("envelope = %+v, want the target's own code and output", env)
	}
}

// A refusal raised before enforce.Run was ever reached - a bad --env, an unparseable
// or unapproved manifest - used to return bare, leaving --json's stdout empty so jq
// could not tell a refusal from a crash (bv2-w4n5). It must produce the SAME refusal
// envelope the enforcement layer's own refusals produce, not a fourth shape.
func TestRefuseJSONUsesTheRefusalEnvelope(t *testing.T) {
	var buf bytes.Buffer
	err := refuseJSON(&buf, true, errors.New("refusing to run: the manifest is not approved"))

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != bentoFailed {
		t.Fatalf("err = %v, want exitError{%d}", err, bentoFailed)
	}
	var got refusalJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, buf.String())
	}
	if !got.Refused || !strings.Contains(got.Reason, "not approved") {
		t.Errorf("envelope = %+v, want refused with the error as the reason", got)
	}
	// No sandbox was ever built, so claiming every layer held would report a clean
	// posture on a run that never had one.
	if got.Report.FullyEnforced {
		t.Error("a pre-run refusal must not report fully_enforced")
	}
}

// Without --json the error is the frontend's own, rendered by main; refuseJSON must
// not swallow it into an exit code that loses the message.
func TestRefuseJSONPassesHumanErrorThrough(t *testing.T) {
	want := errors.New("boom")
	var buf bytes.Buffer
	if got := refuseJSON(&buf, false, want); !errors.Is(got, want) {
		t.Errorf("err = %v, want the original error", got)
	}
	if buf.Len() != 0 {
		t.Errorf("human mode must write no envelope; got %q", buf.String())
	}
}
