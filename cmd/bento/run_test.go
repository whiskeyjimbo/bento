package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
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
		err := writeRunResult(&stdout, &stderr, false, validPolicy(), nil,
			enforce.Result{ExitCode: code}, nil, nil, nil)
		if got := asExitError(t, err).code; got != code {
			t.Errorf("target exit %d passed up as %d", code, got)
		}
	}
}

// A refusal means bento itself could not run the script, so it must map to
// bentoFailed (125) in --json mode - never to the target's code, which never ran. The
// stream carries one refusal event with the reason and report, and no verdict.
func TestWriteRunResultRefusalJSON(t *testing.T) {
	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Degraded, "userns blocked")
	refusal := &enforce.Refusal{Report: report, Reason: "a core guarantee cannot be fully enforced on this host"}

	var stdout, stderr bytes.Buffer
	// A non-zero target code in the (unused) Result must not leak through: a refused
	// run never produced one.
	err := writeRunResult(&stdout, &stderr, true, validPolicy(), nil,
		enforce.Result{ExitCode: 7}, nil, newEventStream(&stdout), refusal)
	if got := asExitError(t, err).code; got != bentoFailed {
		t.Fatalf("refusal exit code = %d, want %d", got, bentoFailed)
	}

	var env struct {
		Event  string     `json:"event"`
		Reason string     `json:"reason"`
		Report reportJSON `json:"report"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("refusal event is not valid JSON: %v\n%s", err, stdout.String())
	}
	if env.Event != "refusal" || env.Reason != refusal.Reason {
		t.Errorf("refusal event = %+v, want event=refusal reason=%q", env, refusal.Reason)
	}
	if len(env.Report.Layers) == 0 {
		t.Error("a refusal must carry the report so a consumer sees which layer fell short")
	}
}

// Without --json a refusal is rendered to stderr in main's own shape and exits
// bentoFailed - never a target's code - and writes no JSON. Rendered here because the
// layer reasons are too long for one line; see writeRefusal.
func TestWriteRunResultRefusalHuman(t *testing.T) {
	refusal := &enforce.Refusal{
		Reason: "strict mode requires every layer to be fully enforced",
		Short: []enforce.LayerStatus{{
			Layer:  enforce.LayerFilesystem,
			State:  enforce.Degraded,
			Reason: strings.Repeat("this host cannot bind-mount the grants, ", 30),
		}},
	}
	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, false, validPolicy(), nil,
		enforce.Result{ExitCode: 7}, nil, nil, refusal)

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != bentoFailed {
		t.Fatalf("human refusal = %v, want exitError{%d}", err, bentoFailed)
	}
	if stdout.Len() != 0 {
		t.Errorf("human refusal must not write JSON to stdout; got %q", stdout.String())
	}
	out := stderr.String()
	if !strings.HasPrefix(out, "bento: refusing to run: "+refusal.Reason) {
		t.Errorf("refusal must keep main's own wording; got %q", out)
	}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if len(line) > textWidth {
			t.Errorf("refusal line is %d columns, want at most %d: %q", len(line), textWidth, line)
		}
	}
}

// A failure that is neither a refusal nor a shortfall (a nil-enforcer, a validation
// error, a backend that died mid-run) is returned verbatim in human mode, so main
// reports it and exits bentoFailed. It must never be swallowed into a success envelope.
func TestWriteRunResultSetupErrorPropagates(t *testing.T) {
	setupErr := errors.New("enforce: nil enforcer")
	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, false, validPolicy(), nil,
		enforce.Result{}, nil, nil, setupErr)
	if !errors.Is(err, setupErr) {
		t.Errorf("setup error must propagate verbatim; got %v", err)
	}
	var ee *exitError
	if errors.As(err, &ee) {
		t.Errorf("setup error must not become an exitError; got code %d", ee.code)
	}
}

// The same failure under --json ends the stream with a failed event rather than just
// stopping. It must not claim refusal - the target may already have started - and it
// carries no exit code, because nothing here knows whether the target produced one.
// Whatever the target printed went out as events while it ran, so nothing is lost by the
// event itself carrying no streams.
func TestWriteRunResultMidFlightFailureJSON(t *testing.T) {
	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	res := enforce.Result{ExitCode: 7, Report: report}
	runErr := errors.New("the sandbox stage died while the target ran")

	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, true, validPolicy(), nil, res, nil, newEventStream(&stdout), runErr)
	if got := asExitError(t, err).code; got != bentoFailed {
		t.Fatalf("mid-flight failure exit code = %d, want %d", got, bentoFailed)
	}
	if stderr.Len() > 0 {
		t.Errorf("--json answers on the stream and says nothing on stderr; got %q", stderr.String())
	}

	var env struct {
		Event    string     `json:"event"`
		Reason   string     `json:"reason"`
		ExitCode *int       `json:"exit_code"`
		Report   reportJSON `json:"report"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("failure event is not valid JSON: %v\n%s", err, stdout.String())
	}
	if env.Event != "failed" {
		t.Errorf("event = %q, want failed - never refusal, which would say bento declined a run it began", env.Event)
	}
	if env.Reason != runErr.Error() {
		t.Errorf("reason = %q, want %q", env.Reason, runErr.Error())
	}
	if env.ExitCode != nil {
		t.Errorf("exit_code = %d, want it absent: nothing here knows whether the target produced one", *env.ExitCode)
	}
	if len(env.Report.Layers) == 0 {
		t.Error("a failed run must carry the report of what was enforced around it")
	}
}

// A failure raised before any stage existed carries the zero Report, which must not be
// rendered as a fully-enforced posture on a run that never had one.
func TestWriteRunResultMidFlightFailureJSONNoReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), nil,
		enforce.Result{}, nil, newEventStream(&stdout), errors.New("enforce: nil enforcer"))

	var env struct {
		Report reportJSON `json:"report"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("failure envelope is not valid JSON: %v\n%s", err, stdout.String())
	}
	if env.Report.FullyEnforced {
		t.Error("a run that never reached a stage must not report fully_enforced")
	}
}

// The verdict is the machine contract and the last object on the stream: it carries the
// target's real exit code, and the command still returns exitError{code} so the process
// exits with that code. The target's own output is not in it - it went out as events
// while the run happened, which is what keeps a run's memory off what it printed.
func TestWriteRunResultSuccessJSON(t *testing.T) {
	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	res := enforce.Result{
		ExitCode: 3, Report: report, EgressConnections: 2,
		ShieldedGrants: []enforce.ShieldedGrant{{Path: "/home/u/.ssh", Holds: "credentials"}},
		Shields:        []enforce.ShieldApplied{{Path: "/home/u/.aws", Kind: "hidden"}, {Path: "/work/.git/hooks", Kind: "read-only"}},
	}

	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, true, validPolicy(), nil, res, nil, newEventStream(&stdout), nil)
	if got := asExitError(t, err).code; got != 3 {
		t.Fatalf("success exit code = %d, want 3", got)
	}

	var env struct {
		Event             string `json:"event"`
		ExitCode          int    `json:"exit_code"`
		EgressConnections int    `json:"egress_connections"`
		ShieldedGrants    []struct {
			Path  string `json:"path"`
			Holds string `json:"holds"`
		} `json:"shielded_grants"`
		Shields []struct {
			Path string `json:"path"`
			Kind string `json:"kind"`
		} `json:"shields"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("verdict is not valid JSON: %v\n%s", err, stdout.String())
	}
	if env.Event != "verdict" || env.ExitCode != 3 {
		t.Errorf("verdict = %+v, want event=verdict exit 3", env)
	}
	if env.EgressConnections != 2 || len(env.ShieldedGrants) != 1 {
		t.Errorf("verdict dropped egress/shielded-grant fields: %+v", env)
	}
	// The buffered envelope this replaced carried them; a consumer reading only the
	// verdict must not find an empty pair of fields where the output used to be.
	var raw map[string]any
	_ = json.Unmarshal(stdout.Bytes(), &raw)
	if _, ok := raw["stdout"]; ok {
		t.Error("the verdict must not carry a stdout field; the target's output is its own events")
	}
	if len(env.Shields) != 2 || env.Shields[0].Path != "/home/u/.aws" || env.Shields[0].Kind != "hidden" || env.Shields[1].Kind != "read-only" {
		t.Errorf("verdict dropped or mangled the shield audit: %+v", env.Shields)
	}
}

// A machine gate reads the envelope, so it must be told what an opted-in grant reached -
// shielded_grants carries the spelling that opted in, and the deny-list builds those
// spellings from $HOME, so under a caller-chosen environment that name can be a link
// while the exposure lands on the real store. The pairing comes from the backend, which
// resolved it as it bound the grant; the frontend must render that rather than stat the
// path again after the target has exited.
func TestWriteRunResultJSONNamesWhatOptedInGrantsReach(t *testing.T) {
	const granted, store = "/home/u/link/.ssh", "/home/u/real/.ssh"

	var stdout, stderr bytes.Buffer
	res := enforce.Result{
		ShieldedGrants: []enforce.ShieldedGrant{
			{Path: granted, OnHost: store, Holds: "credentials"},
			{Path: "/etc/hosts", Holds: "credentials"},
		},
	}
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), nil, res, nil, newEventStream(&stdout), nil)

	var env struct {
		ShieldedGrants []struct {
			Path   string `json:"path"`
			OnHost string `json:"on_host"`
			Holds  string `json:"holds"`
		} `json:"shielded_grants"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("envelope is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(env.ShieldedGrants) != 2 || env.ShieldedGrants[0].Path != granted || env.ShieldedGrants[1].Path != "/etc/hosts" {
		t.Fatalf("shielded_grants = %+v, want the grants as the policy spelled them", env.ShieldedGrants)
	}
	if env.ShieldedGrants[0].OnHost != store || env.ShieldedGrants[0].Holds != "credentials" {
		t.Errorf("shielded_grants[0] = %+v, want %q on %q as a credential store", env.ShieldedGrants[0], granted, store)
	}
	// Only the aliased entry carries on_host: /etc/hosts names its own target, and a
	// field claiming otherwise would be noise a consumer has to filter.
	if env.ShieldedGrants[1].OnHost != "" {
		t.Errorf("shielded_grants[1] = %+v, want no on_host for a grant that names its own target", env.ShieldedGrants[1])
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
	_ = writeRunResult(&stdout, &stderr, false, validPolicy(), nil, res, nil, nil, nil)
	got := stderr.String()
	if !strings.Contains(got, "3 credential/host-service path(s) shielded") || !strings.Contains(got, "2 hidden, 1 read-only") {
		t.Errorf("shield summary line missing or wrong: %q", got)
	}

	var none bytes.Buffer
	_ = writeRunResult(&none, &none, false, validPolicy(), nil, enforce.Result{ExitCode: 0}, nil, nil, nil)
	if strings.Contains(none.String(), "sandbox engaged") {
		t.Errorf("a run that shielded nothing must not print the summary: %q", none.String())
	}
}

// A --json run whose exit code is a target code that happens to equal bentoFailed is
// still a run, not a refusal: the code must pass through the success envelope, not be
// re-minted as a bento refusal. Guards the asymmetry between the two envelopes.
func TestWriteRunResultSuccessDoesNotForgeRefusal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, true, validPolicy(), nil,
		enforce.Result{ExitCode: bentoFailed}, nil, newEventStream(&stdout), nil)
	if got := asExitError(t, err).code; got != bentoFailed {
		t.Fatalf("exit code = %d, want %d passed through", got, bentoFailed)
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if env["event"] != "verdict" {
		t.Errorf("event = %v, want verdict - a completed run is never a refusal", env["event"])
	}
	if _, ok := env["exit_code"]; !ok {
		t.Error("the verdict must carry exit_code")
	}
}

// A stream write that fails (a redirected stdout that is full or gone) leaves stdout
// truncated - and the target's own output is on that stream, so what is there is not what
// the run produced, with nothing in it to say how much is missing. Passing the target's
// exit code through would tell a gate to trust it, so every outcome answers with bento's
// own code and says why on stderr. All three, not just the verdict: a consumer reads the
// stream by its terminal object, and a refusal or failure that never landed leaves one
// that ends in nothing at all.
func TestWriteRunResultStreamWriteFailureRefusesEveryOutcome(t *testing.T) {
	report := enforce.Report{}
	report.Add(enforce.LayerFilesystem, enforce.Degraded, "userns blocked")
	for _, tc := range []struct {
		name string
		res  enforce.Result
		err  error
	}{
		{"verdict", enforce.Result{ExitCode: 5}, nil},
		{"refusal", enforce.Result{}, &enforce.Refusal{Report: report, Reason: "cannot enforce here"}},
		{"failed", enforce.Result{}, errors.New("the sandbox stage died")},
		{"strict shortfall", enforce.Result{ExitCode: 5}, &enforce.Shortfall{Report: report}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			err := writeRunResult(failWriter{}, &stderr, true, validPolicy(), nil,
				tc.res, nil, newEventStream(failWriter{}), tc.err)
			if got := asExitError(t, err).code; got != bentoFailed {
				t.Errorf("a truncated stream reported %d, want %d - nothing on stdout can be trusted", got, bentoFailed)
			}
			if !strings.Contains(stderr.String(), "could not be written") {
				t.Errorf("a failed stream write must say so on stderr; got %q", stderr.String())
			}
		})
	}
}

// The same run with a stream that took the writes keeps its own answer, so the check
// above is a response to the failure and not a code the --json path always returns.
func TestWriteRunResultStreamIntactKeepsTheEarnedCode(t *testing.T) {
	report := enforce.Report{}
	report.Add(enforce.LayerFilesystem, enforce.Degraded, "userns blocked")
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"verdict", nil, 5},
		{"strict shortfall", &enforce.Shortfall{Report: report}, strictShortfall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := writeRunResult(&stdout, &stderr, true, validPolicy(), nil,
				enforce.Result{ExitCode: 5}, nil, newEventStream(&stdout), tc.err)
			if got := asExitError(t, err).code; got != tc.want {
				t.Errorf("exit code = %d, want %d", got, tc.want)
			}
		})
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
		ShieldedGrants: []enforce.ShieldedGrant{{Path: "/home/u/.ssh", Holds: "credentials"}},
	}
	netPolicy := &policy.Policy{Entrypoint: "./x", Network: []policy.NetworkRule{{Host: "a.com", Port: "443"}}}

	var stdout, stderr bytes.Buffer
	err := writeRunResult(&stdout, &stderr, false, netPolicy, nil, res, nil, nil, nil)
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
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), nil, enforce.Result{ExitCode: 0}, nil, newEventStream(&stdout), nil)
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, present := env["shielded_grants"]; present {
		t.Error("shielded_grants must be omitted when empty (omitempty), not emitted as null/[]")
	}
}

// A read grant naming nothing on this host is the failure hardest to diagnose from the
// script's own output - an approved manifest whose data directory was since deleted, and
// a FileNotFoundError with nothing connecting it back. It is said on stderr on the way
// in, but the gate --help sends to --json read nothing; validate already answers it as
// missing_read_grants, and the envelope has to agree with that spelling.
func TestWriteRunResultReportsMissingReadGrants(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), nil, enforce.Result{ExitCode: 0}, []string{"/data/gone"}, newEventStream(&stdout), nil)
	var env struct {
		MissingReadGrants []string `json:"missing_read_grants"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if !slices.Equal(env.MissingReadGrants, []string{"/data/gone"}) {
		t.Errorf("missing_read_grants = %v, want the grant that named nothing", env.MissingReadGrants)
	}

	stdout.Reset()
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), nil, enforce.Result{ExitCode: 0}, nil, newEventStream(&stdout), nil)
	var raw map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, present := raw["missing_read_grants"]; present {
		t.Error("missing_read_grants must be omitted when every grant resolves (omitempty)")
	}
}

// The guard-blocked destinations reach a machine consumer too, and are omitted for the
// run the guard never refused.
func TestWriteRunResultReportsGuardBlocked(t *testing.T) {
	var stdout, stderr bytes.Buffer
	res := enforce.Result{ExitCode: 0, GuardBlocked: []enforce.HostPort{{Host: "internal.example", Port: "443"}}}
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), nil, res, nil, newEventStream(&stdout), nil)
	var env struct {
		GuardBlocked []struct {
			Host string `json:"host"`
			Port string `json:"port"`
		} `json:"guard_blocked"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if len(env.GuardBlocked) != 1 || env.GuardBlocked[0].Host != "internal.example" || env.GuardBlocked[0].Port != "443" {
		t.Errorf("guard_blocked = %+v, want the refused destination", env.GuardBlocked)
	}

	stdout.Reset()
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), nil, enforce.Result{ExitCode: 0}, nil, newEventStream(&stdout), nil)
	var raw map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, present := raw["guard_blocked"]; present {
		t.Error("guard_blocked must be omitted when the guard refused nothing (omitempty)")
	}
}

// failWriter is a stdout that always fails, so a test can drive the JSON-encode error
// path of writeRunResult.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("stdout is gone") }

// validPolicy is the minimal policy writeRunResult needs (writeEgressHint reads its
// Network); no network means the hint stays quiet.
// The two refusal sets are separate fields of the same type in a positional struct
// literal, so a run carrying one of each is what proves they did not get transposed -
// and they call for opposite operator action, so a swap would send a reader at the
// wrong fix. egress_connections alone answers neither question.
func TestWriteRunResultKeepsDeniedAndGuardBlockedApart(t *testing.T) {
	var stdout, stderr bytes.Buffer
	res := enforce.Result{
		ExitCode:     1,
		GuardBlocked: []enforce.HostPort{{Host: "internal.example", Port: "443"}},
		Denied:       []enforce.HostPort{{Host: "api.githb.com", Port: "443"}},
	}
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), nil, res, nil, newEventStream(&stdout), nil)
	var env struct {
		GuardBlocked []hostPortJSON `json:"guard_blocked"`
		EgressDenied []hostPortJSON `json:"egress_denied"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if len(env.GuardBlocked) != 1 || env.GuardBlocked[0].Host != "internal.example" {
		t.Errorf("guard_blocked = %+v, want the guard's refusal", env.GuardBlocked)
	}
	if len(env.EgressDenied) != 1 || env.EgressDenied[0].Host != "api.githb.com" {
		t.Errorf("egress_denied = %+v, want the allowlist's refusal", env.EgressDenied)
	}

	stdout.Reset()
	_ = writeRunResult(&stdout, &stderr, true, validPolicy(), nil, enforce.Result{ExitCode: 0}, nil, newEventStream(&stdout), nil)
	var raw map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, present := raw["egress_denied"]; present {
		t.Error("egress_denied must be omitted when nothing was refused (omitempty), not emitted as null/[]")
	}
}

// exec pumps the target's output into the stream, and an error returned there stops it
// draining the pipe: the target would block once the pipe filled. So a stdout that goes
// away mid-run must not become an error exec sees - the stream keeps accepting writes and
// remembers the failure for the run to report at the end.
func TestEventStreamAbsorbsADeadStdout(t *testing.T) {
	stream := newEventStream(errWriter{})
	w := stream.output("stdout")

	for _, line := range []string{"first\n", "second\n"} {
		n, err := w.Write([]byte(line))
		if err != nil || n != len(line) {
			t.Fatalf("Write = %d, %v; a dead stdout must not fail the pump", n, err)
		}
	}
	if stream.failed() == nil {
		t.Error("the stream must remember the write failure, not swallow it")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// The two stream pumps run in their own goroutines, so the stream has to serialize them:
// without the lock an object written mid-write splices into the other and neither line
// parses. Meaningful under -race, which is where the unsynchronized version fails.
func TestEventStreamSerializesTheTwoPumps(t *testing.T) {
	var dest bytes.Buffer
	stream := newEventStream(&dest)
	var wg sync.WaitGroup
	for _, name := range []string{"stdout", "stderr"} {
		wg.Add(1)
		w := stream.output(name)
		go func() {
			defer wg.Done()
			for range 100 {
				_, _ = w.Write([]byte("line\n"))
			}
		}()
	}
	wg.Wait()

	lines := 0
	for l := range strings.SplitSeq(strings.TrimSuffix(dest.String(), "\n"), "\n") {
		var ev streamEventJSON
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("a spliced line %q; the writes were not serialized", l)
		}
		if ev.Event != "stdout" && ev.Event != "stderr" {
			t.Fatalf("event = %q, want the stream that produced it", ev.Event)
		}
		if string(ev.Data) != "line\n" {
			t.Fatalf("data = %q, want the bytes the target wrote", ev.Data)
		}
		lines++
	}
	if lines != 200 {
		t.Errorf("got %d events, want 200: the stream dropped writes", lines)
	}
}

// The point of the change: nothing about a run is held until it ends. The buffered
// envelope grew with everything the target printed - measured at ~1x the output volume -
// so what this pins is that a chunk has reached the destination before the next one is
// written, with nothing accumulated in between.
func TestEventStreamHoldsNothingBetweenWrites(t *testing.T) {
	var dest bytes.Buffer
	w := newEventStream(&dest).output("stdout")
	for i, chunk := range []string{"first", "second", "third"} {
		before := dest.Len()
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
		if dest.Len() <= before {
			t.Fatalf("chunk %d was buffered rather than written; destination stayed at %d bytes", i, before)
		}
	}
}

// The refusal `bento run --json` answers with, which is not profile's: run's stdout is
// one object per line whether the run produced output or was refused before it started,
// so a consumer switches on event either way.
func TestRefuseStreamJSONEndsTheStreamWithARefusal(t *testing.T) {
	var buf bytes.Buffer
	want := errors.New("refusing to run: the manifest is not approved")
	err := refuseStreamJSON(&buf, true, want)
	if got := asExitError(t, err).code; got != bentoFailed {
		t.Fatalf("exit code = %d, want %d", got, bentoFailed)
	}

	var env struct {
		Event   string     `json:"event"`
		Refused bool       `json:"refused"`
		Reason  string     `json:"reason"`
		Report  reportJSON `json:"report"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("refusal event is not valid JSON: %v\n%s", err, buf.String())
	}
	if env.Event != "refusal" || env.Reason != want.Error() {
		t.Errorf("refusal event = %+v, want event=refusal with the error as its reason", env)
	}
	if env.Refused {
		t.Error("the stream discriminates on event; a refused field would be a second way to say it")
	}
	if env.Report.FullyEnforced || env.Report.Layers == nil {
		t.Errorf("report = %+v, want the empty report of a run that built no sandbox", env.Report)
	}
	// One line, so a consumer parsing the stream line by line reads it like any other.
	if strings.Count(strings.TrimSuffix(buf.String(), "\n"), "\n") != 0 {
		t.Errorf("refusal spans lines; the stream is one object per line:\n%s", buf.String())
	}
}

// Without --json the error is the frontend's own, rendered by main.
func TestRefuseStreamJSONLeavesTheHumanPathAlone(t *testing.T) {
	var buf bytes.Buffer
	want := errors.New("--env \"X\": want NAME=VALUE")
	if got := refuseStreamJSON(&buf, false, want); !errors.Is(got, want) {
		t.Errorf("err = %v, want the error returned untouched", got)
	}
	if buf.Len() != 0 {
		t.Errorf("stdout = %q, want nothing written outside --json", buf.String())
	}
}

// The labelling half of what the stream is for. The buffered envelope merged both of the
// target's streams onto bento's stderr as they arrived, so a consumer could only separate
// them from the envelope, after the run; each chunk now says which stream it came from as
// it happens, and the two interleave in the order they were written.
func TestEventStreamLabelsEachStreamInOrder(t *testing.T) {
	var dest bytes.Buffer
	stream := newEventStream(&dest)
	out, errOut := stream.output("stdout"), stream.output("stderr")
	for _, w := range []struct {
		w    io.Writer
		data string
	}{{out, "building\n"}, {errOut, "warning: slow\n"}, {out, "done\n"}} {
		if _, err := w.w.Write([]byte(w.data)); err != nil {
			t.Fatal(err)
		}
	}

	var got []string
	for l := range strings.SplitSeq(strings.TrimSuffix(dest.String(), "\n"), "\n") {
		var ev streamEventJSON
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("event is not valid JSON: %v\n%s", err, l)
		}
		got = append(got, ev.Event+":"+string(ev.Data))
	}
	want := []string{"stdout:building\n", "stderr:warning: slow\n", "stdout:done\n"}
	if !slices.Equal(got, want) {
		t.Errorf("events = %q, want %q", got, want)
	}
}

// A target is untrusted and prints whatever it likes. encoding/json replaces invalid
// UTF-8 in a Go string with U+FFFD, so the string field the old envelope used handed back
// corrupted bytes for any target that emitted binary, with nothing to say it had happened.
// The event carries []byte, which base64 round-trips.
func TestEventStreamRoundTripsNonUTF8Output(t *testing.T) {
	var dest bytes.Buffer
	stream := newEventStream(&dest)
	raw := []byte{0x00, 0xff, 0xfe, 'o', 'k', 0x80}
	if _, err := stream.output("stdout").Write(raw); err != nil {
		t.Fatal(err)
	}

	var ev streamEventJSON
	if err := json.Unmarshal(dest.Bytes(), &ev); err != nil {
		t.Fatalf("event is not valid JSON: %v\n%s", err, dest.String())
	}
	if !slices.Equal(ev.Data, raw) {
		t.Errorf("data = %v, want the target's bytes %v back unchanged", ev.Data, raw)
	}
}

// The generic profile hint sends the reader to reproduce the run, and a plain reprofile
// records egress without forwarding it - the same failure again. The denial notice has
// already named the destination and the flag that would rediscover it, so the hint's own
// account of a silently denied path must not follow it.
func TestNoProfileHintAfterADenial(t *testing.T) {
	var out, errOut bytes.Buffer
	p := &policy.Policy{Entrypoint: "./t.py", Read: []string{"/data"}}
	res := enforce.Result{ExitCode: 1, EgressConnections: 1, Denied: []enforce.HostPort{{Host: "api.githb.com", Port: "443"}}}
	_ = writeRunResult(&out, &errOut, false, p, nil, res, nil, nil, nil)
	if strings.Contains(errOut.String(), "the sandbox denies silently") {
		t.Errorf("the generic profile hint must not follow a denial; got:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "api.githb.com") {
		t.Errorf("the denial must still be named; got:\n%s", errOut.String())
	}
}

// The two flags are opposites, and strict silently winning discards an explicit
// opt-in. The pair is refused inside RunE rather than by cobra, so --json still gets
// its envelope on stdout - a machine gate cannot tell a bare refusal from a crash.
func TestRunRefusesStrictWithAllowDegraded(t *testing.T) {
	cmd := newRunCmd()
	cmd.SetArgs([]string{"--strict", "--allow-degraded", "nonexistent.manifest.yaml"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--allow-degraded") {
		t.Fatalf("Execute() error = %v, want a refusal naming both flags", err)
	}
	if strings.Contains(err.Error(), "nonexistent.manifest.yaml") {
		t.Errorf("the flags must be refused before the manifest is opened; got %v", err)
	}
}

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
	err := writeRunResult(&stdout, &stderr, false, validPolicy(), nil,
		enforce.Result{ExitCode: 0, Report: report}, nil, nil, shortfall)
	if got := asExitError(t, err).code; got != strictShortfall {
		t.Fatalf("shortfall exit code = %d, want %d - never the target's own code", got, strictShortfall)
	}
	if !strings.Contains(stderr.String(), "did not hold for the whole run") {
		t.Errorf("a strict shortfall must be named on stderr; got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	err = writeRunResult(&stdout, &stderr, true, validPolicy(), nil,
		enforce.Result{ExitCode: 7, Report: report}, nil, newEventStream(&stdout), shortfall)
	if got := asExitError(t, err).code; got != strictShortfall {
		t.Fatalf("shortfall exit code = %d, want %d in --json too", got, strictShortfall)
	}
	var env struct {
		Event           string `json:"event"`
		ExitCode        int    `json:"exit_code"`
		StrictShortfall bool   `json:"strict_shortfall"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if !env.StrictShortfall {
		t.Error("the verdict must mark the strict shortfall")
	}
	// The target ran, so this ends in a verdict - not the refusal or failed event, which
	// both say it did not produce the code below.
	if env.Event != "verdict" || env.ExitCode != 7 {
		t.Errorf("verdict = %+v, want event=verdict with the target's own code", env)
	}
}

// A refusal raised before enforce.Run was ever reached - a bad --env, an unparseable
// or unapproved manifest - used to return bare, leaving --json's stdout empty so jq
// could not tell a refusal from a crash (bv2-w4n5). It must produce the SAME refusal
// envelope the enforcement layer's own refusals produce, not a fourth shape. This is
// profile's shape; run answers the same case with a refusal event, see
// TestRefuseStreamJSONEndsTheStreamWithARefusal.
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

// A script that fails because the sandbox denied a path it needed reports its own error
// and nothing else - there is no observer at enforce time. The hint is the only thing
// connecting that back to the manifest, so it fires on any non-zero exit; and it must not
// stack onto the two cases that already explain the same failure.
func TestProfileHintOnANonZeroExit(t *testing.T) {
	granted := &policy.Policy{Entrypoint: "./t.py", Read: []string{"/data"}, Write: []string{"/out"}}
	networked := &policy.Policy{Entrypoint: "./t.py", Network: []policy.NetworkRule{{Host: "a.com", Port: "443"}}}

	cases := []struct {
		name      string
		p         *policy.Policy
		res       enforce.Result
		shortfall bool
		want      bool
	}{
		{"failed with grants", granted, enforce.Result{ExitCode: 1}, false, true},
		{"failed with none at all", &policy.Policy{Entrypoint: "./t.py"}, enforce.Result{ExitCode: 1}, false, true},
		{"succeeded", granted, enforce.Result{ExitCode: 0}, false, false},
		{"the egress hint already explained it", networked, enforce.Result{ExitCode: 1}, false, false},
		{"a strict shortfall has its own line", granted, enforce.Result{ExitCode: 1}, true, false},
		{"a guard block is not something profiling widens", granted, enforce.Result{ExitCode: 1, GuardBlocked: []enforce.HostPort{{Host: "a.com", Port: "443"}}}, false, false},
		{"the target never ran, so it failed on nothing profiling can see", granted, enforce.Result{ExitCode: 125, Setup: enforce.SetupTargetUnreached}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			var runErr error
			if tc.shortfall {
				runErr = &enforce.Shortfall{}
			}
			_ = writeRunResult(&out, &errOut, false, tc.p, nil, tc.res, nil, nil, runErr)
			if got := strings.Contains(errOut.String(), "bento profile"); got != tc.want {
				t.Errorf("profile hint emitted = %v, want %v; got:\n%s", got, tc.want, errOut.String())
			}
		})
	}

	// Suppressing the hints there must not leave the failure unexplained: the run ended
	// with bento's code, and nothing else on that path says so.
	var unreached bytes.Buffer
	_ = writeRunResult(io.Discard, &unreached, false, granted, nil,
		enforce.Result{ExitCode: 125, Setup: enforce.SetupTargetUnreached}, nil, nil, nil)
	for _, want := range []string{"could not start the target", "exit 125 is bento's"} {
		if !strings.Contains(unreached.String(), want) {
			t.Errorf("unreached-target notice missing %q; got:\n%s", want, unreached.String())
		}
	}
	for _, line := range strings.Split(strings.TrimSuffix(unreached.String(), "\n"), "\n") {
		if len(line) > textWidth {
			t.Errorf("notice line is %d columns, want at most %d: %q", len(line), textWidth, line)
		}
	}

	// --json carries the outcome as a field, and the hint on stdout would corrupt it.
	var out, errOut bytes.Buffer
	_ = writeRunResult(&out, &errOut, true, granted, nil, enforce.Result{ExitCode: 1}, nil, newEventStream(&out), nil)
	if strings.Contains(out.String()+errOut.String(), "bento profile") {
		t.Errorf("--json must not carry the hint; got:\n%s%s", out.String(), errOut.String())
	}

	// The counts are the point: they say how little was granted.
	errOut.Reset()
	_ = writeRunResult(&out, &errOut, false, granted, nil, enforce.Result{ExitCode: 3}, nil, nil, nil)
	for _, want := range []string{"exited 3", "1 read and 1 write"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("hint missing %q; got:\n%s", want, errOut.String())
		}
	}
}
