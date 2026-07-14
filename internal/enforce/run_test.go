package enforce

import (
	"context"
	"errors"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// fakeEnforcer is an in-memory Enforcer for exercising the core orchestration
// without any platform backend: it records that Run was reached and returns
// canned probe/result values.
type fakeEnforcer struct {
	probe  Report
	result Result
	ran    bool
}

func (f *fakeEnforcer) Probe(context.Context) Report { return f.probe }

func (f *fakeEnforcer) Run(context.Context, *policy.Policy, Process) (Result, error) {
	f.ran = true
	return f.result, nil
}

func TestRunDelegatesAndPropagatesExit(t *testing.T) {
	f := &fakeEnforcer{result: Result{ExitCode: 7}}
	res, err := Run(context.Background(), f, &policy.Policy{Entrypoint: "./x"}, Process{}, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !f.ran {
		t.Error("enforcer.Run was not reached")
	}
	if res.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7", res.ExitCode)
	}
}

func TestStrictRefusesOnDegradation(t *testing.T) {
	f := &fakeEnforcer{}
	f.probe.Add(LayerNetwork, Degraded, "pasta missing")
	_, err := Run(context.Background(), f, &policy.Policy{Entrypoint: "./x"}, Process{}, Options{Strict: true})

	var refusal *StrictRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want *StrictRefusal", err)
	}
	if f.ran {
		t.Error("strict mode ran the target despite a degraded layer")
	}
	if len(refusal.Report.Degradations()) != 1 {
		t.Errorf("degradations = %d, want 1", len(refusal.Report.Degradations()))
	}
}

func TestStrictRunsWhenFullyEnforced(t *testing.T) {
	f := &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Enforced, "")
	f.probe.Add(LayerNetwork, Enforced, "")
	if _, err := Run(context.Background(), f, &policy.Policy{Entrypoint: "./x"}, Process{}, Options{Strict: true}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !f.ran {
		t.Error("strict mode refused a fully-enforced host")
	}
}

func TestRunRejectsNilArgs(t *testing.T) {
	if _, err := Run(context.Background(), nil, &policy.Policy{}, Process{}, Options{}); err == nil {
		t.Error("expected error for nil enforcer")
	}
	if _, err := Run(context.Background(), &fakeEnforcer{}, nil, Process{}, Options{}); err == nil {
		t.Error("expected error for nil policy")
	}
}

func TestReportDegradation(t *testing.T) {
	var r Report
	if r.HasDegradation() {
		t.Error("empty report should not report degradation")
	}
	r.Add(LayerFilesystem, Enforced, "")
	r.Add(LayerExec, Unavailable, "no seccomp")
	if !r.HasDegradation() {
		t.Error("report with an unavailable layer should report degradation")
	}
	deg := r.Degradations()
	if len(deg) != 1 || deg[0].Layer != LayerExec {
		t.Errorf("degradations = %+v, want [exec-block]", deg)
	}
}

func TestStateString(t *testing.T) {
	for state, want := range map[State]string{Enforced: "enforced", Degraded: "degraded", Unavailable: "unavailable"} {
		if got := state.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", state, got, want)
		}
	}
}
