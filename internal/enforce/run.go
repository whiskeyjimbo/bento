package enforce

import (
	"context"
	"fmt"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// Options tunes a Run.
type Options struct {
	// Strict refuses to run when the host cannot fully enforce every layer,
	// rather than degrading into a weaker sandbox. Off by default.
	Strict bool
}

// Run orchestrates a sandboxed execution. In strict mode it first probes the
// host and refuses if any layer would be degraded; otherwise it delegates to e.
// It is the one entry frontends call, so the strict-versus-degrade decision
// lives in a single place regardless of backend or frontend.
func Run(ctx context.Context, e Enforcer, p *policy.Policy, proc Process, opts Options) (Result, error) {
	if e == nil {
		return Result{}, fmt.Errorf("enforce: nil enforcer")
	}
	if p == nil {
		return Result{}, fmt.Errorf("enforce: nil policy")
	}
	if opts.Strict {
		if pr := e.Probe(ctx); pr.HasDegradation() {
			return Result{}, &StrictRefusal{Report: pr}
		}
	}
	return e.Run(ctx, p, proc)
}

// StrictRefusal is returned when strict mode declines to run because the host
// cannot fully enforce every layer. It carries the probe report so a frontend
// can show exactly which layers fell short.
type StrictRefusal struct {
	Report Report
}

func (e *StrictRefusal) Error() string {
	return fmt.Sprintf("strict mode: refusing to run, %d layer(s) not fully enforced", len(e.Report.Degradations()))
}
