// Package backend selects the enforcement backend for the host platform.
//
// It exists so frontends depend only on the enforce.Enforcer seam and never on a
// platform package: the CLI asks for "the enforcer for this host" and gets one,
// or a clear error saying this platform is not supported.
package backend

import (
	"context"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/linux"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
	"github.com/whiskeyjimbo/bento-v2/internal/profile"
)

// New returns the enforcer for this platform.
func New() (enforce.Enforcer, error) {
	return linux.New(), nil
}

// Profile runs p under observation and reports what the target did. Linux-only.
func Profile(ctx context.Context, p *policy.Policy, proc enforce.Process) (profile.Observation, error) {
	return linux.New().Profile(ctx, p, proc)
}
