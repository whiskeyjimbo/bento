//go:build !linux

package backend

import (
	"context"
	"fmt"
	"runtime"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
	"github.com/whiskeyjimbo/bento-v2/internal/profile"
)

// New reports that this platform has no enforcement backend yet.
//
// It refuses rather than returning a permissive stand-in: a sandbox that cannot
// enforce anything is worse than no sandbox, because the caller believes their
// untrusted code is confined.
func New() (enforce.Enforcer, error) {
	return nil, fmt.Errorf("bento: no sandbox backend for %s yet (macOS support is planned; Linux requires bubblewrap)", runtime.GOOS)
}

// Profile is unavailable off Linux.
func Profile(ctx context.Context, p *policy.Policy, proc enforce.Process, allowNetwork bool) (profile.Observation, error) {
	return profile.Observation{}, fmt.Errorf("bento: profiling is not supported on %s", runtime.GOOS)
}
