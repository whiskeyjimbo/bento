//go:build !linux

package backend

import (
	"context"
	"fmt"
	"runtime"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
	"github.com/whiskeyjimbo/bento-v2/profile"
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
func Profile(ctx context.Context, p *policy.Policy, proc enforce.Process, opts ProfileOptions) (profile.Observation, error) {
	return profile.Observation{}, fmt.Errorf("bento: profiling is not supported on %s", runtime.GOOS)
}

// DispatchReexec is a no-op off Linux: only the Linux backend re-execs, so its
// sentinels can never legitimately appear here. It deliberately does not import
// the launcher package, which does not build off Linux.
func DispatchReexec() {}
