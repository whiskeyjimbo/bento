//go:build darwin

// darwin rather than !linux, so the tag claims only what the tree can deliver. macOS is
// the one planned platform, and it is the only non-linux target cmd/bento compiles for:
// windows has no syscall.SIGSYS or syscall.Stat_t, and the BSDs have no unix.ENODATA.
// A "no backend here yet" stub that says those platforms build, on a tree that does not
// compile there, reports a backend gap where the real answer is that bento does not
// build at all.

package backend

import (
	"context"
	"fmt"
	"runtime"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
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
