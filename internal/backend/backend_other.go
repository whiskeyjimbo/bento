//go:build !linux

package backend

import (
	"fmt"
	"runtime"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
)

// New reports that this platform has no enforcement backend yet.
//
// It refuses rather than returning a permissive stand-in: a sandbox that cannot
// enforce anything is worse than no sandbox, because the caller believes their
// untrusted code is confined.
func New() (enforce.Enforcer, error) {
	return nil, fmt.Errorf("bento: no sandbox backend for %s yet (macOS support is planned; Linux requires bubblewrap)", runtime.GOOS)
}
