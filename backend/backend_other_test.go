//go:build darwin

package backend

import (
	"context"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
)

// Off Linux, New must REFUSE (error, nil enforcer) rather than substitute a
// permissive stand-in - the product's core "refuse rather than run unconfined"
// invariant. Runs on darwin, the one platform the stub is built for.
func TestNewRefusesOffLinux(t *testing.T) {
	e, err := New()
	if err == nil {
		t.Fatal("New off linux must return an error, not a permissive enforcer")
	}
	if e != nil {
		t.Fatal("New off linux must return a nil enforcer")
	}
}

// Profile must also refuse off Linux. A regression to (Observation{}, nil) would
// read to an embedder as "profiled cleanly, nothing observed" - the same
// runs-unconfined-but-believed-safe failure the New refusal guards against.
func TestProfileRefusesOffLinux(t *testing.T) {
	obs, err := Profile(context.Background(), nil, enforce.Process{}, ProfileOptions{})
	if err == nil {
		t.Fatal("Profile off linux must return an error, not a nil error")
	}
	if len(obs.Reads) != 0 || len(obs.Writes) != 0 || len(obs.Hosts) != 0 {
		t.Fatal("Profile off linux must return an empty observation")
	}
}
