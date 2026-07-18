//go:build !linux

package backend

import "testing"

// Off Linux, New must REFUSE (error, nil enforcer) rather than substitute a
// permissive stand-in - the product's core "refuse rather than run unconfined"
// invariant. Runs only on non-Linux builds.
func TestNewRefusesOffLinux(t *testing.T) {
	e, err := New()
	if err == nil {
		t.Fatal("New off linux must return an error, not a permissive enforcer")
	}
	if e != nil {
		t.Fatal("New off linux must return a nil enforcer")
	}
}
