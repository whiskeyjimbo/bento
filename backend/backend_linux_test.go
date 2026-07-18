//go:build linux

package backend

import "testing"

// On Linux, New must return a usable enforcer and no error. Pins that the Linux
// build selects the real backend (bv2-6f7 - the package previously had no tests).
func TestNewReturnsLinuxEnforcer(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatalf("New on linux: unexpected error %v", err)
	}
	if e == nil {
		t.Fatal("New on linux returned a nil enforcer")
	}
}
