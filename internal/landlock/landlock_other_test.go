//go:build !linux

package landlock

import "testing"

// Every Restrict* reports whether confinement was applied, and off Linux none can be, so
// a nil from any of them would let a caller report a fence that is not there.
func TestRestrictRefusesOffLinux(t *testing.T) {
	for name, err := range map[string]error{
		"Restrict":              Restrict(nil),
		"RestrictTo":            RestrictTo(nil, nil),
		"RestrictDegraded":      RestrictDegraded(nil, nil, nil),
		"RestrictExecAllowlist": RestrictExecAllowlist(nil, nil),
	} {
		if err == nil {
			t.Errorf("%s returned nil off Linux, reporting confinement it did not apply", name)
		}
	}
}
