package denylist

import "testing"

// The deny-list is a security invariant: dropping an entry silently re-exposes a
// credential store. This guards the high-value stores that are easy to forget —
// OS keyrings and browser profiles hold saved passwords and session tokens.
func TestHomeShieldsSecretStores(t *testing.T) {
	rules := Home("/home/u")
	byPath := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byPath[r.Path] = r
	}

	wantDenyAllDir := []string{
		"/home/u/.ssh",
		"/home/u/.aws",
		"/home/u/.local/share/keyrings",
		"/home/u/.mozilla",
		"/home/u/.config/google-chrome",
		"/home/u/.config/rclone",
	}
	for _, p := range wantDenyAllDir {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyAll || !r.Dir {
			t.Errorf("%s: got Deny=%v Dir=%v, want DenyAll directory", p, r.Deny, r.Dir)
		}
	}

	wantDenyAllFile := []string{
		"/home/u/.netrc",
		"/home/u/.pgpass",
	}
	for _, p := range wantDenyAllFile {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyAll || r.Dir {
			t.Errorf("%s: got Deny=%v Dir=%v, want DenyAll file", p, r.Deny, r.Dir)
		}
	}
}
