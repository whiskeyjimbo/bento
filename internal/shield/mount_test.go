package shield_test

import (
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// The backend mounts the assembled set again, with a workspace's rules appended, on every
// derivation of a run's shields. The set already resolved its own rules to assemble, so
// mounting them again must not resolve them a second time - only what was appended.
func TestMountReusesTheSetsResolvedRules(t *testing.T) {
	var resolves int
	s := shield.Assemble(shield.FS{
		IsDir:    func(string) bool { return false },
		Resolve:  func(p string) string { resolves++; return p },
		ListDir:  func(string) ([]string, []string, bool) { return nil, nil, true },
		SameFile: func(a, b string) bool { return a == b },
	}, []string{"/home/u"}, "/run/user/1000", nil)
	resolves = 0
	if got := len(s.Mount(s.Rules())); got != len(s.Shields()) {
		t.Fatalf("mounting the set gave %d shields, want the %d it assembled", got, len(s.Shields()))
	}
	if resolves != 0 {
		t.Errorf("mounting the assembled set again cost %d resolves", resolves)
	}
	// The backend appends a workspace's rules onto this slice and memoizes what comes
	// back. Spare capacity here would put two of those answers in one array, so the set
	// keeps none - asserted directly, because whether a clone happens to leave any
	// depends on how the allocator rounds the rule count.
	if rules := s.Rules(); cap(rules) != len(rules) {
		t.Errorf("Rules has %d of spare capacity, which an appending caller writes into", cap(rules)-len(rules))
	}
	resolves = 0
	s.Mount(append(s.Rules(), denylist.Rule{Path: "/w/.git/hooks", Deny: denylist.DenyWrite, Dir: true}))
	if resolves != 1 {
		t.Errorf("mounting one appended rule cost %d resolves, want 1", resolves)
	}
}
