package shield_test

import (
	"testing"

	"github.com/whiskeyjimbo/bento/internal/shield"
)

// A write verdict asks each DenyAll shield for the spelling that resolves the rule's PARENT
// and keeps its own name literal - the planted-link case. That spelling depends on the rule
// and the host, both fixed once the set is assembled, so asking the filesystem for it inside
// the verdict loop pays the whole set's resolutions on every grant. A read verdict returns
// before those loops and costs nothing, which is what says the cost is avoidable rather than
// inherent.
func TestWriteVerdictResolvesNothing(t *testing.T) {
	var resolves int
	s := shield.Assemble(shield.FS{
		IsDir:    func(string) bool { return false },
		Resolve:  func(p string) string { resolves++; return p },
		ListDir:  func(string) ([]string, []string, bool) { return nil, nil, true },
		SameFile: func(a, b string) bool { return a == b },
	}, []string{"/home/u"}, "/run/user/1000", nil)

	// A grant under no shield, so every loop runs to its end and the count is the worst
	// case rather than whatever an early return happened to leave.
	resolves = 0
	if _, v := s.Contains("/srv/work", shield.Read, nil, nil); v != shield.Honored {
		t.Fatalf("the control grant is under a shield (%v); pick one that is not", v)
	}
	if resolves != 0 {
		t.Fatalf("a read verdict cost %d resolves, so the fixture cannot tell the write path apart", resolves)
	}

	resolves = 0
	s.Contains("/srv/work", shield.Write, nil, nil)
	if resolves != 0 {
		t.Errorf("a write verdict cost %d resolves of values fixed at assembly", resolves)
	}
}
