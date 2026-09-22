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

// Most rules fail the byte-exact containment test against any given grant, so the
// component walk that settles a folded spelling runs for nearly every rule on every
// verdict. It has to answer that common case without building anything.
func TestAVerdictOverNoShieldDoesNotAllocate(t *testing.T) {
	s := shield.Assemble(shield.FS{
		IsDir:    func(string) bool { return false },
		Resolve:  func(p string) string { return p },
		ListDir:  func(string) ([]string, []string, bool) { return nil, nil, true },
		SameFile: func(a, b string) bool { return a == b },
	}, []string{"/home/u"}, "/run/user/1000", nil)

	// Beside the shields rather than above or below them, so every loop runs to its end and
	// no fold test is reached.
	const grant = "/home/u/projects/some-checkout"
	for _, kind := range []shield.Kind{shield.Read, shield.Write} {
		if _, v := s.Contains(grant, kind, nil, nil); v != shield.Honored {
			t.Fatalf("the grant is refused (%v); pick one no shield covers", v)
		}
		if n := testing.AllocsPerRun(20, func() { s.Contains(grant, kind, nil, nil) }); n != 0 {
			t.Errorf("a verdict of kind %v allocated %v times", kind, n)
		}
	}
}

// BenchmarkContains measures one verdict per kind over the assembled Home table, for a
// grant no shield covers - the verdict every ordinary project grant gets.
func BenchmarkContains(b *testing.B) {
	s := shield.Assemble(shield.FS{
		IsDir:    func(string) bool { return false },
		Resolve:  func(p string) string { return p },
		ListDir:  func(string) ([]string, []string, bool) { return nil, nil, true },
		SameFile: func(a, b string) bool { return a == b },
	}, []string{"/home/u"}, "/run/user/1000", nil)
	for _, kind := range []shield.Kind{shield.Read, shield.Write} {
		b.Run(map[shield.Kind]string{shield.Read: "read", shield.Write: "write"}[kind], func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				s.Contains("/home/u/projects/some-checkout", kind, nil, nil)
			}
		})
	}
}
