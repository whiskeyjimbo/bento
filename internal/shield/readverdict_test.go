package shield_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// The three write-only verdicts are unreachable under shield.Read, and one early return in
// Contains is the whole of why. The gate names them as arms it deliberately leaves empty
// (gate.ShieldedReadProblems) and the backend's checkNotShielded does the same, so moving
// that return - adding a verdict ahead of it, or reordering the loops around it - would
// leave both of them silently reporting nothing about a refusal a run raises, in a switch
// that still compiles and still passes the exhaustive linter.
//
// Asserted here rather than in either caller because it is a property of this package:
// the callers can only mirror it.
func TestAReadGrantEarnsNoWriteOnlyVerdict(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{".ssh", ".pyenv/shims", ".local/bin"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	set := shield.Assemble(folding(false), []string{home}, denylist.RuntimeDir(), nil)

	// One grant per write-only verdict, each pinned as the write it is so a case that
	// stops reaching its verdict cannot pass this as a read that is honored.
	for _, c := range []struct {
		grant string
		write shield.Verdict
	}{
		{filepath.Join(home, ".local/bin"), shield.UnderWriteShield},
		{home, shield.AboveShield},
		{filepath.Join(home, ".pyenv"), shield.AboveWriteShield},
	} {
		if _, got := set.Contains(c.grant, shield.Write, nil, nil); got != c.write {
			t.Fatalf("write grant of %q: got %v, want %v", c.grant, got, c.write)
		}
		if _, got := set.Contains(c.grant, shield.Read, nil, nil); got != shield.Honored {
			t.Errorf("read grant of %q: got %v, want Honored - a write-only verdict reached a read", c.grant, got)
		}
	}
}
