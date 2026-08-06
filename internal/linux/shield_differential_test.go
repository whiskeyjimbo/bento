//go:build linux

package linux

import (
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/internal/shieldcorpus"
)

// The backend half of the shield corpus (see internal/shieldcorpus). This one is
// authoritative: it asserts what a RUN does, and the corpus records that answer for the
// validate gate and the profiler clamp to be measured against in their own packages.
//
// A failure here means either the backend changed what it refuses - in which case the
// corpus moves and the other two follow - or the case is describing a shape the backend
// never had. It does not mean the corpus should be edited to match.
func TestShieldCorpusBackendVerdicts(t *testing.T) {
	for _, c := range shieldcorpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			home, err := shieldcorpus.Build(t.TempDir(), c)
			if err != nil {
				t.Fatal(err)
			}
			// A fresh sandbox per case, not one hoisted out of the loop: the symlink
			// set memoizes on an UNKEYED field (shieldCache), so a reused
			// sandbox would answer the second case with the first case's rules and say
			// nothing about it.
			sb := corpusSandbox(home)
			got := corpusVerdict(t, sb, c)
			if got != c.Verdict {
				t.Errorf("%s\nwant %s, got %s\nshape: %s", c.Path(home), c.Verdict, got, c.Why)
			}
		})
	}
}

// corpusSandbox is a sandbox seeing the real host through the same seams newSandbox
// wires for a run, anchored on the corpus home alone. Anchoring on the corpus home
// rather than denylist.HomeAnchors() is what makes the case's own layout the whole rule
// set: the developer's real ~/.ssh would otherwise contribute shields no case describes.
// The other two sites reach the same layout by setting HOME, which is where their
// anchors come from.
func corpusSandbox(home string) sandbox {
	return sandbox{
		homes:      []string{home},
		runtimeDir: denylist.RuntimeDir(),
		exists:     hostExists,
		isDir:      hostIsDir,
		resolve:    hostResolve,
		listDir:    hostListDir,
		// Allocated per sandbox for the reason newSandbox allocates them: the value is
		// copied at every call, so a nil map here would be a memo no caller shares.
		workspaceShieldCache: map[string][]denylist.Rule{},
		shieldCache:          &shieldMemo{},
	}
}

// corpusVerdict runs the shield checks in the order checkGrants runs them and reports
// which one refused, so the corpus records a verdict rather than a sentence. The
// sentences themselves are asserted by the tests that own each refusal; what the corpus
// is for is the three sites agreeing on WHICH grants are refusable at all.
func corpusVerdict(t *testing.T, sb sandbox, c shieldcorpus.Case) shieldcorpus.Verdict {
	t.Helper()
	g := c.Path(sb.homes[0])
	if !c.Write {
		optIns := shield.Targets(explicitShieldOptIns(sb, []string{g}))
		if c.OptInRead && len(optIns) == 0 {
			t.Errorf("%s is meant to be an opt-in read but the backend found no shield to opt into", g)
		}
		if err := checkReadNotShielded(sb, []string{g}, optIns); err != nil {
			return shieldcorpus.InsideShield
		}
		return shieldcorpus.Honored
	}
	writes := []string{g}
	if err := checkWriteNotShielded(sb, writes); err != nil {
		return shieldcorpus.InsideShield
	}
	if err := checkWriteNotUnderReadOnlyShield(sb, writes); err != nil {
		return shieldcorpus.UnderWriteShield
	}
	if err := checkWriteNotAboveShield(sb, writes); err != nil {
		return shieldcorpus.AboveShield
	}
	return shieldcorpus.Honored
}
