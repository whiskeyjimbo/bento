package shield_test

import (
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/internal/shieldcorpus"
)

// The corpus (see internal/shieldcorpus) against the shared verdict. It records what a
// RUN does, so this is the assertion that the shared answer IS the backend's answer -
// which is the whole premise of the three call sites being able to route through it.
//
// The corpus is authored against the backend and asserted there too, so a divergence here
// is this package's, not the corpus's.
func TestCorpusVerdicts(t *testing.T) {
	for _, c := range shieldcorpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			home, err := shieldcorpus.Build(t.TempDir(), c)
			if err != nil {
				t.Fatal(err)
			}
			set := shield.Assemble(shieldcorpus.FS(c), []string{home}, denylist.RuntimeDir(), nil)
			g := c.Path(home)

			kind, optIns := shield.Write, []string(nil)
			if !c.Write {
				kind = shield.Read
				optIns = shield.Targets(set.OptIns([]string{g}))
				if c.OptInRead && len(optIns) == 0 {
					t.Errorf("%s is meant to be an opt-in read but no shield was found to opt into", g)
				}
			}
			// No workspace shields, as at the other two sites that call in here: they are
			// derived from the checkout under a grant, through seams only the backend has.
			// So a case whose refusal comes from one is Honored here, and the corpus says
			// which those are rather than leaving the gap unstated. WorkspaceRedirected is
			// the same gap reached differently - that refusal never goes through Contains -
			// so it is read off the verdict rather than off a field.
			wantV := want(c.Verdict)
			if c.WorkspaceDerived || c.Verdict == shieldcorpus.WorkspaceRedirected {
				// Asserted as a divergence rather than switched off: a case marked as
				// diverging that the run also honors documents nothing, and the field
				// silently covers a real disagreement the moment the corpus verdict moves.
				if c.Verdict == shieldcorpus.Honored {
					t.Fatalf("%s is marked as diverging here but the run honors it too, so there is no divergence to state", g)
				}
				wantV = shield.Honored
			}
			_, got := set.Contains(g, kind, optIns, nil)
			if got != wantV {
				t.Errorf("%s\nthe run says %s, the shared verdict says %v, want %v\nshape: %s", g, c.Verdict, got, wantV, c.Why)
			}
		})
	}
}

// want maps a corpus verdict onto this package's. They are separate types on purpose: the
// corpus describes what a run does in the frontend's terms, and a package that defined
// both sides of its own agreement would be asserting nothing.
func want(v shieldcorpus.Verdict) shield.Verdict {
	switch v {
	case shieldcorpus.InsideShield:
		return shield.InsideShield
	case shieldcorpus.UnderWriteShield:
		return shield.UnderWriteShield
	case shieldcorpus.AboveShield:
		return shield.AboveShield
	case shieldcorpus.FoldedShield:
		return shield.FoldedShield
	// WorkspaceRedirected has no counterpart here on purpose: that refusal is raised
	// outside the shield set, so this package's answer for it is the honored one the
	// caller then overrides.
	case shieldcorpus.Honored, shieldcorpus.WorkspaceRedirected:
	}
	return shield.Honored
}
