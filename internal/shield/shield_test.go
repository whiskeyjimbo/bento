package shield_test

import (
	"os"
	"path/filepath"
	"slices"
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
	// The degraded tier's verdict is no divergence here: the shared answer is where the two
	// above-directions are told apart in the first place, and it is the callers that decide
	// what to do with it.
	case shieldcorpus.AboveWriteShield:
		return shield.AboveWriteShield
	case shieldcorpus.FoldedShield:
		return shield.FoldedShield
	// WorkspaceRedirected has no counterpart here on purpose: that refusal is raised
	// outside the shield set, so this package's answer for it is the honored one the
	// caller then overrides. FoldedWorkspaceExposed has none for a stronger reason - it is
	// not a refusal at all, so Contains has nothing to return for it, and the answer it
	// DOES have lives on FoldedWorkspaceShields. TestFoldedWorkspaceShieldsAreDisclosedNotRefused
	// is where that half is asserted.
	case shieldcorpus.Honored, shieldcorpus.WorkspaceRedirected, shieldcorpus.FoldedWorkspaceExposed:
	}
	return shield.Honored
}

// Contains consults the run's workspace shields under a Deny == DenyWrite guard
// (verdict.go's workspace loop), and every rule denylist.Workspace and WorkspaceGitfile
// emit is DenyWrite today, so the guard costs nothing. Nothing held that in place: a
// DenyAll rule added to Workspace - a checkout-local credential store is the obvious next
// entry - would be assembled, mounted by the enforcer, and never once refuse a grant,
// with nothing failing to compile and nothing failing to pass.
//
// Asserted through Contains rather than over the rules' Deny field, so the pin is on the
// consequence: a rule this guard drops is a write the run would have bound.
func TestEveryWorkspaceRuleRefusesAWriteAtItself(t *testing.T) {
	home := t.TempDir()
	checkout := filepath.Join(home, "proj")
	if err := os.MkdirAll(checkout, 0o700); err != nil {
		t.Fatal(err)
	}
	set := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(), nil)

	for _, emitter := range []struct {
		name  string
		rules []denylist.Rule
	}{
		{"Workspace", denylist.Workspace(checkout)},
		{"WorkspaceGitfile", denylist.WorkspaceGitfile(checkout)},
	} {
		for _, r := range emitter.rules {
			if _, got := set.Contains(r.Path, shield.Write, nil, emitter.rules); got != shield.UnderWriteShield {
				t.Errorf("%s rule %s (Deny %v) refuses nothing: Contains answered %v, and a rule its DenyWrite guard drops is mounted by the enforcer while every grant under it is honored",
					emitter.name, r.Path, r.Deny, got)
			}
		}
	}
}

// The above direction for a checkout-derived shield on a folding mount: the one shape
// where the run has something to say and nothing to refuse with.
//
// Four claims, and the first is the decision rather than the code. A checkout-derived
// shield sits strictly under its own grant, so Contains MUST answer Honored here - adding
// the workspace half to its above-direction loops would refuse every "write: <checkout>"
// on any case-insensitive volume, and offer a remedy (grant something that stops short of
// the shield) that an author whose whole checkout is the grant cannot take. The control
// pins that the folding seam is live while that Honored is being asserted, so the first
// claim cannot pass by the fold simply not reaching the set.
//
// The third is the disclosure that stands in for the refusal, and the fourth is its bound:
// on a host that folds nothing the same layout must disclose nothing, or every ordinary
// run warns about a shield that holds.
func TestFoldedWorkspaceShieldsAreDisclosedNotRefused(t *testing.T) {
	home := t.TempDir()
	checkout := filepath.Join(home, "proj")
	hooks := filepath.Join(checkout, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	pyenv := filepath.Join(home, ".pyenv")
	if err := os.MkdirAll(filepath.Join(pyenv, "shims"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The corpus's folding seam rather than one written here, so this test and the three
	// differential sites cannot disagree about which names collide.
	folding := shield.Assemble(shieldcorpus.FS(shieldcorpus.Case{Folding: true}), []string{home}, denylist.RuntimeDir(), nil)
	workspace := denylist.Workspace(checkout)

	if _, got := folding.Contains(checkout, shield.Write, nil, workspace); got != shield.Honored {
		t.Errorf("write over the checkout answered %v; a self-derived shield is structurally under its own grant, so refusing here refuses every project write on a folding mount and offers a remedy the author cannot take", got)
	}
	if _, got := folding.Contains(pyenv, shield.Write, nil, nil); got != shield.FoldedShield {
		t.Fatalf("the built-in control answered %v, want FoldedShield: the folding seam is not reaching the set, so the honored answer above states nothing", got)
	}

	if got := paths(folding.FoldedWorkspaceShields(checkout, workspace)); !slices.Contains(got, hooks) {
		t.Errorf("the fold walks around the ro-bind at %s and the set discloses %v; with no refusal raised, an undisclosed fold leaves a plantable pre-commit named nowhere", hooks, got)
	}
	byteExact := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(), nil)
	if got := byteExact.FoldedWorkspaceShields(checkout, workspace); len(got) > 0 {
		t.Errorf("a host that folds nothing disclosed %v; the shield holds there, and warning about it would put the notice on every ordinary run", paths(got))
	}
}

func paths(rules []denylist.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Path)
	}
	return out
}
