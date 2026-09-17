package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/internal/shieldcorpus"
	"github.com/whiskeyjimbo/bento/policy"
)

// The profiler clamp against the shield corpus (see internal/shieldcorpus). The
// backend's half is the authoritative one, in internal/linux; the gate's is beside the
// gate. This one stays here because the clamp does: it is the CLI's proposal filter, and
// a clamp that proposes a grant the run refuses drafts the author a manifest that dies at
// its first step.

// The clamp answers keep-or-drop rather than a sentence, so the corpus verdict maps onto
// it: a grant the run refuses must not be proposed, since the reviewer would approve a
// manifest that cannot run. Two documented departures are carried on the case: OptInRead,
// which the run honors but a draft manifest should not arrive holding, and ClampKeeps for
// a grant that merely contains a shield, which the run re-shields the interior of. A third
// is read off the verdict below, because it holds for the shape rather than the case.
// WorkspaceDerived is NOT one of the three: the clamp derives the checkout shields
// under its write grants itself, so a refusal the run raises from one is a drop here too.
func TestShieldCorpusClampDrops(t *testing.T) {
	for _, c := range shieldcorpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			home, err := shieldcorpus.Build(t.TempDir(), c)
			if err != nil {
				t.Fatal(err)
			}
			g := c.Path(home)
			// Assembled here rather than taken from gate.ShieldSet so the case's mount
			// reaches the clamp: folding is a property of the filesystem seam, and
			// ShieldSet builds the real host's. The anchors are the corpus home either way.
			set := shield.Assemble(shieldcorpus.FS(c), []string{home}, denylist.RuntimeDir(), nil)
			var reads, writes []string
			if c.Write {
				writes = []string{g}
			} else {
				reads = []string{g}
			}
			keptReads, keptWrites, dropped, writeShielded := clampShieldedGrants(set, reads, writes)
			// The redirected-shield refusal never goes through Contains, so it is asked
			// separately, as clampProposal does.
			redirected := &policy.Policy{Write: keptWrites}
			if refused := withholdRedirectedWorkspace(redirected); len(refused) > 0 {
				writeShielded = append(writeShielded, refused[0].Path)
			}
			keptWrites = redirected.Write

			wantDropped := (c.Verdict != shieldcorpus.Honored || c.OptInRead) &&
				!c.ClampKeeps && c.Verdict != shieldcorpus.AboveWriteShield
			// The third departure, and the only one whose answer is neither keep nor drop:
			// a grant containing a DenyWrite shield is kept - dropping it would withhold
			// write: ~/.pyenv from every full-tier proposal - and reported, so the reviewer
			// is told the manifest cannot run degraded. Asserted here rather than left to the
			// boolean above, which cannot express the second half.
			if c.Verdict == shieldcorpus.AboveWriteShield && !slices.Contains(aboveWriteShieldGrants(set, keptWrites), g) {
				t.Errorf("%s\nthe run refuses it on the degraded tier, and the clamp keeps it without reporting it (reported: %v)\nshape: %s",
					g, aboveWriteShieldGrants(set, keptWrites), c.Why)
			}
			kept := append(append([]string{}, keptReads...), keptWrites...)
			gotDropped := len(dropped) > 0 || len(writeShielded) > 0
			if gotDropped != wantDropped {
				t.Errorf("%s\nthe run says %s, so the proposal must drop=%v; clamp dropped=%v (kept=%v, dropped=%v, writeShielded=%v)\nshape: %s",
					g, c.Verdict, wantDropped, gotDropped, kept, shieldGrantPaths(dropped), writeShielded, c.Why)
			}
		})
	}
}

// A write grant that CONTAINS a DenyWrite shield - write: ~/.pyenv over the ~/.pyenv/shims
// shield - is refused by checkWriteNotAboveWriteShield on the degraded tier, where there is
// no bind to re-shield the interior with and Landlock takes the union of matching rules.
// The clamp cannot know which tier will run, so it keeps the grant (dropping it would take
// write: ~/.pyenv out of every full-tier proposal, which is the direction the gate rules out
// for itself) and reports it instead - the foreignHomeShields stance, for the same reason.
func TestClampReportsAWriteGrantContainingAWriteShield(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".pyenv", "shims"), 0o755); err != nil {
		t.Fatal(err)
	}
	set := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(), nil)
	grant := filepath.Join(home, ".pyenv")

	_, kept, _, writeShielded := clampShieldedGrants(set, nil, []string{grant})
	if !slices.Contains(kept, grant) {
		t.Errorf("the clamp dropped %q; a grant containing a write shield is honored on the full tier, so dropping it withholds an ordinary proposal", grant)
	}
	if len(writeShielded) != 0 {
		t.Errorf("the grant was reported as dropped (%v), but it is kept", writeShielded)
	}
	if got := aboveWriteShieldGrants(set, kept); !slices.Contains(got, grant) {
		t.Errorf("the clamp keeps %q without reporting it; a degraded run refuses it, so the reviewer approves a manifest that dies at its first step (reported: %v)", grant, got)
	}
}

// The corpus through the whole proposal rather than clampShieldedGrants alone. ClampKeeps
// cases are kept by that first step on purpose and left to withholdRunRefused, so a test
// that stops at the first step cannot see a proposal the run refuses. Only the refusing
// direction is asserted: gate.Refusals reads the real host under $HOME, so it may refuse
// more than the corpus layout alone would, and folding cases are skipped because that
// host's mount does not fold.
func TestShieldCorpusProposalWithholdsRunRefusedGrants(t *testing.T) {
	for _, c := range shieldcorpus.Cases {
		if c.Folding || c.Verdict == shieldcorpus.Honored || c.Verdict == shieldcorpus.AboveWriteShield {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			home, err := shieldcorpus.Build(t.TempDir(), c)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			g := c.Path(home)
			p := &policy.Policy{}
			if c.Write {
				p.Write = []string{g}
			} else {
				p.Read = []string{g}
			}
			clampProposal(p)
			if slices.Contains(p.Read, g) || slices.Contains(p.Write, g) {
				t.Errorf("%s\nthe run says %s, and the proposal still holds it (read=%v, write=%v)\nshape: %s",
					g, c.Verdict, p.Read, p.Write, c.Why)
			}
		})
	}
}
