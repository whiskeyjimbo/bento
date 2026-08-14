package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/internal/shieldcorpus"
)

// The profiler clamp against the shield corpus (see internal/shieldcorpus). The
// backend's half is the authoritative one, in internal/linux; the gate's is beside the
// gate. This one stays here because the clamp does: it is the CLI's proposal filter, and
// a clamp that proposes a grant the run refuses drafts the author a manifest that dies at
// its first step.

// The clamp answers keep-or-drop rather than a sentence, so the corpus verdict maps onto
// it: a grant the run refuses must not be proposed, since the reviewer would approve a
// manifest that cannot run. Two documented departures, both carried on the case:
// OptInRead, which the run honors but a draft manifest should not arrive holding, and
// ClampKeeps for a grant that merely contains a shield, which the run re-shields the
// interior of. WorkspaceDerived is NOT one of them: the clamp derives the checkout shields
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

			// WorkspaceRedirected is the third departure, and the one the clamp cannot
			// close: the refusal never goes through Contains, so no clamp built on the
			// shield set reaches it, and the grant is kept.
			wantDropped := (c.Verdict != shieldcorpus.Honored || c.OptInRead) &&
				!c.ClampKeeps && c.Verdict != shieldcorpus.WorkspaceRedirected
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
