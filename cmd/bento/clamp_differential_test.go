package main

import (
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
// interior of.
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

			wantDropped := (c.Verdict != shieldcorpus.Honored || c.OptInRead) && !c.ClampKeeps
			kept := append(append([]string{}, keptReads...), keptWrites...)
			gotDropped := len(dropped) > 0 || len(writeShielded) > 0
			if gotDropped != wantDropped {
				t.Errorf("%s\nthe run says %s, so the proposal must drop=%v; clamp dropped=%v (kept=%v, dropped=%v, writeShielded=%v)\nshape: %s",
					g, c.Verdict, wantDropped, gotDropped, kept, shieldGrantPaths(dropped), writeShielded, c.Why)
			}
		})
	}
}
