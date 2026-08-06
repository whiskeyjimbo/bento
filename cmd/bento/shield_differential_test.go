package main

import (
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/internal/shieldcorpus"
)

// The validate gate and the profiler clamp against the shield corpus (see
// internal/shieldcorpus). The backend's own half of it lives in internal/linux and is
// the authoritative one; these two are measured against the verdict it recorded, because
// a gate that green-lights what a run refuses hands the author a manifest that dies at
// its first step, and a clamp that proposes one drafts it for them.
//
// The gate and the backend are allowed to differ in exactly one direction and for
// exactly one reason: the gate cannot see the caller-supplied denies an embedder passes,
// so it can miss a refusal. Nothing in this corpus uses those, so here they must agree
// outright.

// gateVerdict classifies the sentence the gate refuses a grant with. Matched on the
// distinguishing clause rather than the whole sentence because the corpus records which
// refusal a grant earns, not the wording - the wording is asserted where each sentence is
// built.
func gateVerdict(t *testing.T, c shieldcorpus.Case, home string) shieldcorpus.Verdict {
	t.Helper()
	g := c.Path(home)
	var problems []string
	var err error
	if c.Write {
		problems, err = gate.ShieldedWriteProblems([]string{g})
	} else {
		problems, err = gate.ShieldedReadProblems([]string{g})
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) == 0 {
		return shieldcorpus.Honored
	}
	switch p := problems[0]; {
	case strings.Contains(p, "is inside the always-shielded path"):
		return shieldcorpus.InsideShield
	case strings.Contains(p, "is at or inside the write-shielded path"):
		return shieldcorpus.UnderWriteShield
	case strings.Contains(p, "contains the always-shielded path"):
		return shieldcorpus.AboveShield
	default:
		t.Fatalf("gate refused %q in a sentence the corpus cannot classify: %s", g, p)
		return shieldcorpus.Honored
	}
}

func TestShieldCorpusGateVerdicts(t *testing.T) {
	for _, c := range shieldcorpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			home, err := shieldcorpus.Build(t.TempDir(), c)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			if got := gateVerdict(t, c, home); got != c.Verdict {
				t.Errorf("%s\nthe run says %s, the gate says %s\nshape: %s", c.Path(home), c.Verdict, got, c.Why)
			}
		})
	}
}

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
			t.Setenv("HOME", home)
			g := c.Path(home)
			var reads, writes []string
			if c.Write {
				writes = []string{g}
			} else {
				reads = []string{g}
			}
			keptReads, keptWrites, dropped, writeShielded := clampShieldedGrants(reads, writes)

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
