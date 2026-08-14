package gate_test

import (
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/internal/shieldcorpus"
)

// The validate gate against the shield corpus (see internal/shieldcorpus). The backend's
// own half of it lives in internal/linux and is the authoritative one; this one is
// measured against the verdict it recorded, because a gate that green-lights what a run
// refuses hands the author a manifest that dies at its first step. The profiler clamp is
// the third site, asserted beside the clamp in cmd/bento.
//
// The gate and the backend are allowed to differ in one direction only - the gate misses
// a refusal, never invents one - and for two reasons: it cannot see the caller-supplied
// denies an embedder passes, and it passes no workspace shields, so a refusal derived from
// the checkout under a grant is one it cannot reach. Nothing in this corpus uses the
// former; the latter is carried on Case.WorkspaceDerived, and on the WorkspaceRedirected
// verdict for the one refusal that does not go through the shield set at all.

// gateVerdict classifies the sentence the gate refuses a grant with. Matched on the
// distinguishing clause rather than the whole sentence because the corpus records which
// refusal a grant earns, not the wording - the wording is asserted where each sentence is
// built.
func gateVerdict(t *testing.T, c shieldcorpus.Case, home string) shieldcorpus.Verdict {
	t.Helper()
	g := c.Path(home)
	// The set is assembled here rather than taken from gate.ShieldSet so the case's mount
	// reaches the gate at all: folding is a property of the filesystem seam, and ShieldSet
	// builds the real host's. Everything else about it is what ShieldSet would have built,
	// off the same anchors the corpus home gives it.
	set := shield.Assemble(shieldcorpus.FS(c), []string{home}, denylist.RuntimeDir(), nil)
	var problems []string
	if c.Write {
		problems = gate.ShieldedWriteProblems(set, []string{g})
	} else {
		problems = gate.ShieldedReadProblems(set, []string{g})
	}
	if len(problems) == 0 {
		return shieldcorpus.Honored
	}
	switch p := problems[0]; {
	case strings.Contains(p, "is inside the always-shielded path"):
		return shieldcorpus.InsideShield
	case strings.Contains(p, "is at or inside the write-shielded path"):
		return shieldcorpus.UnderWriteShield
	case strings.Contains(p, "on a case-insensitive filesystem"):
		return shieldcorpus.FoldedShield
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
			want := c.Verdict
			if c.WorkspaceDerived || c.Verdict == shieldcorpus.WorkspaceRedirected {
				// Asserted as a divergence rather than switched off: a case marked as
				// diverging that the run also honors states nothing, and would go on
				// stating nothing after the corpus verdict moved under it.
				if c.Verdict == shieldcorpus.Honored {
					t.Fatalf("%s is marked as diverging from the gate but the run honors it too, so there is no divergence to state", c.Path(home))
				}
				want = shieldcorpus.Honored
			}
			if got := gateVerdict(t, c, home); got != want {
				t.Errorf("%s\nthe run says %s, the gate says %s, want %s\nshape: %s", c.Path(home), c.Verdict, got, want, c.Why)
			}
		})
	}
}
