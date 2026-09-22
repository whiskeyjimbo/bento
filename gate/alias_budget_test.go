//go:build unix

package gate

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The scan is on `bento validate`'s default path, and on a host holding one hardlinked
// credential it walks every granted tree whole: a granted module cache took validate from
// 40ms to 1.14s here. The budget is what stops that, and what it owes the caller is the
// distinction an empty list cannot carry on its own - a tree read to the end, against one
// the walk left part way down.
func TestAliasWalkStopsOnItsBudget(t *testing.T) {
	root := t.TempDir()
	for i := range 20 {
		if err := os.WriteFile(filepath.Join(root, string(rune('a'+i))), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing is wanted, so nothing is found either way and only the stop is under test.
	want := map[fileID]string{}

	budget := 5
	if _, stopped := aliasesUnder(root, want, &budget); !stopped {
		t.Error("a tree with more entries than the budget must be reported as stopped short")
	}
	if budget > 0 {
		t.Errorf("the walk must spend its budget; %d left", budget)
	}

	// A budget the tree does not exhaust leaves the answer whole, and the remainder is what
	// the next granted tree walks on - the budget is one allowance for the whole answer.
	budget = 1000
	if _, stopped := aliasesUnder(root, want, &budget); stopped {
		t.Error("a tree that fits inside the budget was read to the end")
	}
	if budget != 1000-21 {
		t.Errorf("every entry counts, the root included; %d left of 1000", budget)
	}

	// The boundary: a walk whose last entry spends the last of the budget read the whole
	// tree, and calling that partial puts a note in front of a reader with nothing behind
	// it. Reported rather than inferred from an exhausted budget, which is why.
	budget = 21
	if _, stopped := aliasesUnder(root, want, &budget); stopped {
		t.Errorf("a walk that ended exactly on its last entry is not partial; %d left", budget)
	}
}

// BenchmarkAliasWalkBudget measures a walk the budget cuts short, which is the shape a
// large grant takes on validate's default path: its cost is bounded by aliasBudget, not by
// the tree, so this is the most one granted tree can cost validate.
func BenchmarkAliasWalkBudget(b *testing.B) {
	root := b.TempDir()
	for i := range 60 {
		d := filepath.Join(root, fmt.Sprintf("d%d", i))
		if err := os.Mkdir(d, 0o755); err != nil {
			b.Fatal(err)
		}
		for j := range aliasBudget / 59 {
			if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("f%d", j)), nil, 0o600); err != nil {
				b.Fatal(err)
			}
		}
	}
	// A wanted device, so the walk cannot prune the tree by device and spends the budget.
	fi, err := os.Stat(root)
	if err != nil {
		b.Fatal(err)
	}
	want := map[fileID]string{{dev: uint64(fi.Sys().(*syscall.Stat_t).Dev)}: "/nowhere"}
	// Checked once, outside the timing: a budget the tree fits inside would time the whole
	// walk rather than the bounded one.
	budget := aliasBudget
	if _, stopped := aliasesUnder(root, want, &budget); !stopped {
		b.Fatal("the walk finished inside its budget, so the benchmark is not measuring the stop")
	}
	b.ReportAllocs()
	for b.Loop() {
		budget := aliasBudget
		aliasesUnder(root, want, &budget)
	}
}
