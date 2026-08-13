//go:build unix

package gate

import (
	"os"
	"path/filepath"
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
