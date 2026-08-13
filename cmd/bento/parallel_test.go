package main

import (
	"os"
	"strings"
	"testing"
)

// Nothing in this package may run its tests in parallel, and the reason is not
// discoverable from any one file: several of them reach into process-wide state for the
// length of a command. runCapturingStdout swaps os.Stdout, runProfileInteractively swaps
// both streams and the profilePrompts seam, and the ostree test swaps homeContainers.
// Each restores what it took, which is enough while the tests run one at a time and
// nothing at all once two overlap - a t.Parallel elsewhere in the package would send one
// test's output into another's pipe and be read as a missing line rather than as a
// harness fault.
//
// Asserted over the sources because there is no runtime symptom to assert on: the
// corruption is a wrong answer in an unrelated test. Elsewhere in the tree the
// *_adversarial_test.go files do use t.Parallel, so the convention this breaks with is a
// live one and the next person to follow it here should be told why.
func TestNoTestInThisPackageRunsInParallel(t *testing.T) {
	const guard = "parallel_test.go" // this file, which necessarily names the call
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, "_test.go") || name == guard {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "t.Parallel()") {
			t.Errorf("%s calls t.Parallel: this package's tests swap os.Stdout, os.Stderr, profilePrompts and homeContainers process-wide, so they must run one at a time", name)
		}
	}
}
