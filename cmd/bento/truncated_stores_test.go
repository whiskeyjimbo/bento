package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TruncatedStores carries two shapes: a store nesting real directories past
// shield.MaxWalkDepth, and one whose directory read did not complete. They arrive on the
// same channel and doctor prints one sentence for both, so the sentence must not name the
// depth bound - an operator told an unreadable store nests too deep is sent to flatten a
// tree whose shape was never the problem.
//
// Driven through the unreadable half, since the depth half is what the wording already
// described. A real chmod rather than a seam: this walk is the host's own, and doctor
// assembles its set from shield.Host().
func TestDoctorDoesNotBlameTheDepthBoundForAnUnreadableStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0o000 directory, so nothing truncates")
	}
	home := t.TempDir()
	store := filepath.Join(home, ".password-store")
	unreadable := filepath.Join(store, "sub")
	if err := os.MkdirAll(unreadable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o700) })
	t.Setenv("HOME", home)

	human, _ := renderDoctor(t)
	if !strings.Contains(human, ".password-store") {
		t.Fatalf("a store whose read did not complete must be reported; got:\n%s", human)
	}
	if strings.Contains(human, "nest deeper") {
		t.Errorf("a store doctor could not read whole is reported as nesting too deep, and flattening it is not the remedy:\n%s", human)
	}
}
