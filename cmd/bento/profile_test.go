package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/profile"
)

func TestClampBroadWrites(t *testing.T) {
	home, _ := os.UserHomeDir()

	deep := "/srv/app/data" // a specific directory, safe to grant
	writes := []string{deep, "/", "/etc", "/usr"}
	if home != "" {
		writes = append(writes, home)
	}

	kept, dropped := clampBroadWrites(writes)

	if !slices.Equal(kept, []string{deep}) {
		t.Fatalf("kept = %v, want just the specific directory %q", kept, deep)
	}
	for _, broad := range []string{"/", "/etc", "/usr"} {
		if !slices.Contains(dropped, broad) {
			t.Errorf("%q should be dropped as too broad to grant automatically", broad)
		}
	}
	if home != "" && !slices.Contains(dropped, home) {
		t.Errorf("the home directory %q should be dropped as too broad", home)
	}
}

func TestPartialRunWarning(t *testing.T) {
	if w := partialRunWarning(profile.Observation{ExitCode: 0}); w != "" {
		t.Errorf("clean run should not warn, got %q", w)
	}
	if w := partialRunWarning(profile.Observation{ExitCode: 7}); !strings.Contains(w, "exited with code 7") {
		t.Errorf("nonzero exit warning = %q, want it to name code 7", w)
	}
	// Signaled takes priority over the (implied nonzero) exit code.
	w := partialRunWarning(profile.Observation{Signaled: true, Signal: 9, ExitCode: 137})
	if !strings.Contains(w, "signal 9") || strings.Contains(w, "exited with code") {
		t.Errorf("signaled warning = %q, want it to name signal 9 and not the exit code", w)
	}
}
