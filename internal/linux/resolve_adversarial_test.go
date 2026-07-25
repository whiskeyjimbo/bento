package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdversarialSymlinkResolution(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// 1. Setup nested target: tmpDir/real/target
	realDir := filepath.Join(tmpDir, "real")
	targetDir := filepath.Join(realDir, "target")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("failed to create target dir: %v", err)
	}

	// 2. Setup symlink: tmpDir/link -> real/target
	linkPath := filepath.Join(tmpDir, "link")
	if err := os.Symlink(filepath.Join("real", "target"), linkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// 3. Setup symlink cycle: tmpDir/cycleA -> tmpDir/cycleB -> tmpDir/cycleA
	cycleA := filepath.Join(tmpDir, "cycleA")
	cycleB := filepath.Join(tmpDir, "cycleB")
	if err := os.Symlink("cycleB", cycleA); err != nil {
		t.Fatalf("failed to create cycleA: %v", err)
	}
	if err := os.Symlink("cycleA", cycleB); err != nil {
		t.Fatalf("failed to create cycleB: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		check    func(t *testing.T, got string)
	}{
		{
			name: "eval_symlink_before_dotdot",
			path: linkPath + "/../sibling",
			check: func(t *testing.T, got string) {
				want := filepath.Join(realDir, "sibling")
				if got != want {
					t.Fatalf("resolve(%q) = %q; want %q", linkPath+"/../sibling", got, want)
				}
			},
		},
		{
			name: "handle_symlink_cycle_gracefully",
			path: cycleA,
			check: func(t *testing.T, got string) {
				if !strings.HasSuffix(got, "cycleA") && !strings.HasSuffix(got, "cycleB") {
					t.Fatalf("resolve on symlink cycle = %q; expected path ending in cycleA or cycleB", got)
				}
			},
		},
		{
			name: "resolve_root_path",
			path: "/",
			check: func(t *testing.T, got string) {
				if got != "/" {
					t.Fatalf("resolve(\"/\") = %q; want \"/\"", got)
				}
			},
		},
		{
			name: "resolve_multiple_consecutive_slashes",
			path: tmpDir + "///real//target",
			check: func(t *testing.T, got string) {
				want := targetDir
				if got != want {
					t.Fatalf("resolve(%q) = %q; want %q", tmpDir+"///real//target", got, want)
				}
			},
		},
		{
			name: "resolve_deeply_nested_nonexistent_child",
			path: filepath.Join(targetDir, "nonexistent", "deep", "file.txt"),
			check: func(t *testing.T, got string) {
				want := filepath.Join(targetDir, "nonexistent", "deep", "file.txt")
				if got != want {
					t.Fatalf("resolve = %q; want %q", got, want)
				}
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolve(tc.path)
			if err != nil {
				t.Fatalf("unexpected resolve error for %q: %v", tc.path, err)
			}
			tc.check(t, got)
		})
	}
}
