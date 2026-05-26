package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateWritePaths(t *testing.T) {
	dir := t.TempDir()

	// Ground truth: regular dir is fine.
	regular := filepath.Join(dir, "regular")
	if err := os.Mkdir(regular, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Run("regular dir accepted", func(t *testing.T) {
		if err := validateWritePaths([]string{regular}); err != nil {
			t.Errorf("regular dir should pass, got %v", err)
		}
	})

	// Symlink AT the write target.
	link := filepath.Join(dir, "evil-link")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	t.Run("symlink at write path rejected", func(t *testing.T) {
		err := validateWritePaths([]string{link})
		if err == nil {
			t.Fatal("expected error for symlink at write path")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error should mention 'symlink', got: %v", err)
		}
	})

	// Symlink on the parent chain.
	parentLink := filepath.Join(dir, "parent-link")
	target := filepath.Join(dir, "real-parent")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, parentLink); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(parentLink, "child")
	if err := os.Mkdir(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Run("symlink on parent chain rejected", func(t *testing.T) {
		err := validateWritePaths([]string{deep})
		if err == nil {
			t.Fatal("expected error for symlink on parent chain")
		}
		if !strings.Contains(err.Error(), parentLink) {
			t.Errorf("error should name the symlink path, got: %v", err)
		}
	})

	// Non-existent path is fine — nothing to exploit.
	t.Run("non-existent path accepted", func(t *testing.T) {
		ghost := filepath.Join(dir, "does-not-exist", "deeper")
		if err := validateWritePaths([]string{ghost}); err != nil {
			t.Errorf("non-existent path should pass, got %v", err)
		}
	})

	// Multiple paths: first violation reported.
	t.Run("multiple paths: violation reported", func(t *testing.T) {
		err := validateWritePaths([]string{regular, link})
		if err == nil {
			t.Fatal("expected error when any path is a symlink")
		}
	})

	// Empty input is fine.
	t.Run("empty input accepted", func(t *testing.T) {
		if err := validateWritePaths(nil); err != nil {
			t.Errorf("nil writes should pass, got %v", err)
		}
	})
}
