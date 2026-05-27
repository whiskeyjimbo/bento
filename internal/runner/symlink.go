package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateWritePaths rejects manifests where any declared write path contains
// (or is) a symlink — symlinks in writeable trees let an attacker swap a path
// for a credential file. Callers with intentional symlinks should pre-resolve
// with filepath.EvalSymlinks. Non-existent components are accepted.
func validateWritePaths(writes []string) error {
	for _, w := range writes {
		abs, err := filepath.Abs(w)
		if err != nil {
			return fmt.Errorf("write path %q: %w", w, err)
		}
		if err := scanForSymlink(abs); err != nil {
			return fmt.Errorf("write path %q rejected: %w", w, err)
		}
	}
	return nil
}

// scanForSymlink walks every existing component of p and errors if any is a symlink.
func scanForSymlink(p string) error {
	parts := strings.Split(p, string(filepath.Separator))
	current := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = current + string(filepath.Separator) + part
		info, err := os.Lstat(current)
		if err != nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, _ := os.Readlink(current)
			return fmt.Errorf(
				"symlink at %q (→ %q) — refuse to bind-mount writeable; resolve and re-declare the real path",
				current, target,
			)
		}
	}
	return nil
}
