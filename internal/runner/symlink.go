package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateWritePaths refuses manifests where any declared write path
// contains (or is) a symlink. Symlinks inside writeable trees are an
// attack vector: an attacker who can influence the workspace can swap
// /tmp/out for a symlink to ~/.ssh and have the sandboxed script
// happily write the credential file.
//
// Conservative policy: any symlink anywhere on the path is rejected.
// Users can pass the resolved real path via filepath.EvalSymlinks ahead
// of time if they have an intentional symlink in their layout. Easier
// to relax this later than to tighten it.
//
// Non-existent components are fine — bwrap won't bind-mount them, and
// the script can't create paths through symlinks that don't exist yet.
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

// scanForSymlink walks every existing path component of p from root and
// returns an error if any of them is a symlink. The final path is also
// checked (a symlink AT the write path, not just on its parent chain,
// is equally exploitable).
func scanForSymlink(p string) error {
	parts := strings.Split(p, string(filepath.Separator))
	current := ""
	for _, part := range parts {
		if part == "" {
			continue // leading "/" leaves an empty first element
		}
		current = current + string(filepath.Separator) + part
		info, err := os.Lstat(current)
		if err != nil {
			// Component doesn't exist (or can't lstat). Stop walking —
			// non-existent components can't be exploited via symlink
			// replacement because there's no symlink yet to replace.
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
