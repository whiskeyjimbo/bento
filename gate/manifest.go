package gate

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/whiskeyjimbo/bento/policy"
)

// ManifestProblems reports the ways a write grant reaches the manifest at path around the
// read-only bind a run puts over it (enforce.Options.ReadOnlyPaths). The bind holds only
// its own name: the kernel refuses to rename or unlink a mount point, but a directory
// above one moves with the mount inside it, and another name for the same inode is not
// under any mount at all. A run able to replace its manifest could widen it and re-stamp
// it - the stamp is an unkeyed hash - and the next run would execute a policy nobody read.
//
// Nothing is reported when no write grant reaches the manifest, or when every write grant
// that does is rooted at the manifest's own directory: that directory is then the grant's
// mount point, so it cannot be renamed either. A read grant rooted there does not help -
// the sandbox does not bind a read grant separately inside a write grant covering it.
//
// Exported for the reason WorkdirProblems is: run refuses these, so validate and approve
// have to report and refuse the same set.
func ManifestProblems(path string, resolved *policy.Policy) []string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return []string{fmt.Sprintf("manifest %q: %v", path, err)}
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return []string{fmt.Sprintf("manifest %q: %v", path, err)}
	}
	writable := func(p string) bool {
		return len(writeGrantsCovering(resolved, p)) > 0
	}
	var problems []string
	// Every symlink on the way to the manifest, the leaf and every directory above it, is
	// an entry a run could swing to a manifest of its own for the next run by this name,
	// wherever it lives. The bind protects only the file the links lead to today.
	for p := abs; p != filepath.Dir(p); p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		at := p
		if dir, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			at = filepath.Join(dir, filepath.Base(p))
		}
		if writable(at) {
			problems = append(problems, fmt.Sprintf("manifest %q is named through the symlink %q, which a write grant can replace; run it by its real path %q", path, p, real))
		}
	}
	if !writable(real) {
		return problems
	}
	dir := filepath.Dir(real)
	for _, w := range writeGrantsCovering(resolved, real) {
		if w != dir {
			problems = append(problems, fmt.Sprintf("manifest %q sits under the write grant %q, which starts above its directory, so the run could have that directory renamed and a new manifest put in its place; keep the manifest at the top of its write grant or outside the write grants", path, w))
		}
	}
	if n, ok := linkCount(real); !ok {
		problems = append(problems, fmt.Sprintf("manifest %q: this host cannot say whether it has other hard links, which a write grant could use to rewrite it", path))
	} else if n > 1 {
		problems = append(problems, fmt.Sprintf("manifest %q has %d hard links, and a write grant reaches it, so another name could rewrite it past the read-only bind", path, n))
	}
	return problems
}

func writeGrantsCovering(resolved *policy.Policy, p string) []string {
	var out []string
	for _, w := range resolved.Write {
		if rw := resolvedGrant(w); policy.CoversResolved(rw, p) {
			out = append(out, rw)
		}
	}
	return out
}

// resolvedGrant is a grant as the sandbox binds it: symlinks resolved where the path
// exists, and as spelled where it does not yet.
func resolvedGrant(g string) string {
	if r, err := filepath.EvalSymlinks(g); err == nil {
		return r
	}
	return filepath.Clean(g)
}
