package gate

import (
	"fmt"
	"path/filepath"

	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/trust"
)

// ManifestProblems reports the ways a write grant reaches the manifest m around the
// read-only bind a run puts over it (enforce.Options.ReadOnlyPaths). The bind holds only
// its own name: the kernel refuses to rename or unlink a mount point, but a directory
// above one moves with the mount inside it, and another name for the same inode is not
// under any mount at all. A run able to replace its manifest could widen it and re-stamp
// it - the stamp is an unkeyed hash - and the next run would execute a policy nobody read.
//
// m is judged rather than name, so the verdict is about the file that was opened and
// loaded, as trust.Inspect located it, and the same RealPath the run binds read-only.
// Resolving the name again here would judge whatever it leads to by then.
//
// Nothing is reported when no write grant reaches the manifest, or when every write grant
// that does is rooted at the manifest's own directory: that directory is then the grant's
// mount point, so it cannot be renamed either. A read grant rooted there does not help -
// the sandbox does not bind a read grant separately inside a write grant covering it.
//
// Exported for the reason WorkdirProblems is: run refuses these, so validate and approve
// have to report and refuse the same set.
func ManifestProblems(name string, m trust.Manifest, resolved *policy.Policy) []string {
	real := m.RealPath
	writable := func(p string) bool {
		return len(writeGrantsCovering(resolved, p)) > 0
	}
	var problems []string
	// Every symlink on the way to the manifest, the leaf and every directory above it, is
	// an entry a run could swing to a manifest of its own for the next run by this name,
	// wherever it lives. The bind protects only the file the links lead to today.
	for _, p := range m.Symlinks() {
		if writable(p) {
			problems = append(problems, fmt.Sprintf("manifest %q is named through the symlink %q, which a write grant can replace; run it by its real path %q", name, p, real))
		}
	}
	// Another hard link can sit under a write grant's mount wherever the manifest itself
	// lives, and nothing finds the other names of an inode, so any write grant is enough.
	if n := m.HardLinks(); n > 1 && len(resolved.Write) > 0 {
		problems = append(problems, fmt.Sprintf("manifest %q has %d hard links, and the run has write grants, so another name under one could rewrite it past the read-only bind", name, n))
	}
	if !writable(real) {
		return problems
	}
	dir := filepath.Dir(real)
	for _, w := range writeGrantsCovering(resolved, real) {
		if w != dir {
			problems = append(problems, fmt.Sprintf("manifest %q sits under the write grant %q, which starts above its directory, so the run could have that directory renamed and a new manifest put in its place; keep the manifest at the top of its write grant or outside the write grants", name, w))
		}
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
