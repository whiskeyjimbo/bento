package gate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	real, links, err := walkName(path)
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
	for _, p := range links {
		if writable(p) {
			problems = append(problems, fmt.Sprintf("manifest %q is named through the symlink %q, which a write grant can replace; run it by its real path %q", path, p, real))
		}
	}
	// Another hard link can sit under a write grant's mount wherever the manifest itself
	// lives, and nothing finds the other names of an inode, so any write grant is enough.
	n, counted := linkCount(real)
	if counted && n > 1 && len(resolved.Write) > 0 {
		problems = append(problems, fmt.Sprintf("manifest %q has %d hard links, and the run has write grants, so another name under one could rewrite it past the read-only bind", path, n))
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
	if !counted {
		problems = append(problems, fmt.Sprintf("manifest %q: this host cannot say whether it has other hard links, which a write grant could use to rewrite it", path))
	}
	return problems
}

// walkName resolves name the way the kernel does when it opens it: component by
// component, a ".." stepping out of wherever the walk physically is rather than cancelling
// the name before it, which filepath.Abs and filepath.Clean would do. It returns the real
// path and every symlink the walk followed, each at its real location, including symlinks
// met inside another symlink's target.
func walkName(name string) (string, []string, error) {
	cur := "/"
	if !filepath.IsAbs(name) {
		wd, err := os.Getwd()
		if err != nil {
			return "", nil, err
		}
		if cur, err = filepath.EvalSymlinks(wd); err != nil {
			return "", nil, err
		}
	}
	var links []string
	todo := strings.Split(name, "/")
	for hops := 0; len(todo) > 0; {
		c := todo[0]
		todo = todo[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		p := filepath.Join(cur, c)
		fi, err := os.Lstat(p)
		if err != nil {
			return "", nil, err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			cur = p
			continue
		}
		// The kernel's own limit on symlinks followed in one lookup.
		if hops++; hops > 40 {
			return "", nil, fmt.Errorf("too many levels of symbolic links")
		}
		links = append(links, p)
		target, err := os.Readlink(p)
		if err != nil {
			return "", nil, err
		}
		if filepath.IsAbs(target) {
			cur = "/"
		}
		todo = append(strings.Split(target, "/"), todo...)
	}
	return cur, links, nil
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
