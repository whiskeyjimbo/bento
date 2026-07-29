// Package pathresolve resolves a host path the way a write through it would actually
// land, including through components that do not exist yet.
//
// It exists so the profiler and the Linux backend cannot answer that question
// differently. They both have to: the backend to decide what a grant binds, the
// profiler to decide whether a proposed grant lands somewhere it must not propose. A
// second implementation on either side is a divergence in one of two directions - the
// profiler proposes a grant the backend then binds somewhere else, or it withholds one
// the backend would have bound honestly - and the first of those is a symlink escape.
package pathresolve

import (
	"os"
	"path/filepath"
	"strings"
)

// MaxDepth bounds symlink following, matching the kernel's ELOOP limit, so a
// self-referential or cyclic symlink cannot spin forever.
const MaxDepth = 40

// Existing resolves abs where it exists via the kernel (EvalSymlinks, which is
// accurate through parent symlinks, "..", and chains). Where a component does not
// exist - including a *dangling* leaf symlink pointing into a not-yet-populated store -
// it walks the components against a fully-resolved prefix, following each symlink
// before any later "..", so the result is the target a write through the path would
// actually reach (not the unmountable symlink, and not the wrong sibling
// filepath.Join's lexical ".." cleaning would produce).
//
// A path whose symlinks loop is returned unresolved once the budget runs out: a caller
// that shields on the result then fails closed, and one that judges a proposal is
// judging a path the backend refuses anyway.
func Existing(abs string) string { return existing(abs, abs, 0) }

// existing carries the caller's own path alongside the one being walked, because the
// budget runs out mid-chain: by then abs is a path this function rebuilt out of a link
// target, which is neither what the caller asked about nor anywhere a write through it
// lands. Handing that back is a shield bound on an arbitrary interior hop, so the
// cutoff returns the input instead - the only path the caller can fail closed on.
func existing(input, abs string, depth int) string {
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	if depth >= MaxDepth {
		return input
	}

	resolved := "/"
	parts := strings.Split(strings.Trim(abs, "/"), "/")
	for i, c := range parts {
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, c)
		target, err := os.Readlink(next)
		if err != nil {
			// A real directory/file, or a not-yet-existing component: take it as is.
			// Since resolved is already symlink-free, a later ".." on it is safe.
			resolved = next
			continue
		}
		// A symlink: rebuild the path as its target followed by the not-yet-walked
		// remainder - raw, not lexically joined, so a ".." *inside* the target still
		// follows its own leading symlink - and resolve that from the top.
		rebuilt := target
		if !filepath.IsAbs(target) {
			rebuilt = resolved + "/" + target
		}
		if rem := parts[i+1:]; len(rem) > 0 {
			rebuilt += "/" + strings.Join(rem, "/")
		}
		return existing(input, rebuilt, depth+1)
	}
	return resolved
}
