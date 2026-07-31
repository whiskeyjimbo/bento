package policy

import (
	"path/filepath"
	"strings"
)

// CoversResolved reports whether a grant of grant reaches path: whether path is
// grant itself, or lies beneath it on a path component boundary. "/a/b" is under
// "/a"; "/ab" is not.
//
// It lives with the domain for the same reason Allows does - it is the meaning of a
// read or write grant, and every consumer must agree on that meaning exactly. Bento
// enforces it internally, a supervising wrapper warns on a deny its own grants would
// cover, and an embedder refuses a grant covering its control store; three answers to
// one security question, which drift the moment they are three implementations.
//
// PRECONDITIONS, which this function does not restate and a caller must meet:
//
//   - both paths are absolute.
//   - both paths are already symlink-resolved.
//
// The second is the one that bites. This is a LEXICAL test: it compares spellings and
// touches no filesystem. Every enforcing coverage check inside bento runs on resolved
// paths (grants are resolved before they are bound, so a symlinked grant binds its real
// target and the deny-list, which also works on real paths, still sees it). Handed an
// unresolved path, this returns a security-flavoured answer that is wrong exactly where
// it matters: "/home/u/link" does not lexically cover "/home/u/store" even when the
// link points there, so a caller checking whether a grant reaches its store would be
// told no while the sandbox binds it. Resolve first - bento does not do it for you here,
// because a predicate that touched the filesystem could not live in this package.
// Both sides are cleaned first, so the containment test below can be a plain byte
// comparison. Cleaning unconditionally is deliberate: an earlier version tried to skip
// it when no ".." was present, which got "/home/u//.ssh//id_rsa" wrong against a
// "/home/u/.ssh" grant - an empty segment INSIDE the grant's span shifts every offset
// after it, so a prefix comparison misses a path the grant really does cover. Deciding
// cheaply whether cleaning is needed is most of the work of cleaning. filepath.Clean
// does not allocate when its input is already clean, which is the ordinary case.
func CoversResolved(grant, path string) bool {
	const sep = string(filepath.Separator)
	grant, path = filepath.Clean(grant), filepath.Clean(path)
	if grant == path {
		return true
	}
	// The root covers every absolute path. It is its own case because the test below
	// wants a separator BETWEEN grant and the rest, and the root already ends in one.
	// A relative path is not under it - nor under anything else here - which is the
	// safe answer for a caller that skipped the preconditions.
	if grant == sep {
		return strings.HasPrefix(path, sep)
	}
	// Spelled as an index comparison rather than HasPrefix(path, grant+sep): the
	// concatenation allocates, and this runs once per rule for every file of a
	// whole-home walk.
	return len(path) > len(grant) && path[len(grant)] == filepath.Separator && path[:len(grant)] == grant
}
