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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Outcome says what Existing determined about a path, which the returned path cannot say
// on its own: a symlink-free path resolves to itself, and so does one the walk gave up on.
type Outcome int

const (
	// OK means the returned path is where a write through the caller's path lands.
	OK Outcome = iota
	// Loop means the symlink budget ran out before the walk reached an answer, so the
	// returned path is the caller's own. The kernel answers ELOOP on such a path.
	Loop
	// Unreadable means a component could not be read - any readlink errno that is not
	// EINVAL, ENOENT or ENOTDIR, so EACCES on an ancestor, or EIO or ESTALE from a network
	// mount - and the returned path is the caller's own. Whether that component is a
	// symlink is exactly what stayed unknown.
	Unreadable
)

func (o Outcome) String() string {
	switch o {
	case OK:
		return "ok"
	case Loop:
		return "loop"
	case Unreadable:
		return "unreadable"
	}
	return "unknown"
}

// MaxDepth bounds symlink following, matching the kernel's ELOOP limit, so a
// self-referential or cyclic symlink cannot spin forever.
const MaxDepth = 40

// Existing resolves path where it exists via the kernel (EvalSymlinks, which is
// accurate through parent symlinks, "..", and chains). Where a component does not
// exist - including a *dangling* leaf symlink pointing into a not-yet-populated store -
// it walks the components against a fully-resolved prefix, following each symlink
// before any later "..", so the result is the target a write through the path would
// reach if the kernel accepted the path at all (not the unmountable symlink, and not the
// wrong sibling filepath.Join's lexical ".." cleaning would produce). A path that walks
// ".." out of a non-directory still resolves here while the kernel refuses it with
// ENOTDIR, so a caller shielding on the result shields a path nothing can be written
// through - the safe direction, and the reason this does not re-check each component.
//
// A component this cannot read at all is returned unresolved for the same reason a loop
// is: whether it is a symlink is exactly what could not be determined, and guessing it is
// not one would put a symlink into a prefix a later ".." is popped off lexically.
//
// "Unresolved" means the caller's own path, symlink components and all. The second return
// says WHICH of the three that path is - OK, Loop or Unreadable - because the path alone
// cannot: a symlink-free path resolves to itself, so identity is also the answer for a
// budget that ran out and for a component that could not be read. A caller acting on the
// path alone is acting on an answer it cannot tell apart from success, which is the whole
// reason the signal exists.
//
// The signal is what a caller fails closed ON; nothing in this package makes the PATH safe
// to bind. Where a caller ignores the signal, the property it still has is the consumer
// meeting the same barrier the resolver met: for EACCES, bwrap's --ro-bind-try tolerates
// only a missing source (ENOENT), so it aborts the run at the path the walk could not
// read. bwrap is what carries that - a Landlock stat failure on the same path is
// warn-and-proceed under the bwrap tier, and fatal only on the degraded tier, where
// RestrictDegraded is the enforcement rather than a backstop.
//
// That symmetry is not available for a transient errno. The branch below catches EIO and
// ESTALE from a network mount alongside EACCES (internal/landlock/landlock_linux.go
// reasons about the same set), and a component unreadable at resolve time but readable at
// bind time leaves a consumer that followed the returned path following a symlink - check
// time and use time disagree. Unreadable is the only thing that closes that: the consumer
// has to refuse rather than bind, since the barrier it would have met is gone. EACCES is
// the arm's only locally constructible errno; EIO and ESTALE reach it by the same branch,
// so the signal covers them by construction rather than by test.
//
// A path whose symlinks loop is Loop once the budget runs out, with the caller's own path
// alongside it. The budget matches the kernel's, so a path this reports Loop for is one
// the kernel answers ELOOP on - which is why a caller needing that fact asks here rather
// than stat-ing the result.
//
// A relative path is made absolute against the working directory first, the same way the
// backend does it before binding a grant. The walk below starts from "/", so taking a
// relative path as given would silently re-root it - "foo/bar" answering for /foo/bar,
// and "" for "/" - and the gate would then judge a different path than the run binds,
// which is the one divergence this package exists to prevent. A working directory that
// cannot be read is Unreadable for the same reason any other unreadable component is: the
// path could not be placed, so nothing about it was determined.
func Existing(path string) (string, Outcome) {
	abs := path
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return path, Unreadable
		}
		// Joined raw rather than through filepath.Join, so a ".." in path is walked
		// against resolved components below instead of being cleaned away lexically.
		abs = filepath.Clean(wd) + "/" + path
	}
	return existing(abs, abs, 0)
}

// existing carries the caller's own path alongside the one being walked, because the
// budget runs out mid-chain: by then abs is a path this function rebuilt out of a link
// target, which is neither what the caller asked about nor anywhere a write through it
// lands. Handing that back is a shield bound on an arbitrary interior hop, so the
// cutoff returns the input instead - the only path the caller can fail closed on.
func existing(input, abs string, depth int) (string, Outcome) {
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real, OK
	}
	if depth >= MaxDepth {
		return input, Loop
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
			// EINVAL is a real directory or file, ENOENT a component that does not exist
			// yet, and ENOTDIR one behind a non-directory - none of them a symlink, so
			// taking the component as is keeps resolved symlink-free and a later ".." on
			// it lexically safe. Any other errno is a component this could not READ, which
			// says nothing about whether it is a link: continuing would put a symlink into
			// resolved and pop a later ".." off it, landing somewhere the kernel would
			// not. Handing back the caller's own path is the cutoff the depth budget
			// already uses - a shield bound on it fails closed.
			if !errors.Is(err, syscall.EINVAL) && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
				return input, Unreadable
			}
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
	return resolved, OK
}
