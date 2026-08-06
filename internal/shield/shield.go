// Package shield answers one question - does this grant land inside a shielded path -
// for every caller that has to know.
//
// Three of them do, and they are required to agree: the Linux backend refusing a grant
// at run time, the validate gate predicting that refusal before CI approves a manifest,
// and the profiler's clamp deciding what to put in a draft. They answered it separately
// and diverged, which is what this package exists to end. internal/shieldcorpus holds the
// grants all three are tested against.
//
// It is untagged on purpose. The backend is //go:build linux and the other two callers
// are not, so a shared answer cannot live there - that constraint is why the duplicate
// implementations existed at all, rather than carelessness. What the backend has and the
// others do not is a sandbox view of the host, so the host access this needs is taken as
// a seam (FS) in this package's own terms: three functions, named for what the shield
// logic asks, not for what any caller's filesystem type provides.
//
// The rule DATA stays in internal/denylist, which is already untagged and already where
// the audit tool and the credential hunt read it as data. This layers assembly and
// verdict on top of it.
package shield

import (
	"os"

	"github.com/whiskeyjimbo/bento/internal/pathresolve"
)

// FS is the host as the shield logic needs to see it. Narrow by construction: a seam wide
// enough to mirror a caller's filesystem type would become that caller's API in this
// package's signatures, and the backend's sandbox is the one type that must not leak here.
//
// Resolve returns a path with its symlinks followed, or the path unchanged where it does
// not resolve. It is the operation the whole package turns on - shields are compared
// against grants at the place a write through them would land, never at the name - so
// two callers answering it differently is the divergence this package was built to
// prevent. Use Host unless there is a reason not to.
type FS struct {
	// IsDir reports whether a path is an existing directory. A shield rule covers an
	// interior only where it has one.
	IsDir func(string) bool
	// Resolve follows a path's symlinks, including through components that do not exist
	// yet, and returns the path unchanged where it cannot.
	Resolve func(string) string
	// SameFile reports whether two paths name the same host file. It answers one
	// question the other seams cannot: whether the directory holding a shield folds
	// case, which decides whether a byte-exact bind is enough to contain it. Neither
	// path needs to exist; a path that does not is the same file as nothing.
	SameFile func(a, b string) bool
	// ListDir returns a directory's immediate children, split into real subdirectories
	// the scan may descend into and symlinked entries it may not, plus whether it was
	// read at all. ok false means the directory could not be enumerated, which is not the
	// same as empty: a store nothing can see into exposes nothing, while an empty one
	// might still be linked out tomorrow.
	ListDir func(string) (names, links []string, ok bool)
}

// Host is the FS every caller outside the backend passes: the real filesystem, resolved
// the way a write through a path actually lands. The backend passes its sandbox's own
// seams instead, which are this same behavior with the fakes its tests inject.
func Host() FS {
	return FS{
		IsDir:    hostIsDir,
		Resolve:  pathresolve.Existing,
		ListDir:  hostListDir,
		SameFile: hostSameFile,
	}
}

// hostSameFile compares identity without following a final symlink: the shield binds at
// the name, so a link and its target are two paths a grant reaches separately, not one.
func hostSameFile(a, b string) bool {
	fa, err := os.Lstat(a)
	if err != nil {
		return false
	}
	fb, err := os.Lstat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

func hostIsDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func hostListDir(path string) (names, links []string, ok bool) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, nil, false
	}
	for _, e := range entries {
		switch {
		case e.IsDir(): // DirEntry.IsDir is false for a symlink, even one to a directory
			names = append(names, e.Name())
		case e.Type()&os.ModeSymlink != 0:
			links = append(links, e.Name())
		}
	}
	return names, links, true
}
