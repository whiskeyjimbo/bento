package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// fileFacts is the ownership and permissions of one path, the two things that decide
// who besides its owner can change what is there.
type fileFacts struct {
	path string
	mode fs.FileMode
	uid  uint32
}

func factsOf(path string, fi fs.FileInfo) (fileFacts, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileFacts{}, fmt.Errorf("cannot read ownership of %s", path)
	}
	return fileFacts{path: path, mode: fi.Mode(), uid: st.Uid}, nil
}

// sharedWrite is the write bits granted to someone other than the owner. On a sticky
// directory (/tmp) others may add their own entries but cannot rename or unlink ours,
// which is the only thing that would let them replace a manifest, so it grants none.
func (f fileFacts) sharedWrite() fs.FileMode {
	if f.mode.IsDir() && f.mode&fs.ModeSticky != 0 {
		return 0
	}
	return f.mode.Perm() & 0o022
}

// foreignOwner reports ownership by a user who is neither us nor root. Root is not
// foreign: it can write anywhere regardless, so treating it as a finding would flag
// every system-installed manifest without describing a reachable widening.
func (f fileFacts) foreignOwner(euid uint32) bool {
	return f.uid != euid && f.uid != 0
}

// manifestTrust is a manifest's own permissions together with those of the directory it
// sits in. The directory matters on its own: write and search there is enough to rename
// a new manifest over the old one whatever the old one's mode said.
type manifestTrust struct {
	file fileFacts
	dir  fileFacts
}

// trustFlaw is one way someone other than this user could change the manifest. fatal
// marks the ones approve refuses to stamp over: not everything reported is, since a
// mode on the manifest itself is corrected by the rewrite, and a group-writable
// directory is what a umask of 002 produces for every home on the system.
type trustFlaw struct {
	reason string
	fatal  bool
}

// inspectManifest reads the trust facts for an already-open manifest. The file half
// comes from the open handle so nothing can be swapped in between the check and the
// parse; the directory half is taken at the symlink-resolved location, which is where
// approve writes.
func inspectManifest(f *os.File, path string) (manifestTrust, error) {
	fi, err := f.Stat()
	if err != nil {
		return manifestTrust{}, err
	}
	file, err := factsOf(path, fi)
	if err != nil {
		return manifestTrust{}, err
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return manifestTrust{}, err
	}
	dirPath := filepath.Dir(target)
	di, err := os.Stat(dirPath)
	if err != nil {
		return manifestTrust{}, err
	}
	dir, err := factsOf(dirPath, di)
	if err != nil {
		return manifestTrust{}, err
	}
	return manifestTrust{file: file, dir: dir}, nil
}

// flaws lists what euid cannot vouch for about the manifest's location, most specific
// first. An approval stamp is unkeyed drift detection: it attests that the permissions
// match what was stamped, which says nothing once someone else can restamp them.
func (t manifestTrust) flaws(euid uint32) []trustFlaw {
	var out []trustFlaw
	if t.file.sharedWrite() != 0 {
		out = append(out, trustFlaw{
			reason: fmt.Sprintf("%s is group/world-writable (%#o)", t.file.path, t.file.mode.Perm()),
		})
	}
	if t.file.foreignOwner(euid) {
		out = append(out, trustFlaw{
			reason: fmt.Sprintf("%s is owned by uid %d, not you", t.file.path, t.file.uid),
			fatal:  true,
		})
	}
	if shared := t.dir.sharedWrite(); shared != 0 {
		// Only a world-writable directory is fatal. Group write is what a umask of 002
		// leaves on every directory it creates, and on a distro with per-user groups the
		// group holds nobody else - refusing it would fail approve on ordinary machines.
		out = append(out, trustFlaw{
			reason: fmt.Sprintf("%s, the directory holding it, is %s-writable (%#o), so anyone there can replace the manifest", t.dir.path, writerClass(shared), t.dir.mode.Perm()),
			fatal:  shared&0o002 != 0,
		})
	}
	if t.dir.foreignOwner(euid) {
		out = append(out, trustFlaw{
			reason: fmt.Sprintf("%s, the directory holding it, is owned by uid %d, who can replace the manifest", t.dir.path, t.dir.uid),
			fatal:  true,
		})
	}
	return out
}

// warnUntrusted reports every flaw as advisory. The read commands do not refuse on one:
// a permissive umask or a shared checkout is ordinary, and failing run, validate and
// profile over it would break working setups to describe a risk the user may already
// accept. approve, where a human is establishing the trust, does refuse.
func writerClass(shared fs.FileMode) string {
	switch {
	case shared&0o002 != 0 && shared&0o020 != 0:
		return "group/world"
	case shared&0o002 != 0:
		return "world"
	default:
		return "group"
	}
}

func warnUntrusted(w io.Writer, flaws []trustFlaw) {
	for _, f := range flaws {
		fmt.Fprintf(w, "[bento] %s - its approval stamp attests only what whoever can write it leaves there.\n", f.reason)
	}
}
