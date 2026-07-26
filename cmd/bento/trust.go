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

func statFacts(path string) (fileFacts, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileFacts{}, err
	}
	return factsOf(path, fi)
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

// manifestTrust is a manifest's own permissions together with those of every directory
// that leads to it. The directories matter on their own: write and search in one is
// enough to rename something else into place, whatever the manifest's own mode said.
type manifestTrust struct {
	file fileFacts
	dir  fileFacts
	// link is the directory holding the symlink, when the manifest is reached through
	// one. Whoever can replace the link chooses which file every command reads.
	link *fileFacts
	// ancestors are the directories above dir, nearest first. Renaming one of them
	// aside substitutes the manifest just as surely as replacing the file.
	ancestors []fileFacts
}

// trustFlaw is one way someone other than this user could change the manifest. fatal
// marks the ones approve refuses to stamp over: not everything reported is, since a
// mode on the manifest itself is corrected by the rewrite, and a group-writable
// directory is what a umask of 002 leaves on every directory it creates.
type trustFlaw struct {
	reason string
	fatal  bool
}

// inspectManifest reads the trust facts for an already-open manifest. The file half
// comes from the open handle so nothing can be swapped in between the check and the
// parse; the directory halves are taken at the symlink-resolved location, which is
// where approve writes, plus the link's own directory when there is one.
//
// The reasoning is mode bits only. A POSIX ACL granting a named user write appears in
// the group-class bits and is indistinguishable here, so a clean report means "nothing
// in the mode says otherwise", not "verified private".
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
	// Absolute, so the ancestor walk below terminates at / rather than at "." - a
	// manifest named relatively has the same ancestors as one named in full.
	target, err = filepath.Abs(target)
	if err != nil {
		return manifestTrust{}, err
	}
	dirPath := filepath.Dir(target)
	dir, err := statFacts(dirPath)
	if err != nil {
		return manifestTrust{}, err
	}
	trust := manifestTrust{file: file, dir: dir}

	if li, err := os.Lstat(path); err == nil && li.Mode()&fs.ModeSymlink != 0 {
		linkDir, err := statFacts(filepath.Dir(path))
		if err != nil {
			return manifestTrust{}, err
		}
		trust.link = &linkDir
	}

	for p := filepath.Dir(dirPath); ; p = filepath.Dir(p) {
		a, err := statFacts(p)
		if err != nil {
			return manifestTrust{}, err
		}
		trust.ancestors = append(trust.ancestors, a)
		if p == filepath.Dir(p) {
			break
		}
	}
	return trust, nil
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
			reason: fmt.Sprintf("%s is owned by uid %d", t.file.path, t.file.uid),
			fatal:  true,
		})
	}
	out = append(out, locationFlaws(t.dir, "the directory holding it", euid)...)
	if t.link != nil {
		out = append(out, locationFlaws(*t.link, "the directory holding the symlink to it", euid)...)
	}
	// Only the nearest fatal ancestor is reported. A group-writable one is as ordinary
	// as a group-writable directory, and naming every level up to / would bury the one
	// that actually lets someone else choose which manifest is read.
	for _, a := range t.ancestors {
		for _, f := range locationFlaws(a, "an ancestor of its directory", euid) {
			if f.fatal {
				return append(out, f)
			}
		}
	}
	return out
}

// locationFlaws reports what a directory on the way to the manifest lets someone other
// than euid do with it. role names the directory in the message.
func locationFlaws(d fileFacts, role string, euid uint32) []trustFlaw {
	var out []trustFlaw
	if shared := d.sharedWrite(); shared != 0 {
		// Only world-writable is fatal. Group write is what a umask of 002 leaves on
		// every directory it creates, and on a distro with per-user groups the group
		// holds nobody else - refusing it would fail approve on ordinary machines.
		out = append(out, trustFlaw{
			reason: fmt.Sprintf("%s, %s, is %s-writable (%#o), so anyone there can replace the manifest", d.path, role, writerClass(shared), d.mode.Perm()),
			fatal:  shared&0o002 != 0,
		})
	}
	if d.foreignOwner(euid) {
		out = append(out, trustFlaw{
			reason: fmt.Sprintf("%s, %s, is owned by uid %d, who can replace the manifest", d.path, role, d.uid),
			fatal:  true,
		})
	}
	return out
}

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

// warnUntrusted reports every flaw as advisory. The read commands do not refuse on one:
// a permissive umask or a shared checkout is ordinary, and failing run, validate and
// profile over it would break working setups to describe a risk the user may already
// accept. approve, where a human is establishing the trust, does refuse.
func warnUntrusted(w io.Writer, flaws []trustFlaw) {
	for _, f := range flaws {
		fmt.Fprintf(w, "[bento] %s - its approval stamp attests only what whoever can write it leaves there.\n", f.reason)
	}
}
