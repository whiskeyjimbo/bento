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
	// chain is every other directory that can decide which file the manifest's name
	// reaches, nearest first: the ones above dir, since renaming one of them aside
	// substitutes the manifest as surely as replacing the file, and - when the name
	// goes through a symlink anywhere along it - the unresolved path's own directories,
	// since whoever can replace a link repoints it at a file of their choosing.
	chain []fileFacts
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
// parse; the directory half is taken at the symlink-resolved location, which is where
// approve writes, and the chain covers everything else that leads there.
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
	// Absolute, so the walks below terminate at / rather than at "." - a manifest named
	// relatively leads through the same directories as one named in full.
	given, err := filepath.Abs(path)
	if err != nil {
		return manifestTrust{}, err
	}
	target, err := filepath.EvalSymlinks(given)
	if err != nil {
		return manifestTrust{}, err
	}
	dirPath := filepath.Dir(target)
	dir, err := statFacts(dirPath)
	if err != nil {
		return manifestTrust{}, err
	}
	trust := manifestTrust{file: file, dir: dir}

	above, err := dirsUpward(filepath.Dir(dirPath))
	if err != nil {
		return manifestTrust{}, err
	}
	// skip dirPath: for a manifest sitting directly in /, walking up from it starts at
	// / again, and reporting it as both the holding directory and an ancestor is noise.
	trust.chain = appendUnseen(nil, above, dirPath)

	// Both paths are cleaned and absolute, so they differ only when a symlink was
	// resolved - at the manifest itself or at any component along the way. Every
	// directory of the name as given then decides which file that name reaches, so all
	// of them are inspected, not just the one holding a final link.
	if given != target {
		linked, err := dirsUpward(filepath.Dir(given))
		if err != nil {
			return manifestTrust{}, err
		}
		trust.chain = appendUnseen(trust.chain, linked, dirPath)
	}
	return trust, nil
}

// dirsUpward returns facts for dir and every directory above it, nearest first.
func dirsUpward(dir string) ([]fileFacts, error) {
	var out []fileFacts
	for p := dir; ; p = filepath.Dir(p) {
		facts, err := statFacts(p)
		if err != nil {
			return nil, err
		}
		out = append(out, facts)
		if p == filepath.Dir(p) {
			return out, nil
		}
	}
}

// appendUnseen adds the directories of add that are not already in chain and are not
// skip, so a path and its resolved target - which share every level above the point
// they diverge - do not report the same directory twice.
func appendUnseen(chain, add []fileFacts, skip string) []fileFacts {
	seen := map[string]bool{skip: true}
	for _, d := range chain {
		seen[d.path] = true
	}
	for _, d := range add {
		if !seen[d.path] {
			chain = append(chain, d)
		}
	}
	return chain
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
	return append(out, t.locationFlaws(euid)...)
}

// locationFlaws is the half of flaws that is about where the manifest lives rather than
// the manifest itself. approve reports these on their own: the file's own mode is
// something its rewrite corrects and announces, so warning about it here as well would
// describe a state approve is in the middle of leaving.
func (t manifestTrust) locationFlaws(euid uint32) []trustFlaw {
	out := dirFlaws(t.dir, "the directory holding it", euid)
	// Only the nearest fatal link in the chain is reported. A group-writable directory
	// up the tree is as ordinary as a group-writable one holding the manifest, and
	// naming every level to / would bury the one that actually lets someone else choose
	// which manifest is read.
	for _, d := range t.chain {
		for _, f := range dirFlaws(d, "a directory on the path to it", euid) {
			if f.fatal {
				return append(out, f)
			}
		}
	}
	return out
}

// dirFlaws reports what a directory on the way to the manifest lets someone other than
// euid do with it. role names the directory in the message.
func dirFlaws(d fileFacts, role string, euid uint32) []trustFlaw {
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
