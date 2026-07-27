package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// fileFacts is the ownership and permissions of one path, the two things that decide
// who besides its owner can change what is there.
type fileFacts struct {
	path string
	mode fs.FileMode
	uid  uint32
	// aclWrite is write granted to a named user or group by a POSIX ACL, which the mode
	// cannot show: such a grant appears in the group-class bits and is indistinguishable
	// there from the group write an ordinary umask leaves. Only statFacts fills it in - the
	// manifest's own ACL is corrected along with its mode by the rewrite, which zeroes the
	// group class and with it the mask every named entry is filtered through.
	aclWrite bool
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
	facts, err := factsOf(path, fi)
	if err != nil {
		return fileFacts{}, err
	}
	facts.aclWrite, err = aclNamedWrite(path)
	if err != nil {
		return fileFacts{}, err
	}
	return facts, nil
}

// POSIX ACL entry tags and permission bits, as the kernel lays them out in
// system.posix_acl_access. See acl(5) and fs/posix_acl.c.
const (
	aclTagUser   = 0x0002 // a named user
	aclTagGroup  = 0x0008 // a named group
	aclTagMask   = 0x0010 // the ceiling every named entry is filtered through
	aclPermWrite = 0x0002
	aclEntrySize = 8
	aclVersion   = 2
)

// aclNamedWrite reports whether a POSIX ACL grants write to a named user or group - that
// is, to somebody the mode bits cannot name. Only named entries count: a directory that
// merely inherited a default ACL carries an access ACL with no named entry in it, and
// treating the ACL's presence as the signal would flag every such directory.
//
// Absence of the attribute, and a filesystem that does not carry it at all, both mean the
// mode is the whole story - which is the common case and not a finding.
func aclNamedWrite(path string) (bool, error) {
	// Sized from the attribute rather than guessed: a long ACL read into a short buffer
	// fails, and answering "no named writer" about an ACL nobody read would be the one
	// wrong answer this can give.
	size, err := unix.Getxattr(path, "system.posix_acl_access", nil)
	switch {
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("cannot read the ACL on %s: %w", path, err)
	}
	buf := make([]byte, size)
	n, err := unix.Getxattr(path, "system.posix_acl_access", buf)
	switch {
	case errors.Is(err, unix.ENODATA):
		return false, nil // set aside between the two reads
	case err != nil:
		return false, fmt.Errorf("cannot read the ACL on %s: %w", path, err)
	}
	acl := buf[:n]
	if len(acl) < 4 || binary.LittleEndian.Uint32(acl) != aclVersion {
		return false, fmt.Errorf("cannot read the ACL on %s: unrecognized format", path)
	}
	entries := acl[4:]
	if len(entries)%aclEntrySize != 0 {
		return false, fmt.Errorf("cannot read the ACL on %s: truncated entry", path)
	}
	// The mask is the ceiling on every named entry, so a named grant it does not include
	// grants nothing. A missing mask means an ACL with no named entries to filter.
	var named, mask uint16
	for i := 0; i < len(entries); i += aclEntrySize {
		tag := binary.LittleEndian.Uint16(entries[i:])
		perm := binary.LittleEndian.Uint16(entries[i+2:])
		switch tag {
		case aclTagUser, aclTagGroup:
			named |= perm
		case aclTagMask:
			mask = perm
		}
	}
	return named&mask&aclPermWrite != 0, nil
}

// sharedWrite is the write bits granted to someone other than the owner.
func (f fileFacts) sharedWrite() fs.FileMode {
	if f.stickyDir() {
		return 0
	}
	return f.mode.Perm() & 0o022
}

// aclSharedWrite is aclWrite once the sticky exemption is applied, so both ways of granting
// write to someone else are read through the same rule about what write there means.
func (f fileFacts) aclSharedWrite() bool {
	return f.aclWrite && !f.stickyDir()
}

// stickyDir marks a directory whose write bits grant less than they say: on a sticky one
// (/tmp) others may add their own entries but cannot rename or unlink ours, and replacing
// the manifest is the only thing that would matter here.
func (f fileFacts) stickyDir() bool {
	return f.mode.IsDir() && f.mode&fs.ModeSticky != 0
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
	// realPath is where the manifest actually lives, as the kernel names the open
	// descriptor: the same resolution dir and chain were judged against, so a caller that
	// rewrites the manifest writes at the location that was inspected rather than
	// resolving the name a second time and racing whoever can repoint it.
	realPath string
	// chain is every other directory that can decide which file the manifest's name
	// reaches: the ones above dir, since renaming one of them aside substitutes the
	// manifest as surely as replacing the file, followed by those leading to a symlink
	// named as the manifest, since whoever can replace a link repoints it at a file of
	// their choosing. Each run is nearest-first, but the second follows the whole of
	// the first rather than being interleaved by distance.
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

// inspectManifest reads the trust facts for an already-open manifest. Both halves come
// from the open handle: the file's from fstat, and its location from the kernel's own
// name for the descriptor. Resolving the path in userspace instead gets this wrong -
// lexically cleaning a `..` that follows a symlink names a directory the file is not in
// - and asking the kernel is also free of any race with the bytes already parsed.
//
// The directories are judged on their mode bits and their access ACL. The manifest's own
// facts come from fstat, which carries no ACL, because the rewrite corrects its mode - and
// with the group class the mask every named ACL entry is filtered through.
func inspectManifest(f *os.File, path string) (manifestTrust, error) {
	fi, err := f.Stat()
	if err != nil {
		return manifestTrust{}, err
	}
	// A manifest read from a pipe or a device has no location to judge: the kernel names
	// the descriptor `pipe:[N]`, whose directory reads back as the process's own working
	// directory, and a verdict about that describes nothing the manifest came from.
	// Approve could not rewrite it either.
	if !fi.Mode().IsRegular() {
		return manifestTrust{}, fmt.Errorf("%s is not a regular file, so there is nothing to vouch for its permissions", path)
	}
	file, err := factsOf(path, fi)
	if err != nil {
		return manifestTrust{}, err
	}
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil {
		return manifestTrust{}, err
	}
	// The kernel's name is not always usable as a path: a manifest unlinked between the
	// open and the readlink reads back as "/w/m.yaml (deleted)", and one replaced in that
	// window names a different inode. Both would send a rewrite somewhere the facts
	// gathered here do not describe, so the name is required to still lead back to the
	// descriptor before anything is concluded from it.
	targetFI, err := os.Stat(target)
	if err != nil {
		return manifestTrust{}, err
	}
	if !os.SameFile(fi, targetFI) {
		return manifestTrust{}, fmt.Errorf("%s moved while it was being read; nothing can be said about where it lives", path)
	}
	dirPath := filepath.Dir(target)
	dir, err := statFacts(dirPath)
	if err != nil {
		return manifestTrust{}, err
	}
	trust := manifestTrust{file: file, dir: dir, realPath: target}

	above, err := dirsUpward(filepath.Dir(dirPath))
	if err != nil {
		return manifestTrust{}, err
	}
	// skip dirPath: for a manifest sitting directly in /, walking up from it starts at
	// / again, and reporting it as both the holding directory and an ancestor is noise.
	trust.chain = appendUnseen(nil, above, dirPath)

	// A symlink named as the manifest is a second name for it, and whoever can replace
	// the link points it wherever they like however private its current target is - so
	// the directories leading to the link are inspected too. Only a link at the name
	// itself: a link at an intermediate component is the same exposure, but finding it
	// needs the resolution walked hop by hop rather than its endpoint read back.
	li, err := os.Lstat(path)
	if err != nil {
		return manifestTrust{}, err
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		linkDir, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			return manifestTrust{}, err
		}
		linked, err := dirsUpward(linkDir)
		if err != nil {
			return manifestTrust{}, err
		}
		trust.chain = appendUnseen(trust.chain, linked, dirPath)
	}
	return trust, nil
}

// inspectNewManifest gathers what can be judged about a manifest that does not exist yet:
// its location. The directory is resolved, so the write lands where the facts were read
// even if a component of the given path is a link.
//
// file describes the manifest as it will be created rather than one that is there, so only
// locationFlaws is meaningful on the result - flaws would report a clean verdict about a
// file nobody has looked at.
func inspectNewManifest(path string) (manifestTrust, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return manifestTrust{}, err
	}
	dirPath, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return manifestTrust{}, err
	}
	dir, err := statFacts(dirPath)
	if err != nil {
		return manifestTrust{}, err
	}
	above, err := dirsUpward(filepath.Dir(dirPath))
	if err != nil {
		return manifestTrust{}, err
	}
	return manifestTrust{
		file:     fileFacts{path: path, mode: newManifestMode, uid: uint32(os.Geteuid())},
		dir:      dir,
		chain:    appendUnseen(nil, above, dirPath),
		realPath: filepath.Join(dirPath, filepath.Base(abs)),
	}, nil
}

// newManifestMode is what a manifest written where none was gets: readable and writable by
// its owner and nobody else. Narrower than any umask would have left it, deliberately - a
// manifest is the policy a sandbox is built from, its approval attests permissions that
// only stay attested while nobody else can touch them, and someone who wants it readable
// can say so afterwards. Rewrites of an existing manifest carry its mode forward instead.
const newManifestMode fs.FileMode = 0o600

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
	if d.aclSharedWrite() {
		out = append(out, trustFlaw{
			reason: fmt.Sprintf("%s, %s, has an ACL granting write to a named user or group, who can replace the manifest", d.path, role),
			fatal:  true,
		})
	}
	if shared := d.sharedWrite(); shared != 0 {
		// World write is always fatal. Group write on its own is not: it is what a umask of
		// 002 leaves on every directory it creates, and on a distro with per-user groups the
		// group holds nobody else - refusing it would fail approve on ordinary machines.
		// Setgid is what says otherwise. A setgid group-writable directory is the shared
		// project layout, made that way so a group of people can all write there, so the
		// "nobody else is in the group" reading is the one thing it rules out.
		fatal := shared&0o002 != 0
		reason := fmt.Sprintf("%s, %s, is %s-writable (%#o), so anyone there can replace the manifest", d.path, role, writerClass(shared), d.mode.Perm())
		if shared&0o020 != 0 && d.mode&fs.ModeSetgid != 0 {
			fatal = true
			reason = fmt.Sprintf("%s, %s, is setgid and group-writable (%#o), which is the shared-project layout, so the group holds other people who can replace the manifest", d.path, role, d.mode.Perm())
		}
		out = append(out, trustFlaw{reason: reason, fatal: fatal})
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
