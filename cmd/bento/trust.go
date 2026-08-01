package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/manifest"
)

// fileFacts is the ownership and permissions of one path, the two things that decide
// who besides its owner can change what is there.
type fileFacts struct {
	path string
	mode fs.FileMode
	uid  uint32
	// aclWrite is write granted to a named user or group by a POSIX ACL, which the mode
	// cannot show: such a grant appears in the group-class bits and is indistinguishable
	// there from the group write an ordinary umask leaves. Only the directories the path walk
	// records carry it - the manifest's own ACL is corrected along with its mode by the
	// rewrite, which zeroes the group class and with it the mask every named entry is
	// filtered through.
	aclWrite bool
	// privateGroup marks a group-write grant that reaches nobody: the owning group was
	// resolved and holds no member but the owner. False whenever that could not be
	// established, so a group nothing could be learned about is read as holding somebody.
	privateGroup bool
}

func factsOf(path string, fi fs.FileInfo) (fileFacts, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileFacts{}, fmt.Errorf("cannot read ownership of %s", path)
	}
	// No group lookup, unlike the directories: this comes from fstat, which carries no ACL,
	// and on a file with one the group bits are the mask every named entry is filtered
	// through rather than a grant to the group. Reading them as reaching only a private
	// group would say nothing about a named writer the mask lets through. The false positive
	// that lookup exists to stop is not here either - the warning is only for a stamped
	// manifest, and approve clamps group write off the ones it stamps.
	return fileFacts{path: path, mode: fi.Mode(), uid: st.Uid}, nil
}

// withGroup fills in privateGroup, and only where a group-write bit makes the answer
// matter: the lookup reads the account database, and the modes that grant the group
// nothing have no question to ask of it.
func withGroup(f fileFacts, gid uint32) fileFacts {
	if f.mode.Perm()&0o020 != 0 {
		f.privateGroup = groupHoldsOnly(gid, f.uid)
	}
	return f
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

// sharedWrite is the write bits granted to someone other than the owner. A group bit whose
// group holds nobody else is not one of them: it grants write to a set of one, and the
// owner is already the owner. Setgid says the group is a real one - see dirFlaws - so the
// bit stands there whatever the membership reads as.
func (f fileFacts) sharedWrite() fs.FileMode {
	if f.stickyDir() {
		return 0
	}
	shared := f.mode.Perm() & 0o022
	if f.privateGroup && f.mode&fs.ModeSetgid == 0 {
		shared &^= 0o020
	}
	return shared
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
	// chain is every other directory the resolution passed through, in the reverse of the
	// order it read them so the nearest comes first: those above dir, since renaming one of
	// them aside substitutes the manifest as surely as replacing the file, and those that
	// held a symlink along the way, since whoever can replace a link repoints it at a file
	// of their choosing.
	chain []fileFacts
	// links is every symlink the resolution followed. Their own ownership is judged, not
	// their mode, which grants nothing on a symlink: the directory holding one usually
	// decides who may repoint it, but a sticky directory exempts that write on the premise
	// that only we can unlink our own entries - which is exactly what a link belonging to
	// somebody else breaks.
	links []fileFacts
}

// trustFlaw is one way someone other than this user could change the manifest. fatal
// marks the ones approve refuses to stamp over: not everything reported is, since a
// mode on the manifest itself is corrected by the rewrite, and a group-writable
// directory is what a umask of 002 leaves on every directory it creates.
type trustFlaw struct {
	reason string
	fatal  bool
	// hint is the command that resolves the flaw, where one does. A permissive umask is the
	// usual cause and chmod is the whole fix, but the reader has to be told so: a warning on
	// every command that never names its remedy is the shape of a line people learn to skip.
	hint string
}

// inspectManifest reads the trust facts for an already-open manifest. The file's come from
// fstat of the handle, and where it lives from the kernel's own name for the descriptor:
// authoritative, and free of any race with the bytes already parsed. The directories that
// lead there come from walking the given path a component at a time, since the endpoint
// alone cannot show a symlink partway along it; the two are required to agree.
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
	target, err := manifestLocation(f)
	if err != nil {
		return manifestTrust{}, err
	}
	// The kernel's name is not always usable as a path, and a rewrite sent to one that no
	// longer leads back to this descriptor would land somewhere the facts gathered here do
	// not describe. A manifest unlinked or renamed over between the open and the readlink
	// reads back as "/w/m.yaml (deleted)", which stats as a path nobody asked about; a name
	// that leads to a different inode is the same conclusion arrived at the other way. Any
	// other reason the stat fails describes a different problem and is left as it came.
	targetFI, err := os.Stat(target)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return manifestTrust{}, err
	}
	if err != nil || !os.SameFile(fi, targetFI) {
		return manifestTrust{}, fmt.Errorf("%s moved while it was being read; nothing can be said about where it lives", path)
	}
	dirs, links, _, err := pathDirs(path)
	if err != nil {
		return manifestTrust{}, err
	}
	// The walk landed where the kernel says the descriptor is, or the two disagree about
	// which file this is and neither the facts nor the location can be trusted. Nothing
	// short of a swap mid-walk makes them differ, and that is the case worth refusing.
	if dirPath := filepath.Dir(target); dirs[0].path != dirPath {
		return manifestTrust{}, fmt.Errorf("%s moved while it was being read: it resolved to %s but is open in %s", path, dirs[0].path, dirPath)
	}
	return manifestTrust{file: file, dir: dirs[0], chain: dirs[1:], links: links, realPath: target}, nil
}

// inspectNewManifest gathers what can be judged about a manifest that does not exist yet:
// its location. The path is walked the same way as an existing manifest's, so the write lands
// where the facts were read, and where the kernel would have put it - including through a
// symlink at the name itself, which a dotfiles repo whose target is not checked out yet
// leaves dangling, and which os.WriteFile would have followed rather than replaced.
//
// file describes the manifest as it will be created rather than one that is there, so only
// locationFlaws is meaningful on the result - flaws would report a clean verdict about a
// file nobody has looked at.
func inspectNewManifest(path string) (manifestTrust, error) {
	dirs, links, leaf, err := pathDirs(path)
	if err != nil {
		return manifestTrust{}, err
	}
	return manifestTrust{
		file:     fileFacts{path: path, mode: newManifestMode, uid: uint32(os.Geteuid())},
		dir:      dirs[0],
		chain:    dirs[1:],
		links:    links,
		realPath: filepath.Join(dirs[0].path, leaf),
	}, nil
}

// newManifestMode is what a manifest written where none was gets: readable and writable by
// its owner and nobody else. Narrower than any umask would have left it, deliberately - a
// manifest is the policy a sandbox is built from, its approval attests permissions that
// only stay attested while nobody else can touch them, and someone who wants it readable
// can say so afterwards. Rewrites of an existing manifest carry its mode forward instead.
const newManifestMode fs.FileMode = 0o600

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
	// A link belonging to someone else is theirs to repoint - but only where they can still
	// write the directory holding it, which ownership on its own does not say: root
	// unpacking somebody's tarball restores the link's uid (lchown) in a directory nobody
	// but root can write, and refusing that would fail on every such install.
	//
	// The holding directory's raw mode decides, not sharedWrite: sticky is exempted there
	// because others cannot unlink our entries, and a link that is not ours is exactly what
	// that premise misses. So a sticky world-writable directory, which reports no flaw of
	// its own, is the case this catches - and a plainly group-writable one, whose own flaw
	// is not fatal because a per-user group holds nobody else, becomes fatal once a link in
	// it belongs to somebody who evidently is in that group.
	for _, l := range t.links {
		if !l.foreignOwner(euid) {
			continue
		}
		if holder, ok := t.dirAt(filepath.Dir(l.path)); ok && holder.mode.Perm()&0o022 == 0 {
			continue
		}
		out = append(out, trustFlaw{
			reason: fmt.Sprintf("%s, a symlink on the path to it, is owned by uid %d and sits in a directory they can write, so they can repoint it at a manifest of their choosing", l.path, l.uid),
			fatal:  true,
		})
		break
	}
	// One fatal link in the chain is enough to report. A group-writable directory up the
	// tree is as ordinary as a group-writable one holding the manifest, and naming every
	// level to / would bury the one that actually lets someone else choose which manifest
	// is read.
	for _, d := range t.chain {
		for _, f := range dirFlaws(d, "a directory on the path to it", euid) {
			if f.fatal {
				return append(out, f)
			}
		}
	}
	return out
}

// dirAt finds the recorded facts for one of the directories the walk read a component
// from. Every directory holding a link the walk followed is among them, since the walk had
// to enter it to read the link - a miss means the two disagree, and a link whose holder
// cannot be found is judged as though the holder were writable rather than waved through.
func (t manifestTrust) dirAt(path string) (fileFacts, bool) {
	if t.dir.path == path {
		return t.dir, true
	}
	for _, d := range t.chain {
		if d.path == path {
			return d, true
		}
	}
	return fileFacts{}, false
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
		// 002 leaves on every directory it creates, and the group it grants may hold nobody -
		// refusing it would fail approve on ordinary machines. sharedWrite has already dropped
		// the ones proven to hold nobody, so what reaches here is a group with other people in
		// it or one nothing could be learned about, and neither is worth a refusal on its own.
		// Setgid is what says otherwise. A setgid group-writable directory is the shared
		// project layout, made that way so a group of people can all write there, so the
		// "nobody else is in the group" reading is the one thing it rules out.
		fatal := shared&0o002 != 0
		reason := fmt.Sprintf("%s, %s, is %s-writable (%#o), so anyone there can replace the manifest", d.path, role, writerClass(shared), d.mode.Perm())
		hint := fmt.Sprintf("chmod %s %s narrows it, if nobody else is meant to write there", chmodNarrowing(shared), d.path)
		if shared&0o020 != 0 && d.mode&fs.ModeSetgid != 0 {
			fatal = true
			reason = fmt.Sprintf("%s, %s, is setgid and group-writable (%#o), which is the shared-project layout, so the group holds other people who can replace the manifest", d.path, role, d.mode.Perm())
			// Not chmod: the directory is that mode on purpose, for people whose write it is
			// not this manifest's business to take away. Somewhere else is the remedy.
			hint = fmt.Sprintf("keep the manifest somewhere only you can write, and point bento at it there, rather than narrowing %s", d.path)
		}
		out = append(out, trustFlaw{reason: reason, fatal: fatal, hint: hint})
	}
	if d.foreignOwner(euid) {
		out = append(out, trustFlaw{
			reason: fmt.Sprintf("%s, %s, is owned by uid %d, who can replace the manifest", d.path, role, d.uid),
			fatal:  true,
		})
	}
	return out
}

// chmodNarrowing is the argument to chmod that takes the reported write away, and only
// that: a directory group-writable on purpose within a world-writable one should not be
// told to drop the group bit it meant to have.
func chmodNarrowing(shared fs.FileMode) string {
	switch {
	case shared&0o002 != 0 && shared&0o020 != 0:
		return "go-w"
	case shared&0o002 != 0:
		return "o-w"
	default:
		return "g-w"
	}
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

// warnStampAtRisk reports who besides this user can change the manifest - but only for a
// manifest carrying an approval stamp, which is the only thing the warning is about. An
// unstamped one is the profile-then-run inner loop, run with --allow-unapproved, where
// there is nothing yet to devalue and the warning is inapplicable; left unconditional it
// fired on every command of that loop, twice, on any host whose umask is 002. A reader
// learns within a day that [bento] lines are noise, which is the same shape as the lines
// they will someday need read - an accepted alias, a shielded-grant opt-in, a degraded
// layer. approve does not go through here: there a human is establishing the trust, so
// the state of the location is the decision being made.
func warnStampAtRisk(w io.Writer, doc *manifest.Document, trust manifestTrust) {
	if doc.Provenance.Approves == "" {
		return
	}
	warnUntrusted(w, trust.flaws(uint32(os.Geteuid())))
}

// warnUntrusted reports every flaw as advisory. The read commands do not refuse on one:
// a permissive umask or a shared checkout is ordinary, and failing run and validate over
// it would break working setups to describe a risk the user may already accept. approve,
// where a human is establishing the trust, does refuse.
func warnUntrusted(w io.Writer, flaws []trustFlaw) {
	for _, f := range flaws {
		fmt.Fprintf(w, "[bento] %s - its approval stamp attests only what whoever can write it leaves there.\n", f.reason)
		if f.hint != "" {
			fmt.Fprintf(w, "[bento] %s\n", f.hint)
		}
	}
}
