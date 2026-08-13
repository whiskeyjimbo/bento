// Package trust answers the two questions a manifest's approval rests on, for the CLI and
// for any other caller that runs one: whether the stamped fingerprint still matches the
// policy, and who besides the observing identity could have changed the file it is stamped
// on.
//
// Neither question is decided here. The observing identity is a parameter rather than
// os.Geteuid, because a caller running a manifest on somebody else's behalf must judge the
// location against that somebody; and a Flaw is data, so what to refuse over is the
// caller's to say. The CLI treats them as advisory on a read and fatal on an approve, which
// is one answer among several rather than the package's.
//
// One fact is not judged against that identity: whether a group-write bit reaches anybody,
// which is owner-relative - see withGroup. It is settled at Inspect time, before the
// identity is known, and cannot be re-parameterized afterwards.
package trust

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
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
	// group is what the account database could establish about a group-write grant: that
	// it reaches nobody, that it reaches other real users, or nothing at all. The zero
	// value is groupUnknown, so facts assembled without a lookup are not read as private.
	group groupReach
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

// withGroup fills in group, and only where a group-write bit makes the answer matter:
// the lookup reads the account database, and the modes that grant the group nothing have
// no question to ask of it.
//
// Owner-relative, and deliberately not the observing identity: the reach is read here,
// while the facts are gathered, and Flaws does not learn who is asking until later. The two
// coincide for every caller today - the CLI passes os.Geteuid() throughout, and the process
// that reads the directory is the one the manifest is judged for. They come apart for a
// caller judging on somebody else's behalf. It reads both ways there: a group holding only
// {owner, observer} warns about a second writer who is the observer, and a group holding
// only a foreign owner reads as private where an observer-relative lookup would warn. The
// second is the direction that would matter, and foreignOwner already answers it - a file
// somebody else owns is a fatal flaw on its own, which is the same reason sharedWrite does
// not count the owner. Moving the lookup behind Flaws is what fixes it, and would also
// have to stop counting the observer as another member; it waits for the caller that needs
// it rather than being guessed at now.
func withGroup(f fileFacts, gid uint32) fileFacts {
	if f.mode.Perm()&0o020 != 0 {
		f.group = groupReachOf(gid, f.uid)
	}
	return f
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
	if f.group == groupPrivate && f.mode&fs.ModeSetgid == 0 {
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

// Manifest is a manifest's own permissions together with those of every directory
// that leads to it. The directories matter on their own: write and search in one is
// enough to rename something else into place, whatever the manifest's own mode said.
type Manifest struct {
	file fileFacts
	dir  fileFacts
	// RealPath is where the manifest actually lives, as the kernel names the open
	// descriptor: the same resolution dir and chain were judged against, so a caller that
	// rewrites the manifest writes at the location that was inspected rather than
	// resolving the name a second time and racing whoever can repoint it.
	RealPath string
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
	// located records that the location above was actually established. False is the
	// zero value on purpose: a host where the location cannot be read must not read as
	// one where it was read and found clean, and LocationFlaws reports the gap rather
	// than answering nothing. See ErrLocationUnknown.
	located bool
}

// ErrLocationUnknown is what the platform stubs return where the location cannot be
// established at all, as opposed to a location that was read and is unsound. The two
// answers differ in what a caller may do with them: an unsound location is a finding
// about this manifest, an unknown one is a finding about this host.
var ErrLocationUnknown = errors.New("where a manifest lives cannot be checked on this platform")

// Flaw is one way someone other than the observing identity could change the manifest.
// Fatal marks the ones a caller establishing trust should refuse to stamp over: not
// everything reported is, since a mode on the manifest itself is corrected by the
// rewrite, and a group-writable directory is what a umask of 002 leaves on every
// directory it creates. What to do about either is the caller's decision - nothing here
// acts on Fatal.
type Flaw struct {
	Reason string
	Fatal  bool
	// Hint is the command that resolves the flaw, where one does. A permissive umask is the
	// usual cause and chmod is the whole fix, but the reader has to be told so: a warning on
	// every command that never names its remedy is the shape of a line people learn to skip.
	Hint string
}

// Inspect reads the trust facts for an already-open manifest. The file's come from
// fstat of the handle, and where it lives from the kernel's own name for the descriptor:
// authoritative, and free of any race with the bytes already parsed. The directories that
// lead there come from walking the given path a component at a time, since the endpoint
// alone cannot show a symlink partway along it; the two are required to agree.
//
// The directories are judged on their mode bits and their access ACL. The manifest's own
// facts come from fstat, which carries no ACL, because the rewrite corrects its mode - and
// with the group class the mask every named ACL entry is filtered through.
func Inspect(f *os.File, path string) (Manifest, error) {
	fi, err := f.Stat()
	if err != nil {
		return Manifest{}, err
	}
	// A manifest read from a pipe or a device has no location to judge: the kernel names
	// the descriptor `pipe:[N]`, whose directory reads back as the process's own working
	// directory, and a verdict about that describes nothing the manifest came from.
	// Approve could not rewrite it either.
	if !fi.Mode().IsRegular() {
		return Manifest{}, fmt.Errorf("%s is not a regular file, so there is nothing to vouch for its permissions", path)
	}
	file, err := factsOf(path, fi)
	if err != nil {
		return Manifest{}, err
	}
	target, err := manifestLocation(f)
	// A host that cannot read the location still knows everything fstat says about the
	// manifest itself, and refusing here would withhold that over a fact the caller may
	// not need: validate only warns on what it finds, and a macOS developer linting a
	// manifest in CI is asking about its contents. What is missing is reported by
	// LocationFlaws, so it is carried rather than assumed clean.
	if errors.Is(err, ErrLocationUnknown) {
		return Manifest{file: file}, nil
	}
	if err != nil {
		return Manifest{}, err
	}
	// The kernel's name is not always usable as a path, and a rewrite sent to one that no
	// longer leads back to this descriptor would land somewhere the facts gathered here do
	// not describe. A manifest unlinked or renamed over between the open and the readlink
	// reads back as "/w/m.yaml (deleted)", which stats as a path nobody asked about; a name
	// that leads to a different inode is the same conclusion arrived at the other way. Any
	// other reason the stat fails describes a different problem and is left as it came.
	targetFI, err := os.Stat(target)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, err
	}
	if err != nil || !os.SameFile(fi, targetFI) {
		return Manifest{}, fmt.Errorf("%s moved while it was being read; nothing can be said about where it lives", path)
	}
	dirs, links, _, err := pathDirs(path)
	if err != nil {
		return Manifest{}, err
	}
	// The walk landed where the kernel says the descriptor is, or the two disagree about
	// which file this is and neither the facts nor the location can be trusted. Nothing
	// short of a swap mid-walk makes them differ, and that is the case worth refusing.
	if dirPath := filepath.Dir(target); dirs[0].path != dirPath {
		return Manifest{}, fmt.Errorf("%s moved while it was being read: it resolved to %s but is open in %s", path, dirs[0].path, dirPath)
	}
	return Manifest{file: file, dir: dirs[0], chain: dirs[1:], links: links, RealPath: target, located: true}, nil
}

// InspectNew gathers what can be judged about a manifest that does not exist yet:
// its location. The path is walked the same way as an existing manifest's, so the write lands
// where the facts were read, and where the kernel would have put it - including through a
// symlink at the name itself, which a dotfiles repo whose target is not checked out yet
// leaves dangling, and which os.WriteFile would have followed rather than replaced.
//
// file describes the manifest as it will be created rather than one that is there, so only
// LocationFlaws is meaningful on the result - Flaws would report a clean verdict about a
// file nobody has looked at. euid is who will create it, which is the same identity the
// result is later judged against: reading it from the process here would answer for the
// observer rather than for the writer, which is the whole distinction Flaws takes it as a
// parameter to keep.
func InspectNew(path string, euid uint32) (Manifest, error) {
	dirs, links, leaf, err := pathDirs(path)
	if err != nil {
		return Manifest{}, err
	}
	return Manifest{
		file:     fileFacts{path: path, mode: newManifestMode, uid: euid},
		dir:      dirs[0],
		chain:    dirs[1:],
		links:    links,
		RealPath: filepath.Join(dirs[0].path, leaf),
		located:  true,
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
func (t Manifest) Flaws(euid uint32) []Flaw {
	var out []Flaw
	if t.file.sharedWrite() != 0 {
		out = append(out, Flaw{
			Reason: fmt.Sprintf("%s is group/world-writable (%#o)", t.file.path, t.file.mode.Perm()),
		})
	}
	if t.file.foreignOwner(euid) {
		out = append(out, Flaw{
			Reason: fmt.Sprintf("%s is owned by uid %d", t.file.path, t.file.uid),
			Fatal:  true,
			Hint:   ownershipHint(t.file, euid),
		})
	}
	return append(out, t.LocationFlaws(euid)...)
}

// LocationFlaws is the half of flaws that is about where the manifest lives rather than
// the manifest itself. approve reports these on their own: the file's own mode is
// something its rewrite corrects and announces, so warning about it here as well would
// describe a state approve is in the middle of leaving.
func (t Manifest) LocationFlaws(euid uint32) []Flaw {
	// Nothing was read, so there is nothing to judge and a clean verdict would be the one
	// wrong answer: every directory below reads as mode 0 owned by root, which is neither
	// what is there nor a sentence about this manifest. Fatal because approve's stamp is
	// worth exactly what the location vouches for, and here nothing does.
	if !t.located {
		return []Flaw{{
			Reason: fmt.Sprintf("where %s lives cannot be checked on %s, so nothing vouches for who else can replace it", t.file.path, runtime.GOOS),
			Fatal:  true,
		}}
	}
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
		out = append(out, Flaw{
			Reason: fmt.Sprintf("%s, a symlink on the path to it, is owned by uid %d and sits in a directory they can write, so they can repoint it at a manifest of their choosing", l.path, l.uid),
			Fatal:  true,
		})
		break
	}
	// One fatal link in the chain is enough to report. A group-writable directory up the
	// tree is as ordinary as a group-writable one holding the manifest, and naming every
	// level to / would bury the one that actually lets someone else choose which manifest
	// is read.
	for _, d := range t.chain {
		for _, f := range dirFlaws(d, "a directory on the path to it", euid) {
			if f.Fatal {
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
func (t Manifest) dirAt(path string) (fileFacts, bool) {
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
func dirFlaws(d fileFacts, role string, euid uint32) []Flaw {
	var out []Flaw
	if d.aclSharedWrite() {
		out = append(out, Flaw{
			Reason: fmt.Sprintf("%s, %s, has an ACL granting write to a named user or group, who can replace the manifest", d.path, role),
			Fatal:  true,
		})
	}
	if shared := d.sharedWrite(); shared != 0 {
		// World write is always fatal. Group write is fatal once something says the group
		// really does hold other people: the account database proving it, or setgid, which
		// is the shared-project layout - made that way so a group can all write there - and
		// says so structurally on a host where nothing can be proven at all. Group write
		// with neither is not: it is what a umask of 002 leaves on every directory it
		// creates, and where the database cannot answer (a directory service, an
		// unresolvable member, a gid the files do not name) the group may hold nobody, so
		// refusing would fail approve on ordinary machines. sharedWrite has already dropped
		// the ones proven to hold nobody.
		fatal := shared&0o002 != 0
		reason := fmt.Sprintf("%s, %s, is %s-writable (%#o), so anyone there can replace the manifest", d.path, role, writerClass(shared), d.mode.Perm())
		hint := fmt.Sprintf("chmod %s %s narrows it, if nobody else is meant to write there", chmodNarrowing(shared), d.path)
		switch {
		case shared&0o020 == 0:
		case d.mode&fs.ModeSetgid != 0:
			fatal = true
			reason = fmt.Sprintf("%s, %s, is setgid and group-writable (%#o), which is the shared-project layout, so the group holds other people who can replace the manifest", d.path, role, d.mode.Perm())
			// Not chmod: the directory is that mode on purpose, for people whose write it is
			// not this manifest's business to take away. Somewhere else is the remedy.
			hint = relocateHint(d.path)
		case d.group == groupShared:
			fatal = true
			reason = fmt.Sprintf("%s, %s, is %s-writable (%#o) and its group holds other users, so they can replace the manifest", d.path, role, writerClass(shared), d.mode.Perm())
			// The chmod hint stands where the caller owns the directory - a plain 0775 is
			// usually just what the umask left, and narrowing it takes nothing from anybody
			// who was meant to have it. Where they do not, it names a command that fails: a
			// root-owned /var/www group-writable to www-data is proven-shared, and
			// foreignOwner exempts root, so nothing else here would name a remedy at all.
			if d.uid != euid {
				hint = relocateHint(d.path)
			}
		}
		out = append(out, Flaw{Reason: reason, Fatal: fatal, Hint: hint})
	}
	if d.foreignOwner(euid) {
		out = append(out, Flaw{
			Reason: fmt.Sprintf("%s, %s, is owned by uid %d, who can replace the manifest", d.path, role, d.uid),
			Fatal:  true,
			Hint:   ownershipHint(d, euid),
		})
	}
	return out
}

// ownershipHint is the remedy for a path somebody else owns - the pair of flaws a
// container meets on every command, with sources checked out as one uid and the job run as
// another, and until now the pair that named nothing to do about it.
//
// The chown is named only to root, because only root can hand a path to a different user.
// Telling an ordinary user to chown a file that is not theirs names a command that fails,
// which is worse than naming none - so they are told the thing they can do without the
// owner's help, in the same shape as the shared-project directory's hint. It carries the
// same hedge the chmod hint does, and for a stronger reason: this fires on the directory
// as well as the manifest, and taking a whole checkout from the uid that populated it
// breaks every later step still running as them.
func ownershipHint(f fileFacts, euid uint32) string {
	if euid == 0 {
		return fmt.Sprintf("chown 0 %s hands it over, if nobody else is meant to write there", f.path)
	}
	return fmt.Sprintf("keep the manifest somewhere you own, and point bento at it there, rather than relying on uid %d to leave it alone", f.uid)
}

// relocateHint is the remedy for a directory whose write belongs to somebody else and is
// not this manifest's to take away - a shared-project layout, or one this user does not
// own at all. Moving the manifest is the whole of what they can do without the owner.
func relocateHint(path string) string {
	return fmt.Sprintf("keep the manifest somewhere only you can write, and point bento at it there, rather than narrowing %s", path)
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

// Located reports whether where the manifest lives was actually established. False on a
// host that cannot read it at all, where a caller about to write has nothing inspected to
// write at - see ErrLocationUnknown.
func (t Manifest) Located() bool { return t.located }

// Path is the manifest as it was named, not as it resolved: RealPath is the resolution.
func (t Manifest) Path() string { return t.file.path }

// Mode is the manifest's own permission bits, which a caller rewriting it carries forward.
func (t Manifest) Mode() fs.FileMode { return t.file.mode.Perm() }

// SharedWrite is the write the manifest itself grants to someone other than its owner,
// with the exemptions sharedWrite applies - the bits that make an approval stamp attest
// only what the other writer leaves there.
func (t Manifest) SharedWrite() fs.FileMode { return t.file.sharedWrite() }
