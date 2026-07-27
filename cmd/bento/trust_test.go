package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A sticky directory (/tmp) is world-writable but does not let anyone rename or unlink
// another user's manifest, so it must not read as a second writer - otherwise every
// manifest under /tmp warns and the warning stops meaning anything.
func TestSharedWrite(t *testing.T) {
	cases := map[string]struct {
		mode fs.FileMode
		want fs.FileMode
	}{
		"private file":       {0o644, 0},
		"group-writable":     {0o664, 0o020},
		"world-writable":     {0o646, 0o002},
		"private dir":        {fs.ModeDir | 0o755, 0},
		"open dir":           {fs.ModeDir | 0o777, 0o022},
		"sticky open dir":    {fs.ModeDir | fs.ModeSticky | 0o777, 0},
		"group-writable dir": {fs.ModeDir | 0o775, 0o020},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := fileFacts{path: "/m.yaml", mode: tc.mode}
			if got := f.sharedWrite(); got != tc.want {
				t.Errorf("sharedWrite(%v) = %#o, want %#o", tc.mode, got, tc.want)
			}
		})
	}
}

// The mode alone cannot say who the group holds. Setgid can: a setgid group-writable
// directory is the shared-project layout, made that way precisely so several people write
// there, which is the one thing "on a distro with per-user groups the group holds nobody
// else" rules out. An ACL naming a writer is the same story told a different way.
func TestDirFlawsFatality(t *testing.T) {
	const me = 1000
	cases := map[string]struct {
		facts     fileFacts
		wantFatal bool
	}{
		"private":                {fileFacts{path: "/w", mode: fs.ModeDir | 0o755, uid: me}, false},
		"group-writable":         {fileFacts{path: "/w", mode: fs.ModeDir | 0o775, uid: me}, false},
		"world-writable":         {fileFacts{path: "/w", mode: fs.ModeDir | 0o777, uid: me}, true},
		"setgid group-writable":  {fileFacts{path: "/w", mode: fs.ModeDir | fs.ModeSetgid | 0o775, uid: me}, true},
		"setgid but not group":   {fileFacts{path: "/w", mode: fs.ModeDir | fs.ModeSetgid | 0o755, uid: me}, false},
		"an ACL names a writer":  {fileFacts{path: "/w", mode: fs.ModeDir | 0o755, uid: me, aclWrite: true}, true},
		"sticky world-writable":  {fileFacts{path: "/tmp", mode: fs.ModeDir | fs.ModeSticky | 0o777, uid: 0}, false},
		"setgid sticky and open": {fileFacts{path: "/w", mode: fs.ModeDir | fs.ModeSetgid | fs.ModeSticky | 0o775, uid: me}, false},
		// Sticky is the same exemption whichever way the write was granted: a named user who
		// cannot unlink our manifest cannot replace it either, and refusing every approve
		// under a /tmp that carries an ACL would leave the user no remedy.
		"sticky, an ACL names a writer": {fileFacts{path: "/tmp", mode: fs.ModeDir | fs.ModeSticky | 0o777, uid: 0, aclWrite: true}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var fatal bool
			for _, f := range dirFlaws(tc.facts, "the directory holding it", me) {
				fatal = fatal || f.fatal
			}
			if fatal != tc.wantFatal {
				t.Errorf("fatal = %v, want %v for %v", fatal, tc.wantFatal, tc.facts.mode)
			}
		})
	}
}

// setACL writes a POSIX access ACL, so the parse is exercised against what the kernel
// actually stores rather than a blob this test made up. entries are {tag, perm, id}
// triples in the order the kernel requires: USER_OBJ, USER*, GROUP_OBJ, GROUP*, MASK,
// OTHER.
func setACL(t *testing.T, path string, entries [][3]uint32) {
	t.Helper()
	blob := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range entries {
		blob = binary.LittleEndian.AppendUint16(blob, uint16(e[0]))
		blob = binary.LittleEndian.AppendUint16(blob, uint16(e[1]))
		blob = binary.LittleEndian.AppendUint32(blob, e[2])
	}
	if err := unix.Setxattr(path, "system.posix_acl_access", blob, 0); err != nil {
		t.Skipf("this filesystem does not take POSIX ACLs: %v", err)
	}
}

// A named user granted write is exactly what the mode cannot show: it lands in the
// group-class bits, where it is indistinguishable from the group write an ordinary umask
// leaves. Reading the ACL is the only way to tell them apart, and only entries naming
// somebody count - a directory that merely inherited a default ACL names nobody.
func TestACLNamedWrite(t *testing.T) {
	const (
		userObj, user, groupObj, mask, other = 0x01, 0x02, 0x04, 0x10, 0x20
		noID                                 = 0xffffffff
	)
	cases := map[string]struct {
		entries [][3]uint32
		want    bool
	}{
		"trivial, as an inherited default leaves it": {
			[][3]uint32{{userObj, 7, noID}, {groupObj, 5, noID}, {other, 5, noID}}, false,
		},
		"a named user with write": {
			[][3]uint32{{userObj, 7, noID}, {user, 7, 65534}, {groupObj, 5, noID}, {mask, 7, noID}, {other, 5, noID}}, true,
		},
		"a named user with read only": {
			[][3]uint32{{userObj, 7, noID}, {user, 5, 65534}, {groupObj, 5, noID}, {mask, 7, noID}, {other, 5, noID}}, false,
		},
		"a named user whose write the mask withholds": {
			[][3]uint32{{userObj, 7, noID}, {user, 7, 65534}, {groupObj, 5, noID}, {mask, 5, noID}, {other, 5, noID}}, false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setACL(t, dir, tc.entries)
			got, err := aclNamedWrite(dir)
			if err != nil {
				t.Fatalf("aclNamedWrite: %v", err)
			}
			if got != tc.want {
				t.Errorf("aclNamedWrite = %v, want %v", got, tc.want)
			}
		})
	}
}

// A directory an ACL lets a specific other user write is one they can replace the manifest
// in, so approve must refuse it - the same as a world-writable one, and for the same
// reason, however private the mode looks.
func TestApproveRefusesADirectoryAnACLOpens(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere regardless")
	}
	dir := t.TempDir()
	path := manifestIn(t, dir)
	setACL(t, dir, [][3]uint32{
		{0x01, 7, 0xffffffff}, {0x02, 7, 65534}, {0x04, 5, 0xffffffff}, {0x10, 7, 0xffffffff}, {0x20, 5, 0xffffffff},
	})

	_, err := runCapturingStdout(t, newApproveCmd(), path)
	if err == nil {
		t.Fatal("a directory an ACL opens to another user must not be stamped over")
	}
	if !strings.Contains(err.Error(), "ACL") {
		t.Errorf("the refusal must name the ACL; got %v", err)
	}
}

// A symlink partway along the path is the same exposure as one at the manifest's own name:
// whoever can write the directory holding it repoints it at a file of their choosing. The
// endpoint cannot show it - an intermediate hop appears in neither the name given nor the
// path it resolved to - so the walk has to record the directory every hop was read from.
func TestPathDirsSeesIntermediateSymlinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// <root>/open holds the link, <root>/real holds the manifest; only the link's holder is
	// world-writable, and nothing about /open appears in <root>/real/bento.yaml.
	open, real := filepath.Join(root, "open"), filepath.Join(root, "real")
	for _, d := range []string{open, real} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(open, "lnk")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(open, "lnk", "bento.yaml")
	if err := os.WriteFile(filepath.Join(real, "bento.yaml"), []byte("entrypoint: ./x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dirs, _, err := pathDirs(path)
	if err != nil {
		t.Fatalf("pathDirs: %v", err)
	}
	if dirs[0].path != real {
		t.Errorf("the nearest directory must be the manifest's own %s; got %s", real, dirs[0].path)
	}
	var sawOpen bool
	for _, d := range dirs {
		sawOpen = sawOpen || d.path == open
	}
	if !sawOpen {
		t.Fatalf("the directory holding the intermediate link must be inspected; got %v", dirs)
	}

	if os.Geteuid() == 0 {
		return // root writes anywhere regardless, so nothing about the mode is a finding
	}
	// And it is reported as fatal, so approve refuses rather than stamping a manifest whose
	// name somebody else chooses.
	flaws := trustOf(t, path).locationFlaws(uint32(os.Geteuid()))
	var fatal bool
	for _, f := range flaws {
		fatal = fatal || (f.fatal && strings.Contains(f.reason, open))
	}
	if !fatal {
		t.Errorf("a world-writable directory holding an intermediate link must be fatal; got %+v", flaws)
	}
}

// A chain of links resolves the way an open of the same path would, and a loop is refused
// at the kernel's own ceiling rather than walked until something runs out.
func TestPathDirsFollowsChainsAndRefusesLoops(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A relative target continues from the directory holding the link, not from the cwd.
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "two")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("two", filepath.Join(root, "one")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "bento.yaml"), []byte("entrypoint: ./x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirs, _, err := pathDirs(filepath.Join(root, "one", "bento.yaml"))
	if err != nil {
		t.Fatalf("pathDirs: %v", err)
	}
	if dirs[0].path != target {
		t.Errorf("a chain of relative links must land in %s; got %s", target, dirs[0].path)
	}

	if err := os.Symlink(filepath.Join(root, "b"), filepath.Join(root, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pathDirs(filepath.Join(root, "a", "bento.yaml")); err == nil {
		t.Error("a symlink loop must be refused, not walked")
	}
}

// The place a manifest is about to be written is judged by the same walk as one already
// there, `..` and all: cleaning the name lexically first would name a directory the kernel
// would not have written to, so profile would judge one location and create the file in
// another.
func TestInspectNewManifestFollowsDotDotThroughALink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, w := filepath.Join(root, "elsewhere"), filepath.Join(root, "w")
	for _, d := range []string{elsewhere, w} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(elsewhere, filepath.Join(w, "lnk")); err != nil {
		t.Fatal(err)
	}

	// Built by hand: filepath.Join and filepath.Abs both clean the ".." away, and after a
	// symlink the cleaned name is a different directory than the kernel reaches.
	trust, err := inspectNewManifest(w + "/lnk/../bento.yaml")
	if err != nil {
		t.Fatalf("inspectNewManifest: %v", err)
	}
	if want := filepath.Join(root, "bento.yaml"); trust.realPath != want {
		t.Errorf("realPath = %q, want %q - where an open of the same name would land", trust.realPath, want)
	}
}

// A manifest symlinked into place from a dotfiles repo whose target is not checked out yet
// is a dangling link. os.WriteFile followed it and created the target; renaming onto the
// name would replace the link with a regular file and detach it from its source, which is
// the case writeManifestAtomically exists to avoid for an existing manifest.
func TestInspectNewManifestFollowsADanglingLink(t *testing.T) {
	dir := t.TempDir()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(real, "bento.yaml")
	if err := os.Symlink(filepath.Join(real, "source.yaml"), link); err != nil {
		t.Fatal(err)
	}
	trust, err := inspectNewManifest(link)
	if err != nil {
		t.Fatalf("inspectNewManifest: %v", err)
	}
	if err := writeManifestAtomically(trust, []byte("entrypoint: ./x\n"), io.Discard); err != nil {
		t.Fatalf("writeManifestAtomically: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("the link must survive and its target be written; lstat = %v, %v", fi, err)
	}
	if data, err := os.ReadFile(filepath.Join(real, "source.yaml")); err != nil || string(data) != "entrypoint: ./x\n" {
		t.Errorf("the link's target must hold the manifest; got %q, %v", data, err)
	}
}

// pathDirs is run once per manifest load, and a profile session loads the manifest every
// round, so a descriptor left behind on the way out accumulates over a long session.
func TestPathDirsLeaksNoDescriptors(t *testing.T) {
	dir := t.TempDir()
	path := manifestIn(t, dir)
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}

	before := count()
	for range 20 {
		if _, _, err := pathDirs(path); err != nil {
			t.Fatal(err)
		}
		// The interesting half: an error partway along used to leave the descriptor the walk
		// was standing on open.
		if _, _, err := pathDirs(filepath.Join(dir, "absent", "bento.yaml")); err == nil {
			t.Fatal("a missing intermediate directory must fail")
		}
	}
	if after := count(); after > before {
		t.Errorf("open descriptors went from %d to %d", before, after)
	}
}

// Root is not a foreign owner: it can write anywhere regardless, so flagging it would
// report every system-installed manifest without naming a reachable widening.
func TestForeignOwner(t *testing.T) {
	const me = 1000
	cases := map[string]struct {
		uid  uint32
		want bool
	}{
		"mine":          {me, false},
		"root":          {0, false},
		"another user":  {1001, true},
		"a system user": {48, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := (fileFacts{uid: tc.uid}).foreignOwner(me); got != tc.want {
				t.Errorf("foreignOwner(%d) = %v, want %v", tc.uid, got, tc.want)
			}
		})
	}
}

// Everything a second writer could do is reported; only some of it stops an approve.
func TestFlawsSeparateReportingFromRefusal(t *testing.T) {
	const me = 1000
	cases := map[string]struct {
		trust     manifestTrust
		wantCount int
		wantFatal int
	}{
		// The rewrite clamps the manifest's own mode, so it is reported, not refused.
		"writable manifest": {
			trust: manifestTrust{
				file: fileFacts{path: "/w/m.yaml", mode: 0o666, uid: me},
				dir:  fileFacts{path: "/w", mode: fs.ModeDir | 0o755, uid: me},
			},
			wantCount: 1,
		},
		// A umask of 002 leaves this on every directory it creates.
		"group-writable dir": {
			trust: manifestTrust{
				file: fileFacts{path: "/w/m.yaml", mode: 0o644, uid: me},
				dir:  fileFacts{path: "/w", mode: fs.ModeDir | 0o775, uid: me},
			},
			wantCount: 1,
		},
		"world-writable dir": {
			trust: manifestTrust{
				file: fileFacts{path: "/w/m.yaml", mode: 0o644, uid: me},
				dir:  fileFacts{path: "/w", mode: fs.ModeDir | 0o777, uid: me},
			},
			wantCount: 1,
			wantFatal: 1,
		},
		"someone else's manifest in their directory": {
			trust: manifestTrust{
				file: fileFacts{path: "/w/m.yaml", mode: 0o644, uid: 1001},
				dir:  fileFacts{path: "/w", mode: fs.ModeDir | 0o755, uid: 1001},
			},
			wantCount: 2,
			wantFatal: 2,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			flaws := tc.trust.flaws(me)
			fatal := 0
			for _, f := range flaws {
				if f.fatal {
					fatal++
				}
			}
			if len(flaws) != tc.wantCount || fatal != tc.wantFatal {
				t.Errorf("flaws = %+v (%d fatal), want %d flaws and %d fatal", flaws, fatal, tc.wantCount, tc.wantFatal)
			}
		})
	}

	// The two halves of the split in one trust: the file's foreign owner refuses, the
	// group-writable directory around it only reports. Asserting counts alone would let
	// the two fatality bits swap without failing.
	t.Run("fatal and reported together", func(t *testing.T) {
		mixed := manifestTrust{
			file: fileFacts{path: "/w/m.yaml", mode: 0o644, uid: 1001},
			dir:  fileFacts{path: "/w", mode: fs.ModeDir | 0o775, uid: me},
		}
		flaws := mixed.flaws(me)
		if len(flaws) != 2 {
			t.Fatalf("flaws = %+v, want the foreign owner and the group-writable directory", flaws)
		}
		if !flaws[0].fatal || !strings.Contains(flaws[0].reason, "/w/m.yaml is owned by uid 1001") {
			t.Errorf("a manifest owned by someone else must refuse the approve; got %+v", flaws[0])
		}
		if flaws[1].fatal || !strings.Contains(flaws[1].reason, "group-writable") {
			t.Errorf("a group-writable directory is reported, not refused; got %+v", flaws[1])
		}
	})

	clean := manifestTrust{
		file: fileFacts{path: "/w/m.yaml", mode: 0o644, uid: me},
		dir:  fileFacts{path: "/w", mode: fs.ModeDir | 0o755, uid: me},
	}
	if got := clean.flaws(me); got != nil {
		t.Errorf("a private manifest in a private directory has nothing to report; got %+v", got)
	}
}

// approve announces the clamp it applies to the manifest's own mode, so the warnings it
// prints alongside must describe only where the manifest lives - otherwise one loose
// mode is reported twice, once as a problem and once as the fix.
func TestLocationFlawsExcludeTheManifestItself(t *testing.T) {
	const me = 1000
	trust := manifestTrust{
		file: fileFacts{path: "/w/m.yaml", mode: 0o666, uid: me},
		dir:  fileFacts{path: "/w", mode: fs.ModeDir | 0o775, uid: me},
	}
	if got := trust.flaws(me); len(got) != 2 {
		t.Fatalf("flaws = %+v, want the manifest's mode and the directory's", got)
	}
	got := trust.locationFlaws(me)
	if len(got) != 1 || strings.Contains(got[0].reason, "m.yaml") {
		t.Errorf("locationFlaws must not repeat the manifest's own mode; got %+v", got)
	}
}

func manifestIn(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "bento.yaml")
	if err := os.WriteFile(path, []byte("entrypoint: ./x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// profile writes a manifest where none was, so there is no open handle to read the location
// from - but the directory is there to be judged, and a world-writable one is the whole
// reason the write is worth a word at all.
func TestInspectNewManifestJudgesTheDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	trust, err := inspectNewManifest(filepath.Join(dir, "bento.yaml"))
	if err != nil {
		t.Fatalf("inspectNewManifest: %v", err)
	}
	flaws := trust.locationFlaws(uint32(os.Geteuid()))
	if len(flaws) != 1 || !strings.Contains(flaws[0].reason, "the directory holding it") {
		t.Errorf("a world-writable directory must be reported; got %+v", flaws)
	}

	// The write goes to the resolved directory: a link at a component of --out would
	// otherwise send it somewhere the facts above describe nothing about.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	linked, err := inspectNewManifest(filepath.Join(link, "bento.yaml"))
	if err != nil {
		t.Fatalf("inspectNewManifest: %v", err)
	}
	if want := filepath.Join(trust.dir.path, "bento.yaml"); linked.realPath != want {
		t.Errorf("realPath = %q, want the resolved %q", linked.realPath, want)
	}
}

// A manifest written where none was gets owner-only write, whatever the umask: the next
// command's approval stamp is worth what the file's permissions are.
func TestWriteManifestAtomicallyCreatesAPrivateManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bento.yaml")
	trust, err := inspectNewManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeManifestAtomically(trust, []byte("entrypoint: ./x\n"), io.Discard); err != nil {
		t.Fatalf("writeManifestAtomically: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %#o, want 0600 - narrower than the umask, since nobody else's write can be attested", got)
	}
}

// trustOf is how the write path is reached in a test: the location a manifest is rewritten
// at comes from the trust, which only an open handle can produce.
func trustOf(t *testing.T, path string) manifestTrust {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	trust, err := inspectManifest(f, path)
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

// run, validate and profile keep working on a permissive checkout: a second writer is
// reported, not refused, since a shared box or a loose umask is ordinary.
func TestLoadDocumentWarnsAboutAWorldWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	path := manifestIn(t, dir)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}

	var warn bytes.Buffer
	if _, _, err := loadDocument(path, &warn); err != nil {
		t.Fatalf("loadDocument: %v", err)
	}
	if !strings.Contains(warn.String(), "the directory holding it") {
		t.Errorf("a world-writable directory must be reported; got %q", warn.String())
	}
}

// A `..` that follows a symlink cannot be cleaned away lexically: the kernel applies it
// to where the link landed, so `w/lnk/../m.yaml` names a file beside lnk's target and
// not one in w. Resolving the path in userspace got this wrong and described a directory
// the manifest was not in, which is the whole verdict computed against the wrong tree.
func TestInspectManifestFollowsTheKernelThroughDotDot(t *testing.T) {
	// Resolved, because the assertion below compares against the kernel's name for the
	// directory and a TMPDIR reached through a symlink would otherwise fail spuriously.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(root, "elsewhere")
	w := filepath.Join(root, "w")
	for _, d := range []string{elsewhere, w} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(elsewhere, filepath.Join(w, "lnk")); err != nil {
		t.Fatal(err)
	}
	real := manifestIn(t, root)

	// Built by hand: filepath.Join would clean the ".." away, which is exactly the
	// lexical shortcut this test exists to rule out.
	path := w + "/lnk/../" + filepath.Base(real)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	trust, err := inspectManifest(f, path)
	if err != nil {
		t.Fatalf("inspectManifest: %v", err)
	}
	if trust.dir.path != root {
		t.Errorf("the manifest lives in %s, but its location reads as %s", root, trust.dir.path)
	}
}

// The kernel names a pipe or device descriptor `pipe:[N]` or /dev/null, whose directory
// is either meaningless or the process's own working directory. Parsing would succeed
// and the verdict would describe somewhere the manifest never came from, so the load
// fails instead.
func TestLoadDocumentRefusesANonRegularFile(t *testing.T) {
	_, _, err := loadDocument(os.DevNull, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a manifest with no location on disk must not load; got %v", err)
	}
}

// approvable runs the check the way approve does, on the trust from the same open that
// read the manifest.
func approvable(t *testing.T, path string) error {
	t.Helper()
	_, trust, err := loadDocument(path, io.Discard)
	if err != nil {
		t.Fatalf("loadDocument: %v", err)
	}
	return requireApprovableLocation(path, trust)
}

func TestRequireApprovableLocation(t *testing.T) {
	t.Run("refuses a world-writable directory", func(t *testing.T) {
		dir := t.TempDir()
		path := manifestIn(t, dir)
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		err := approvable(t, path)
		if err == nil || !strings.Contains(err.Error(), "the directory holding it") {
			t.Fatalf("a manifest anyone can replace must not be stamped; got %v", err)
		}
	})

	// A private directory under a world-writable one is no safer: renaming the parent
	// aside substitutes the whole tree, so the check cannot stop at the first level.
	t.Run("refuses a world-writable ancestor", func(t *testing.T) {
		outer := t.TempDir()
		inner := filepath.Join(outer, "proj")
		if err := os.Mkdir(inner, 0o755); err != nil {
			t.Fatal(err)
		}
		path := manifestIn(t, inner)
		if err := os.Chmod(outer, 0o777); err != nil {
			t.Fatal(err)
		}
		err := approvable(t, path)
		if err == nil || !strings.Contains(err.Error(), "a directory on the path to it") {
			t.Fatalf("a writable ancestor must not be stamped over; got %v", err)
		}
		if !strings.Contains(err.Error(), outer) {
			t.Errorf("the refusal must name the offending directory; got %v", err)
		}
	})

	// Whoever can replace a symlink chooses which file every command reads, however
	// private the file it currently points at - and a directory above the link is as
	// good as the one holding it, so the walk runs from the link's own location too.
	t.Run("refuses a world-writable directory above a symlinked manifest", func(t *testing.T) {
		real := manifestIn(t, t.TempDir())
		links := t.TempDir()
		// The link sits one level down, so only walking up from it finds the
		// world-writable directory that lets anyone rename sub aside.
		if err := os.Mkdir(filepath.Join(links, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(links, "sub", "link.yaml")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(links, 0o777); err != nil {
			t.Fatal(err)
		}
		err := approvable(t, link)
		if err == nil || !strings.Contains(err.Error(), links) {
			t.Fatalf("a swappable symlink must not be stamped through; got %v", err)
		}
	})

	t.Run("allows a group/world-writable manifest the rewrite will clamp", func(t *testing.T) {
		dir := t.TempDir()
		path := manifestIn(t, dir)
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := approvable(t, path); err != nil {
			t.Fatalf("the mode on the manifest itself is approve's to fix; got %v", err)
		}
	})

	t.Run("allows a sticky world-writable directory", func(t *testing.T) {
		dir := t.TempDir()
		path := manifestIn(t, dir)
		if err := os.Chmod(dir, fs.ModeSticky|0o777); err != nil {
			t.Fatal(err)
		}
		if err := approvable(t, path); err != nil {
			t.Fatalf("nobody else can replace a file in a sticky directory; got %v", err)
		}
	})
}

// approve rewrites through a temporary file in the manifest's directory, so it needs
// write and search there - a permission os.WriteFile never asked for. The failure must
// say which directory and why, not surface a bare "permission denied" naming a temp file
// the user never created.
func TestWriteManifestAtomicallyExplainsAnUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only-mode directory regardless")
	}
	dir := t.TempDir()
	path := manifestIn(t, dir)
	trust := trustOf(t, path)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	// t.TempDir's own cleanup cannot remove the manifest until the mode is put back.
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Error(err)
		}
	})

	err := writeManifestAtomically(trust, []byte("entrypoint: ./y\n"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("an unwritable directory must fail the approve")
	}
	if !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "not only on the manifest") {
		t.Errorf("the error must name the directory and the permission it needs; got %v", err)
	}
}
