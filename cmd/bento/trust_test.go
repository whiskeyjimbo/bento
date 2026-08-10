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

	"github.com/whiskeyjimbo/bento/trust"
)

// A directory an ACL lets a specific other user write is one they can replace the manifest
// in, so approve must refuse it - the same as a world-writable one, and for the same
// reason, however private the mode looks.
func TestApproveRefusesADirectoryAnACLOpens(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere regardless")
	}
	dir := t.TempDir()
	path := manifestIn(t, dir)
	trustSetACL(t, dir, [][3]uint32{
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
	mt, err := trust.InspectNew(link, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("trust.InspectNew: %v", err)
	}
	if err := writeManifestAtomically(mt, []byte("entrypoint: ./x\n"), io.Discard); err != nil {
		t.Fatalf("writeManifestAtomically: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("the link must survive and its target be written; lstat = %v, %v", fi, err)
	}
	if data, err := os.ReadFile(filepath.Join(real, "source.yaml")); err != nil || string(data) != "entrypoint: ./x\n" {
		t.Errorf("the link's target must hold the manifest; got %q, %v", data, err)
	}
}

// A manifest written where none was gets owner-only write, whatever the umask: the next
// command's approval stamp is worth what the file's permissions are.
func TestWriteManifestAtomicallyCreatesAPrivateManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bento.yaml")
	mt, err := trust.InspectNew(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeManifestAtomically(mt, []byte("entrypoint: ./x\n"), io.Discard); err != nil {
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
// at comes from the mt, which only an open handle can produce.
func trustOf(t *testing.T, path string) trust.Manifest {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	mt, err := trust.Inspect(f, path)
	if err != nil {
		t.Fatal(err)
	}
	return mt
}

// run and validate keep working on a permissive checkout: a second writer is reported,
// not refused, since a shared box or a loose umask is ordinary. It is reported only for a
// manifest carrying a stamp, though - the warning is about what that stamp is worth, and
// the profile-then-run inner loop runs unstamped manifests over and over.
func TestWarnStampAtRiskOnlySpeaksForAStampedManifest(t *testing.T) {
	dir := t.TempDir()
	path := manifestIn(t, dir)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	doc, mt, err := loadDocument(path)
	if err != nil {
		t.Fatalf("loadDocument: %v", err)
	}

	var warn bytes.Buffer
	warnStampAtRisk(&warn, doc, mt)
	if warn.String() != "" {
		t.Errorf("an unstamped manifest has no approval to devalue; got %q", warn.String())
	}

	doc.Provenance.Approves = doc.Policy.Fingerprint()
	warnStampAtRisk(&warn, doc, mt)
	if !strings.Contains(warn.String(), "the directory holding it") {
		t.Errorf("a world-writable directory must be reported for a stamped manifest; got %q", warn.String())
	}
}

// The kernel names a pipe or device descriptor `pipe:[N]` or /dev/null, whose directory
// is either meaningless or the process's own working directory. Parsing would succeed
// and the verdict would describe somewhere the manifest never came from, so the load
// fails instead.
func TestLoadDocumentRefusesANonRegularFile(t *testing.T) {
	_, _, err := loadDocument(os.DevNull)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a manifest with no location on disk must not load; got %v", err)
	}
}

// approvable runs the check the way approve does, on the mt from the same open that
// read the manifest.
func approvable(t *testing.T, path string) error {
	t.Helper()
	_, mt, err := loadDocument(path)
	if err != nil {
		t.Fatalf("loadDocument: %v", err)
	}
	return requireApprovableLocation(path, mt)
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

	// A setgid group-writable ancestor is the shared-project layout: the group demonstrably
	// holds other people, any of whom can rename the level below aside. Fatality for that
	// mode is decided in dirFlaws, but only the chain loop applies it above the manifest's
	// own directory, and world-writability was the only case that ever drove it end to end.
	t.Run("refuses a setgid group-writable ancestor", func(t *testing.T) {
		outer := t.TempDir()
		inner := filepath.Join(outer, "proj")
		if err := os.Mkdir(inner, 0o755); err != nil {
			t.Fatal(err)
		}
		path := manifestIn(t, inner)
		if err := os.Chmod(outer, fs.ModeSetgid|0o775); err != nil {
			t.Fatal(err)
		}
		err := approvable(t, path)
		if err == nil || !strings.Contains(err.Error(), "a directory on the path to it") {
			t.Fatalf("a shared-project ancestor must not be stamped over; got %v", err)
		}
		if !strings.Contains(err.Error(), outer) || !strings.Contains(err.Error(), "setgid") {
			t.Errorf("the refusal must name the directory and why its group write counts; got %v", err)
		}
	})

	// The same for the other flaw the mode cannot show. An ACL naming a writer on an
	// ancestor is as good as one on the manifest's own directory: the named user renames
	// the level below aside and substitutes the whole tree.
	t.Run("refuses an ancestor an ACL opens", func(t *testing.T) {
		outer := t.TempDir()
		inner := filepath.Join(outer, "proj")
		if err := os.Mkdir(inner, 0o755); err != nil {
			t.Fatal(err)
		}
		path := manifestIn(t, inner)
		trustSetACL(t, outer, [][3]uint32{
			{0x01, 7, 0xffffffff}, {0x02, 7, 65534}, {0x04, 5, 0xffffffff}, {0x10, 7, 0xffffffff}, {0x20, 5, 0xffffffff},
		})
		err := approvable(t, path)
		if err == nil || !strings.Contains(err.Error(), "a directory on the path to it") {
			t.Fatalf("an ancestor a named user can write must not be stamped over; got %v", err)
		}
		if !strings.Contains(err.Error(), outer) || !strings.Contains(err.Error(), "ACL") {
			t.Errorf("the refusal must name the directory and the ACL; got %v", err)
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
	mt := trustOf(t, path)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	// t.TempDir's own cleanup cannot remove the manifest until the mode is put back.
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Error(err)
		}
	})

	err := writeManifestAtomically(mt, []byte("entrypoint: ./y\n"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("an unwritable directory must fail the approve")
	}
	if !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "not only on the manifest") {
		t.Errorf("the error must name the directory and the permission it needs; got %v", err)
	}
}

// The same refusal driven end to end rather than from a synthesized mt, which needs a
// second uid to plant the link and so a euid that can hand one out. Everything else here is
// clean: the manifest and its directory are private and ours, and the sticky directory the
// link sits in reports no flaw of its own - the link's owner is the whole finding.
func TestApproveRefusesAForeignSymlinkInAStickyDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("planting a link owned by another user needs a uid to give it away to")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real, pub := filepath.Join(root, "real"), filepath.Join(root, "pub")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Sticky and world-writable, as /tmp is: the exemption that clears the directory itself
	// rests on nobody being able to unlink our entries, which says nothing about an entry
	// that is not ours.
	if err := os.Chmod(pub, fs.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(pub, "bento.yaml")
	if err := os.Symlink(manifestIn(t, real), link); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(link, 65534, 65534); err != nil {
		t.Fatal(err)
	}

	err = approvable(t, link)
	if err == nil || !strings.Contains(err.Error(), link) {
		t.Fatalf("a link its owner can repoint must not be stamped through; got %v", err)
	}
	if !strings.Contains(err.Error(), "repoint") {
		t.Errorf("the refusal must say what the link's owner can do with it; got %v", err)
	}
}

// setACL writes a POSIX access ACL, so the parse is exercised against what the kernel
// actually stores rather than a blob this test made up. entries are {tag, perm, id}
// triples in the order the kernel requires: USER_OBJ, USER*, GROUP_OBJ, GROUP*, MASK,
// OTHER.
func trustSetACL(t *testing.T, path string, entries [][3]uint32) {
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

func manifestIn(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "bento.yaml")
	if err := os.WriteFile(path, []byte("entrypoint: ./x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
