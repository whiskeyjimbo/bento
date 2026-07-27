package main

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
