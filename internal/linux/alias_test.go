package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// aliasSandbox returns a sandbox whose alias seams are driven by a hypothetical
// filesystem: creds maps a walked root to the identified files under it, and matches
// maps a granted tree to the paths under it carrying a wanted content identity.
func aliasSandbox(creds map[string][]identifiedFile, matches map[string][]identifiedFile) sandbox {
	sb := testSandbox()
	sb.fileIDs = func(root string) []identifiedFile { return creds[root] }
	sb.aliasesUnder = func(root string, want map[fileID]string) []credentialAlias {
		var out []credentialAlias
		for _, f := range matches[root] {
			if cred, ok := want[f.id]; ok {
				out = append(out, credentialAlias{Path: f.path, Credential: cred})
			}
		}
		return out
	}
	sb.mountpoints = func([]string) []mountPoint { return nil }
	return sb
}

// The whole cost structure rests on one fact: a hardlink needs a second directory
// entry pointing at the credential's inode, so nlink==1 on every credential *proves*
// no hardlink alias to any of them exists anywhere on the host. When that holds, the
// granted-tree walk is provably unnecessary and must not run - this is what keeps the
// mechanism off the hot path of an ordinary run.
func TestAliasedCredentialsSkipsWalkWhenNoCredentialIsLinked(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.aws": {{path: "/home/u/.aws/credentials", id: fileID{dev: 1, ino: 10}, links: 1}},
		"/home/u/.ssh": {{path: "/home/u/.ssh/id_rsa", id: fileID{dev: 1, ino: 11}, links: 1}},
	}
	sb := aliasSandbox(creds, nil)
	walked := false
	sb.aliasesUnder = func(string, map[fileID]string) []credentialAlias {
		walked = true
		return nil
	}
	if got := aliasedCredentials(sb, []string{"/home/u/project"}, nil, nil); got != nil {
		t.Errorf("aliasedCredentials = %v, want none when no credential carries an extra link", got)
	}
	if walked {
		t.Error("the granted-tree walk ran even though nlink==1 proves no hardlink alias exists")
	}
}

// The deliverable delta over the old warning: name WHERE the alias is, and which
// credential it exposes. A credential with an extra link opens the gate; the walk over
// the granted trees then reports the matching path.
func TestAliasedCredentialsNamesTheAliasAndItsCredential(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.aws": {{path: "/home/u/.aws/credentials", id: fileID{dev: 1, ino: 10}, links: 2}},
	}
	matches := map[string][]identifiedFile{
		"/home/u/project": {{path: "/home/u/project/notes.txt", id: fileID{dev: 1, ino: 10}}},
	}
	got := aliasedCredentials(aliasSandbox(creds, matches), []string{"/home/u/project"}, nil, nil)
	want := []credentialAlias{{Path: "/home/u/project/notes.txt", Credential: "/home/u/.aws/credentials"}}
	if !slices.Equal(got, want) {
		t.Errorf("aliasedCredentials = %v, want %v", got, want)
	}
}

// A write grant is a granted tree too - an alias there is strictly worse than one in a
// read tree, since the run can rewrite the credential through it.
func TestAliasedCredentialsCoversWriteGrants(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.ssh": {{path: "/home/u/.ssh/id_rsa", id: fileID{dev: 1, ino: 11}, links: 2}},
	}
	matches := map[string][]identifiedFile{
		"/home/u/build": {{path: "/home/u/build/key", id: fileID{dev: 1, ino: 11}}},
	}
	got := aliasedCredentials(aliasSandbox(creds, matches), nil, []string{"/home/u/build"}, nil)
	want := []credentialAlias{{Path: "/home/u/build/key", Credential: "/home/u/.ssh/id_rsa"}}
	if !slices.Equal(got, want) {
		t.Errorf("write grants must be walked too; got %v want %v", got, want)
	}
}

// The credential itself is not an alias of itself. A grant that contains the credential
// path (read: ~) walks over the shielded file, whose identity is by definition in the
// wanted set - reporting it would refuse every broad-home run for no reason. The shield
// covers that path; only a SECOND path is the leak.
func TestAliasedCredentialsIgnoresTheShieldedPathItself(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.aws": {{path: "/home/u/.aws/credentials", id: fileID{dev: 1, ino: 10}, links: 2}},
	}
	matches := map[string][]identifiedFile{
		"/home/u": {
			{path: "/home/u/.aws/credentials", id: fileID{dev: 1, ino: 10}}, // the shielded path
			{path: "/home/u/copy", id: fileID{dev: 1, ino: 10}},             // the actual alias
		},
	}
	got := aliasedCredentials(aliasSandbox(creds, matches), []string{"/home/u"}, nil, nil)
	want := []credentialAlias{{Path: "/home/u/copy", Credential: "/home/u/.aws/credentials"}}
	if !slices.Equal(got, want) {
		t.Errorf("the shielded path is not its own alias; got %v want %v", got, want)
	}
}

// An explicit opt-in means the user deliberately handed the sandbox that credential
// store, so its shield never engages and its content is exposed on purpose. An alias to
// it is not a leak past a shield - there is no shield - and refusing on it would break
// the opt-in it was granted under.
func TestAliasedCredentialsDropsOptedInCredentials(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.aws": {{path: "/home/u/.aws/credentials", id: fileID{dev: 1, ino: 10}, links: 2}},
		"/home/u/.ssh": {{path: "/home/u/.ssh/id_rsa", id: fileID{dev: 1, ino: 11}, links: 2}},
	}
	matches := map[string][]identifiedFile{
		"/home/u/project": {
			{path: "/home/u/project/a", id: fileID{dev: 1, ino: 10}},
			{path: "/home/u/project/b", id: fileID{dev: 1, ino: 11}},
		},
	}
	sb := aliasSandbox(creds, matches)
	got := aliasedCredentials(sb, []string{"/home/u/project"}, nil, []string{"/home/u/.aws"})
	want := []credentialAlias{{Path: "/home/u/project/b", Credential: "/home/u/.ssh/id_rsa"}}
	if !slices.Equal(got, want) {
		t.Errorf("an opted-in credential has no shield to leak past; got %v want %v", got, want)
	}
}

// A bind alias shares the credential's (dev, inode) but does NOT bump its link count,
// so the nlink gate correctly skips the walk and would miss it entirely. The mountinfo
// scan is the second mechanism that covers exactly that case, at O(mounts).
func TestAliasedCredentialsFindsBindAliasWithoutTheWalk(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.aws": {{path: "/home/u/.aws/credentials", id: fileID{dev: 1, ino: 10}, links: 1}},
	}
	matches := map[string][]identifiedFile{
		"/home/u/project/creds": {{path: "/home/u/project/creds", id: fileID{dev: 1, ino: 10}}},
	}
	sb := aliasSandbox(creds, matches)
	sb.mountpoints = func([]string) []mountPoint {
		return []mountPoint{
			{path: "/home/u/project/creds", id: fileID{dev: 1, ino: 10}}, // the bind of the credential
			{path: "/home/u/project/cache", id: fileID{dev: 9, ino: 99}}, // unrelated, foreign device
			{path: "/mnt/elsewhere", id: fileID{dev: 1, ino: 11}},        // wanted device, outside every grant
		}
	}
	got := aliasedCredentials(sb, []string{"/home/u/project"}, nil, nil)
	want := []credentialAlias{{Path: "/home/u/project/creds", Credential: "/home/u/.aws/credentials"}}
	if !slices.Equal(got, want) {
		t.Errorf("a bind alias bumps no link count and must be caught from mountinfo; got %v want %v", got, want)
	}
}

// A bind of a credential's parent DIRECTORY exposes every file under it, so the
// mountpoint-relative path of the credential is the alias, not the mountpoint itself.
func TestAliasedCredentialsMapsDirectoryBindToTheCredentialPath(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.aws": {{path: "/home/u/.aws/credentials", id: fileID{dev: 1, ino: 10}, links: 1}},
	}
	matches := map[string][]identifiedFile{
		"/home/u/project/vendor": {{path: "/home/u/project/vendor/credentials", id: fileID{dev: 1, ino: 10}}},
	}
	sb := aliasSandbox(creds, matches)
	sb.mountpoints = func([]string) []mountPoint {
		return []mountPoint{{path: "/home/u/project/vendor", id: fileID{dev: 1, ino: 10}}}
	}
	got := aliasedCredentials(sb, []string{"/home/u/project"}, nil, nil)
	want := []credentialAlias{{Path: "/home/u/project/vendor/credentials", Credential: "/home/u/.aws/credentials"}}
	if !slices.Equal(got, want) {
		t.Errorf("a directory bind aliases each credential under it; got %v want %v", got, want)
	}
}

// On a host where $HOME sits behind a symlink (/home -> /var/home on Silverblue), the
// deny-list paths resolve but the grants arrive as written. Both sides must be resolved
// before they are compared, or the containment tests match nothing and the whole
// mechanism silently no-ops - the worst possible failure for a refusal.
func TestAliasedCredentialsResolvesBothSidesBeforeComparing(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/var/home/u/.aws": {{path: "/var/home/u/.aws/credentials", id: fileID{dev: 1, ino: 10}, links: 2}},
	}
	matches := map[string][]identifiedFile{
		"/var/home/u/project": {{path: "/var/home/u/project/copy", id: fileID{dev: 1, ino: 10}}},
	}
	sb := aliasSandbox(creds, matches)
	sb.resolve = func(p string) string { return strings.Replace(p, "/home/u", "/var/home/u", 1) }
	got := aliasedCredentials(sb, []string{"/home/u/project"}, nil, nil)
	want := []credentialAlias{{Path: "/var/home/u/project/copy", Credential: "/var/home/u/.aws/credentials"}}
	if !slices.Equal(got, want) {
		t.Errorf("grants and deny paths must be compared resolved; got %v want %v", got, want)
	}
}

// The real-filesystem walk: a hardlink to a credential planted inside a granted tree is
// found and named, a plain unrelated file is not, and a file whose content merely
// matches byte-for-byte (an independent inode) is not - inode identity is the test, and
// this is the positive control that keeps a green result from being vacuous.
func TestHostAliasesUnderFindsHardlinkNotCopy(t *testing.T) {
	dir := t.TempDir()
	cred := filepath.Join(dir, "credentials")
	if err := os.WriteFile(cred, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(dir, "project")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(tree, "notes.txt")
	if err := os.Link(cred, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "copy.txt"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	ids := hostFileIDs(cred)
	if len(ids) != 1 || ids[0].links != 2 {
		t.Fatalf("hostFileIDs(%q) = %+v, want one file with 2 links", cred, ids)
	}
	want := map[fileID]string{ids[0].id: cred}
	got := hostAliasesUnder(tree, want)
	if len(got) != 1 || got[0].Path != alias || got[0].Credential != cred {
		t.Errorf("hostAliasesUnder = %+v, want just the hardlink %q (a byte-identical copy has its own inode)", got, alias)
	}
}

// The refusal has to name both ends - the granted path that reaches the content and the
// credential it reaches - because the alias is host-made, so the user is the only one
// who can remove it. A refusal that says only "an alias exists" leaves nothing to act on.
func TestAliasRefusalNamesBothEnds(t *testing.T) {
	err := aliasRefusal([]credentialAlias{
		{Path: "/home/u/project/notes.txt", Credential: "/home/u/.aws/credentials"},
	})
	for _, want := range []string{"/home/u/project/notes.txt", "/home/u/.aws/credentials", "shielded credential"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q must mention %q", err, want)
		}
	}
}

// A credential store kept in git hardlinks every object into a `git clone --local`, so
// anchoring identity on those blobs would refuse a run merely because a clone of the
// store sits in a granted tree. The store stays shielded either way; the live credential
// files outside .git are what anchor the scan. Without this the common ~/.password-store
// layout turns a security refusal into a false alarm whose only escape is exposing the
// whole store.
func TestCredentialFilesSkipsGitObjectStore(t *testing.T) {
	home := t.TempDir()
	store := filepath.Join(home, ".password-store")
	objects := filepath.Join(store, ".git", "objects", "ab")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(objects, "cdef")
	if err := os.WriteFile(blob, []byte("packed"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The extra link a local clone would leave behind.
	if err := os.Link(blob, filepath.Join(home, "clone-object")); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(store, "email.gpg")
	if err := os.WriteFile(live, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	sb := testSandbox()
	sb.home = home
	sb.resolve = func(p string) string { return p }
	sb.fileIDs = hostFileIDs

	files, linked := credentialFiles(sb, nil)
	if linked {
		t.Error("a hardlinked git object must not open the gate; only live credential files anchor it")
	}
	if !slices.ContainsFunc(files, func(f identifiedFile) bool { return f.path == live }) {
		t.Errorf("the live credential %q must still be in the set; got %+v", live, files)
	}
	if slices.ContainsFunc(files, func(f identifiedFile) bool { return f.path == blob }) {
		t.Errorf("the git object %q must not be in the credential set", blob)
	}
}

// The granted tree's own device says nothing about what is under it. Pruning by device
// at the walk root hands fs.SkipDir to WalkDir before it descends anywhere, ending the
// entire walk - so a "read: /" run on a host with /home on its own partition would find
// no alias in a home full of them, and silently admit what this mechanism exists to
// refuse. /dev (devtmpfs) and /dev/shm (tmpfs) are different devices on any Linux host,
// which makes the boundary reproducible without mounting anything.
func TestHostAliasesUnderCrossesADeviceBoundaryAtTheRoot(t *testing.T) {
	cred := "/dev/shm/bento_boundary_cred"
	alias := "/dev/shm/bento_boundary_alias"
	if err := os.WriteFile(cred, []byte("SECRET"), 0o600); err != nil {
		t.Skipf("no writable /dev/shm: %v", err)
	}
	t.Cleanup(func() { os.Remove(cred) })
	os.Remove(alias)
	if err := os.Link(cred, alias); err != nil {
		t.Skipf("no hardlink support: %v", err)
	}
	t.Cleanup(func() { os.Remove(alias) })

	ids := hostFileIDs(cred)
	if len(ids) != 1 {
		t.Fatalf("hostFileIDs(%q) = %+v, want one file", cred, ids)
	}
	if devOf(t, "/dev") == ids[0].id.dev {
		t.Skip("/dev and /dev/shm share a device on this host; no boundary to cross")
	}

	want := map[fileID]string{ids[0].id: cred}
	got := hostAliasesUnder("/dev", want)
	if !slices.ContainsFunc(got, func(a credentialAlias) bool { return a.Path == alias }) {
		t.Errorf("walking /dev must reach the alias at %q on the /dev/shm device; got %+v", alias, got)
	}
}

func devOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no Stat_t for %q", path)
	}
	return uint64(st.Dev)
}

// Bulk stores are shielded exactly as hard as credential stores, but they must not
// IDENTIFY a credential. A maildir holds tens of thousands of files and mail sync tools
// (mbsync, notmuch) hardlink duplicate messages as a matter of course - so anchoring on
// one would both enumerate a whole mail spool on every launch and latch the nlink gate
// permanently open, making every run pay the granted-tree walk and letting a duplicate
// message refuse a run as though it were a leaked key.
func TestCredentialFilesDoesNotAnchorOnBulkStores(t *testing.T) {
	home := t.TempDir()
	mail := filepath.Join(home, ".mail", "INBOX", "cur")
	if err := os.MkdirAll(mail, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		msg := filepath.Join(mail, fmt.Sprintf("msg%d", i))
		if err := os.WriteFile(msg, []byte("m"), 0o600); err != nil {
			t.Fatal(err)
		}
		// The duplicate-message hardlinks mbsync leaves behind.
		if err := os.Link(msg, filepath.Join(mail, fmt.Sprintf("dup%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, ".ssh", "id_rsa")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	sb := testSandbox()
	sb.home = home
	sb.resolve = func(p string) string { return p }
	sb.fileIDs = hostFileIDs

	files, linked := credentialFiles(sb, nil)
	if linked {
		t.Error("hardlinked maildir duplicates must not open the nlink gate")
	}
	got := make([]string, 0, len(files))
	for _, f := range files {
		got = append(got, f.path)
	}
	if !slices.Equal(got, []string{key}) {
		t.Errorf("only key-bearing stores anchor the scan; got %v, want just %q", got, key)
	}
}

// The mechanism's entire product is a refusal, so the wiring is the one place a silent
// no-op could hide: drop the check from Run and every unit test above still passes while
// the sandbox happily launches over an exposed credential. This drives a real Enforcer
// against a real home with a real hardlink and asserts the run never starts.
func TestRunRefusesAnAliasedCredential(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not installed")
	}
	// newSandbox takes the home the deny-list anchors on from os.UserHomeDir, i.e. $HOME.
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "id_rsa")
	if err := os.WriteFile(key, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(project, "notes.txt")
	if err := os.Link(key, alias); err != nil {
		t.Skipf("no hardlink support: %v", err)
	}
	entrypoint := filepath.Join(project, "run.sh")
	if err := os.WriteFile(entrypoint, []byte("#!/bin/sh\necho ran\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: entrypoint, Interpreter: "/bin/sh", Read: []string{project}}
	proc := enforce.Process{Env: map[string]string{"HOME": home}}

	_, err := New().Run(context.Background(), p, proc, nil, false)
	if err == nil {
		t.Fatal("Run admitted a policy whose granted tree holds a hardlink to a shielded credential")
	}
	for _, want := range []string{alias, key} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q must name %q", err, want)
		}
	}
}
