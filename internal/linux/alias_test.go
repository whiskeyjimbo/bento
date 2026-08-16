//go:build linux

package linux

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
)

// aliasSandbox returns a sandbox whose alias seams are driven by a hypothetical
// filesystem: creds maps a walked root to the identified files under it, and matches
// maps a granted tree to the paths under it carrying a wanted content identity.
func aliasSandbox(creds map[string][]identifiedFile, matches map[string][]identifiedFile) sandbox {
	sb := testSandbox()
	sb.fileIDs = func(root string) ([]identifiedFile, error) { return creds[root], nil }
	sb.aliasesUnder = func(root string, want map[fileID]string) ([]credentialAlias, error) {
		var out []credentialAlias
		for _, f := range matches[root] {
			if cred, ok := want[f.id]; ok {
				out = append(out, credentialAlias{Path: f.path, Credential: cred})
			}
		}
		return out, nil
	}
	sb.mountpoints = func([]uint64) ([]mountPoint, error) { return nil, nil }
	sb.statID = func(string) (fileID, bool) { return fileID{}, false }
	return sb
}

// mustFileIDs and mustAliasesUnder drive the real host walks in the tests that exercise
// them against a temp tree, where an error is the test's own setup failing.
func mustFileIDs(t *testing.T, path string) []identifiedFile {
	t.Helper()
	ids, err := hostFileIDs(path)
	if err != nil {
		t.Fatalf("hostFileIDs(%q): %v", path, err)
	}
	return ids
}

func mustAliasesUnder(t *testing.T, root string, want map[fileID]string) []credentialAlias {
	t.Helper()
	got, err := hostAliasesUnder(root, want)
	if err != nil {
		t.Fatalf("hostAliasesUnder(%q): %v", root, err)
	}
	return got
}

// scanAliases runs the scan and fails the test on an error, so the cases that only care
// about what was found read the way they did before an unreadable mount table became a
// refusal rather than an empty result.
func scanAliases(t *testing.T, sb sandbox, trees, optIns []string) []credentialAlias {
	t.Helper()
	scan, err := aliasedCredentials(sb, trees, optIns)
	if err != nil {
		t.Fatalf("aliasedCredentials: %v", err)
	}
	return scan.found
}

// scanOf builds the scan value the split takes. The credential set is spelled out by
// each caller rather than derived from found, because deriving it is exactly the bug
// the guard was fixed for: what the host shields does not depend on what this run
// aliased, and a helper that tied the two together would quietly weaken every test
// written with it.
func scanOf(credentials []string, found ...credentialAlias) aliasScan {
	return aliasScan{found: found, credentials: credentials}
}

// shieldedStores is what the host in these cases shields. It deliberately holds more
// than any single case's aliases name: the guard's whole point is that a tree is judged
// against every store, so a fixture where the two coincided would prove nothing. It mixes
// anchor directories with the files behind them because that is what aliasedCredentials
// hands over - a fixture of files alone would stop exercising the shipped shape.
var shieldedStores = []string{"/home/u/.ssh", "/home/u/.ssh/id_rsa", "/home/u/.aws", "/home/u/.aws/credentials"}

// The same set on a host whose home sits behind a symlink; the scan resolves before it
// compares, so this is the form the guard actually meets there.
var relocatedShieldedStores = []string{"/var/home/u/.ssh", "/var/home/u/.ssh/id_rsa", "/var/home/u/.aws", "/var/home/u/.aws/credentials"}

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
	sb.aliasesUnder = func(string, map[fileID]string) ([]credentialAlias, error) {
		walked = true
		return nil, nil
	}
	if got := scanAliases(t, sb, []string{"/home/u/project"}, nil); got != nil {
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
	got := scanAliases(t, aliasSandbox(creds, matches), []string{"/home/u/project"}, nil)
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
	got := scanAliases(t, aliasSandbox(creds, matches), []string{"/home/u/build"}, nil)
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
	got := scanAliases(t, aliasSandbox(creds, matches), []string{"/home/u"}, nil)
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
	got := scanAliases(t, sb, []string{"/home/u/project"}, []string{"/home/u/.aws"})
	want := []credentialAlias{{Path: "/home/u/project/b", Credential: "/home/u/.ssh/id_rsa"}}
	if !slices.Equal(got, want) {
		t.Errorf("an opted-in credential has no shield to leak past; got %v want %v", got, want)
	}
}

// The opt-in set arrives as the literal deny-list paths, while the credential roots are
// resolved. On a host where a store sits behind a symlink the two forms differ, and an
// unresolved comparison would refuse a run over a store the policy explicitly opted into.
func TestAliasedCredentialsResolvesTheOptInBeforeMatching(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/data/aws": {{path: "/data/aws/credentials", id: fileID{dev: 1, ino: 10}, links: 2}},
	}
	matches := map[string][]identifiedFile{
		"/home/u/project": {{path: "/home/u/project/a", id: fileID{dev: 1, ino: 10}}},
	}
	sb := aliasSandbox(creds, matches)
	sb.resolve = func(p string) string {
		if p == "/home/u/.aws" {
			return "/data/aws"
		}
		return p
	}
	if got := scanAliases(t, sb, []string{"/home/u/project"}, []string{"/home/u/.aws"}); got != nil {
		t.Errorf("a symlinked store opted in by its literal path has no shield to leak past; got %v", got)
	}
}

// A bind alias shares the credential's (dev, inode) but does NOT bump its link count,
// so the nlink gate correctly skips the walk and would miss it entirely. The mountinfo
// scan is the second mechanism that covers exactly that case, at O(mounts).
func TestAliasedCredentialsFindsBindAliasWithoutTheWalk(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.aws": {{path: "/home/u/.aws/credentials", id: fileID{dev: 1, ino: 10}, links: 1}},
	}
	sb := aliasSandbox(creds, nil)
	sb.statID = func(p string) (fileID, bool) {
		if p == "/home/u/.aws/credentials" {
			return fileID{dev: 1, ino: 10}, true
		}
		return fileID{}, false
	}
	sb.mountpoints = func([]uint64) ([]mountPoint, error) {
		return []mountPoint{
			{path: "/home/u/project/creds", id: fileID{dev: 1, ino: 10}}, // the bind of the credential
			{path: "/home/u/project/cache", id: fileID{dev: 9, ino: 99}}, // unrelated, foreign device
			{path: "/mnt/elsewhere", id: fileID{dev: 1, ino: 10}},        // same bind, outside every grant
		}, nil
	}
	got := scanAliases(t, sb, []string{"/home/u/project"}, nil)
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
	sb := aliasSandbox(creds, nil)
	// The bind is of the credential's parent directory, so the mount matches that
	// ancestor and the credential's remaining path rides along onto the mountpoint.
	sb.statID = func(p string) (fileID, bool) {
		if p == "/home/u/.aws" {
			return fileID{dev: 1, ino: 7}, true
		}
		return fileID{}, false
	}
	sb.mountpoints = func([]uint64) ([]mountPoint, error) {
		return []mountPoint{{path: "/home/u/project/vendor", id: fileID{dev: 1, ino: 7}}}, nil
	}
	got := scanAliases(t, sb, []string{"/home/u/project"}, nil)
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
	got := scanAliases(t, sb, []string{"/home/u/project"}, nil)
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

	ids := mustFileIDs(t, cred)
	if len(ids) != 1 || ids[0].links != 2 {
		t.Fatalf("hostFileIDs(%q) = %+v, want one file with 2 links", cred, ids)
	}
	want := map[fileID]string{ids[0].id: cred}
	got := mustAliasesUnder(t, tree, want)
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
	}, []string{"/home/u/.aws/credentials"})
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
	sb.homes = []string{home}
	sb.resolve = func(p string) string { return p }
	sb.fileIDs = hostFileIDs

	files, _, linked, credErr := credentialFiles(sb, nil)
	if credErr != nil {
		t.Fatal(credErr)
	}
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
	stem := fmt.Sprintf("/dev/shm/bento_boundary_%d", os.Getpid())
	cred, alias := stem+"_cred", stem+"_alias"
	if err := os.WriteFile(cred, []byte("SECRET"), 0o600); err != nil {
		t.Skipf("no writable /dev/shm: %v", err)
	}
	t.Cleanup(func() { os.Remove(cred) })
	os.Remove(alias)
	if err := os.Link(cred, alias); err != nil {
		t.Skipf("no hardlink support: %v", err)
	}
	t.Cleanup(func() { os.Remove(alias) })

	ids := mustFileIDs(t, cred)
	if len(ids) != 1 {
		t.Fatalf("hostFileIDs(%q) = %+v, want one file", cred, ids)
	}
	if devOf(t, "/dev") == ids[0].id.dev {
		t.Skip("/dev and /dev/shm share a device on this host; no boundary to cross")
	}

	want := map[fileID]string{ids[0].id: cred}
	got := mustAliasesUnder(t, "/dev", want)
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
	sb.homes = []string{home}
	sb.resolve = func(p string) string { return p }
	sb.fileIDs = hostFileIDs

	files, _, linked, credErr := credentialFiles(sb, nil)
	if credErr != nil {
		t.Fatal(credErr)
	}
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
		skipMissingDep(t, "bwrap not installed")
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

	_, err := New().Run(context.Background(), p, proc, enforce.RunOptions{})
	if err == nil {
		t.Fatal("Run admitted a policy whose granted tree holds a hardlink to a shielded credential")
	}
	for _, want := range []string{alias, key} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q must name %q", err, want)
		}
	}
}

// A bind whose mountpoint sits ABOVE the granted tree is the case path arithmetic loses
// and the one that leaks most: bind the whole home to /srv/backup, grant
// "read: /srv/backup/.ssh", and the key is reachable through a path that names no
// credential bento shields. The mountpoint is not inside the grant, so a containment
// filter drops it; a bind adds no directory entry, so the hardlink gate never opens and no
// walk happens. Only matching the mount against the credential's ancestors finds it.
func TestAliasedCredentialsFindsABindMountedAboveTheGrant(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.ssh": {{path: "/home/u/.ssh/id_rsa", id: fileID{dev: 1, ino: 11}, links: 1}},
	}
	sb := aliasSandbox(creds, nil)
	sb.statID = func(p string) (fileID, bool) {
		if p == "/home/u" {
			return fileID{dev: 1, ino: 2}, true
		}
		return fileID{}, false
	}
	sb.mountpoints = func([]uint64) ([]mountPoint, error) {
		return []mountPoint{{path: "/srv/backup", id: fileID{dev: 1, ino: 2}}}, nil
	}

	got := scanAliases(t, sb, []string{"/srv/backup/.ssh"}, nil)
	want := []credentialAlias{{Path: "/srv/backup/.ssh/id_rsa", Credential: "/home/u/.ssh/id_rsa"}}
	if !slices.Equal(got, want) {
		t.Errorf("a bind above the grant must still be found; got %v want %v", got, want)
	}
}

// A caller's own deny is a directory rule at a path denylist.AliasAnchors - a list of
// home-relative names - can never contain, so selecting alias roots by shape alone gave an
// embedder's DenyPaths zero alias coverage: a pre-existing hardlink out of it into a
// granted tree was admitted, where the same shape over a built-in store is refused.
func TestAliasedCredentialsScansACallerDeniedDirectory(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/srv/secrets": {{path: "/srv/secrets/key", id: fileID{dev: 1, ino: 20}, links: 2}},
	}
	matches := map[string][]identifiedFile{
		"/home/u/proj": {{path: "/home/u/proj/notes.txt", id: fileID{dev: 1, ino: 20}}},
	}
	sb := aliasSandbox(creds, matches)
	sb.extraDeny = []denylist.Rule{{Path: "/srv/secrets", Deny: denylist.DenyAll, Dir: true}}

	got := scanAliases(t, sb, []string{"/home/u/proj"}, nil)
	want := []credentialAlias{{Path: "/home/u/proj/notes.txt", Credential: "/srv/secrets/key"}}
	if !slices.Equal(got, want) {
		t.Errorf("a hardlink out of a caller's denied directory must be reported; got %v want %v", got, want)
	}
}

// The other half of the same omission: the symlinked-credential expansion takes the kind of
// the LINK'S TARGET, so a store entry pointing at a directory in a dotfile farm (what stow
// and chezmoi produce for ~/.gnupg/private-keys-v1.d) emits a Dir rule where a file entry
// emits a file rule. Nothing else reaches the farm copy - hostFileIDs walks the anchor
// without following symlinks - so dropping the directory rule left the keys unscanned.
func TestAliasedCredentialsScansADirectoryValuedCredentialLink(t *testing.T) {
	const (
		store = "/home/u/.gnupg"
		link  = store + "/private-keys-v1.d"
		farm  = "/home/u/dotfiles/gnupg/private-keys-v1.d"
	)
	creds := map[string][]identifiedFile{
		farm: {{path: farm + "/key.key", id: fileID{dev: 1, ino: 21}, links: 2}},
	}
	matches := map[string][]identifiedFile{
		"/home/u/proj": {{path: "/home/u/proj/notes.txt", id: fileID{dev: 1, ino: 21}}},
	}
	sb := aliasSandbox(creds, matches)
	sb.listDir = func(p string) (names, links []string, ok bool) {
		if p == store {
			return nil, []string{filepath.Base(link)}, true
		}
		return nil, nil, p == farm
	}
	sb.isDir = func(p string) bool { return p == store || p == farm || p == "/home/u" }
	sb.resolve = func(p string) string {
		if p == link {
			return farm
		}
		return p
	}

	got := scanAliases(t, sb, []string{"/home/u/proj"}, nil)
	want := []credentialAlias{{Path: "/home/u/proj/notes.txt", Credential: farm + "/key.key"}}
	if !slices.Equal(got, want) {
		t.Errorf("a directory-valued credential link must be scanned; got %v want %v", got, want)
	}
}

// The counterpart that keeps the mechanism affordable: an ordinary, non-bind mount matches
// the credential's own ancestor at that same path, so the alias it computes IS the
// credential and drops out. Without this the root filesystem's own mount would report every
// credential as aliased - and refuse every run on every host.
func TestAliasedCredentialsIgnoresAnOrdinaryMount(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.ssh": {{path: "/home/u/.ssh/id_rsa", id: fileID{dev: 1, ino: 11}, links: 1}},
	}
	sb := aliasSandbox(creds, nil)
	sb.statID = func(p string) (fileID, bool) {
		if p == "/" {
			return fileID{dev: 1, ino: 2}, true
		}
		return fileID{}, false
	}
	sb.mountpoints = func([]uint64) ([]mountPoint, error) {
		return []mountPoint{{path: "/", id: fileID{dev: 1, ino: 2}}}, nil
	}

	// The grant contains the credential, so the computed path lands inside a granted tree
	// and only the "this is the credential itself" guard can reject it. Granting a sibling
	// would let the containment filter pass the test without that guard working.
	if got := scanAliases(t, sb, []string{"/home/u"}, nil); got != nil {
		t.Errorf("the root mount names the credential's own path, not an alias; got %v", got)
	}
}

// The device filter is what keeps the mount scan from touching a filesystem no credential
// lives on - which is not an optimization but the defense against blocking forever on an
// lstat of a dead hard-mounted NFS export. Nothing else pins it: hostMountpoints reads
// /proc directly, so without a seam on the parse the filter can be deleted with every
// test still green.
func TestMountinfoPathsFiltersByDevice(t *testing.T) {
	// Real mountinfo shape, including an nsfs line whose source is not a path at all.
	const info = `25 30 0:23 / /proc rw,nosuid - proc proc rw
26 30 8:2 / / rw,relatime - ext4 /dev/sda2 rw
27 30 8:2 /home/u/.ssh /srv/backup/.ssh rw,relatime - ext4 /dev/sda2 rw
28 30 0:44 mnt:[4026532372] /run/snapd/ns/x.mnt rw - nsfs nsfs rw
29 30 0:99 / /mnt/dead-nfs rw - nfs4 srv:/export rw
30 30 8:2 / /home/u/with\040space rw,relatime - ext4 /dev/sda2 rw`

	// Device 8:2 is where the credentials live.
	dev := uint64(unix.Mkdev(8, 2))
	got, _, err := mountinfoPaths(strings.NewReader(info), []uint64{dev})
	if err != nil {
		t.Fatalf("mountinfoPaths: %v", err)
	}
	want := []string{"/", "/srv/backup/.ssh", "/home/u/with space"}
	if !slices.Equal(got, want) {
		t.Errorf("mountinfoPaths = %v, want %v (only device 8:2, escapes decoded)", got, want)
	}
	for _, p := range got {
		if p == "/mnt/dead-nfs" {
			t.Error("a mount on another device must never be returned - it would be lstat'd and could hang forever")
		}
	}
}

// The decoder's edge arms, which the mountinfo table above does not reach: a backslash
// that is not an octal escape, and one at the very end of a mountpoint. Both must come
// back as the bytes the kernel wrote. The mount half of the alias scan turns entirely on
// the decoded mountpoint comparing byte-equal to a host path, and a decoder that drops or
// mangles a byte silently LOSES the bind detection rather than failing - the exact shape
// hostMountpoints' doc says the scan must never produce.
func TestUnescapeMountLeavesNonEscapesAlone(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/mnt/plain", "/mnt/plain"},
		{`/mnt/My\040Backup`, "/mnt/My Backup"},
		{`/mnt/a\040b\011c`, "/mnt/a b\tc"},
		// \ is not one of the four escapes the kernel writes, and 8 is not an octal
		// digit: both stay literal rather than eating the bytes after them.
		{`/mnt/back\\slash`, `/mnt/back\\slash`},
		{`/mnt/x\888y`, `/mnt/x\888y`},
		// A truncated escape at the end of the string: the decoder must not read past it.
		{`/mnt/trail\04`, `/mnt/trail\04`},
		{`/mnt/trail\`, `/mnt/trail\`},
	} {
		if got := unescapeMount(tc.in); got != tc.want {
			t.Errorf("unescapeMount(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A mountinfo line past the Scanner's buffer stops the scan early. Reporting that as an
// error is what keeps a partial mount list from being read as the whole one.
func TestMountinfoPathsRefusesATruncatedScan(t *testing.T) {
	dev := uint64(unix.Mkdev(8, 2))
	huge := "26 30 8:2 / /" + strings.Repeat("a", 1<<20) + " rw - ext4 /dev/sda2 rw\n"
	if _, _, err := mountinfoPaths(strings.NewReader(huge), []uint64{dev}); !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("mountinfoPaths on an over-long line = %v, want bufio.ErrTooLong", err)
	}
}

// A full-node wallet client's keys sit in a named location inside a data directory that
// is shielded whole - the chain data around them is far too large to enumerate. That
// makes the anchor a path the deny list has no rule for, so selecting rules by
// anchorhood skips the shielded parent as "not an anchor" and never reaches the keys.
// Both layouts are covered: modern Bitcoin Core keeps wallets under wallets/, and a host
// upgraded from before 0.16 still has wallet.dat at the top of the data directory.
func TestCredentialFilesReachesAnchorsNestedInABulkStore(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(home, ".bitcoin")
	if err := os.MkdirAll(filepath.Join(data, "blocks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(data, "wallets"), 0o700); err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(data, "blocks", "blk00000.dat")
	if err := os.WriteFile(chain, []byte("CHAIN"), 0o600); err != nil {
		t.Fatal(err)
	}
	modern := filepath.Join(data, "wallets", "wallet.dat")
	legacy := filepath.Join(data, "wallet.dat")
	for _, w := range []string{modern, legacy} {
		if err := os.WriteFile(w, []byte("SPENDING KEYS"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The extra name a host actor would have to create for either to leak.
	if err := os.Link(legacy, filepath.Join(home, "backup.dat")); err != nil {
		t.Skipf("no hardlink support: %v", err)
	}

	sb := testSandbox()
	sb.homes = []string{home}
	sb.resolve = func(p string) string { return p }
	sb.fileIDs = hostFileIDs

	files, _, linked, credErr := credentialFiles(sb, nil)
	if credErr != nil {
		t.Fatal(credErr)
	}
	got := make([]string, 0, len(files))
	for _, f := range files {
		got = append(got, f.path)
	}
	if !linked {
		t.Error("a hardlinked wallet must open the gate; the wallet anchors are unreachable if it does not")
	}
	for _, w := range []string{modern, legacy} {
		if !slices.Contains(got, w) {
			t.Errorf("wallet %q must be anchored; got %v", w, got)
		}
	}
	if slices.Contains(got, chain) {
		t.Errorf("chain data %q must not be anchored - that is the walk the narrowing exists to avoid", chain)
	}
}

// Every other bind test drives fakes. This one drives the real thing: a real bind mount,
// the real /proc/self/mountinfo, real stats. It is the only check that the bind half of
// the scan works at all rather than merely agreeing with a hand-written mount table - and
// the bind half is the half the hardlink gate cannot cover, since a bind adds no
// directory entry and so never opens the gate.
//
// A bind needs a mount namespace, so the test re-execs itself under unshare and reports
// the result back through stdout.
func TestRealBindAliasIsFound(t *testing.T) {
	const marker, reached = "BIND_ALIAS_FOUND", "BIND_TEST_REACHED_SCAN"
	// Fixed paths: the bind is established by the outer process and must be at the same
	// place inside, and the namespace is private so nothing here escapes it.
	const bindHome, bindBackup = "/tmp/bento-bindtest-home", "/tmp/bento-bindtest-backup"
	if os.Getenv("BENTO_BIND_INNER") == "" {
		exe, err := os.Executable()
		if err != nil {
			t.Skip(err)
		}
		// The outer process creates the content; bwrap only binds it.
		if err := os.MkdirAll(filepath.Join(bindHome, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(bindBackup, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bindHome, ".ssh", "id_rsa"), []byte("PRIVATE KEY"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(bindHome); os.RemoveAll(bindBackup) })
		if _, err := exec.LookPath("bwrap"); err != nil {
			skipMissingDep(t, "bwrap not installed")
		}
		// bwrap gives the mount namespace and establishes the bind in one step; the
		// binary under test then sees it in its own /proc/self/mountinfo.
		cmd := exec.Command("bwrap", "--dev-bind", "/", "/",
			"--bind", bindHome, bindBackup,
			exe, "-test.run", "TestRealBindAliasIsFound", "-test.v")
		cmd.Env = append(os.Environ(), "BENTO_BIND_INNER=1")
		out, _ := cmd.CombinedOutput()
		// A failing inner run also exits non-zero, so the exit status cannot distinguish
		// "this host has no user namespace" from "the scan missed the alias". The inner
		// run says when it got far enough to be meaningful; only its silence is a skip.
		if !strings.Contains(string(out), reached) {
			t.Skipf("no usable user namespace here:\n%s", out)
		}
		if !strings.Contains(string(out), marker) {
			t.Errorf("the real bind alias was not found by the real scan:\n%s", out)
		}
		return
	}

	home, backup := bindHome, bindBackup
	key := filepath.Join(home, ".ssh", "id_rsa")

	sb := sandbox{homes: []string{home}, resolve: hostResolve, fileIDs: hostFileIDs,
		isDir: hostIsDir, listDir: hostListDir,
		aliasesUnder: hostAliasesUnder, mountpoints: hostMountpoints, statID: hostStatIDOK}
	t.Log(reached)

	// The grant names the backup, which mentions no credential path at all - and the key
	// has a single link, so the hardlink gate stays shut and only the mount scan can see it.
	got := scanAliases(t, sb, []string{backup}, nil)
	want := credentialAlias{Path: filepath.Join(backup, ".ssh/id_rsa"), Credential: key}
	if !slices.Contains(got, want) {
		t.Fatalf("real bind scan = %+v, want it to contain %+v", got, want)
	}
	t.Log(marker)
}

// A credential store that has been relocated out of $HOME is still a credential store.
// Both ends of the deny list already follow relocation - AliasAnchors expands an
// XDG-relative anchor to the relocated base, and the hidden file rules follow the
// documented env vars - so scoping the scan to $HOME would shield those at their own
// path while quietly excusing them from alias detection, which is the failure the whole
// mechanism exists to prevent. Covers both forms: an XDG-relocated directory anchor and
// an env-relocated file rule.
func TestCredentialFilesAnchorsRelocatedStores(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()       // XDG_CONFIG_HOME, deliberately outside home
	elsewhere := t.TempDir() // KUBECONFIG target, likewise
	t.Setenv("XDG_CONFIG_HOME", xdg)

	gh := filepath.Join(xdg, "gh")
	if err := os.MkdirAll(gh, 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(gh, "hosts.yml")
	if err := os.WriteFile(token, []byte("TOKEN"), 0o600); err != nil {
		t.Fatal(err)
	}
	kube := filepath.Join(elsewhere, "kubeconfig")
	if err := os.WriteFile(kube, []byte("CLUSTER CREDS"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kube)
	// The second name a host actor would have to create for either to leak.
	for i, c := range []string{token, kube} {
		if err := os.Link(c, filepath.Join(home, fmt.Sprintf("leaked%d", i))); err != nil {
			t.Skipf("no hardlink support: %v", err)
		}
	}

	sb := testSandbox()
	sb.homes = []string{home}
	sb.resolve = func(p string) string { return p }
	sb.fileIDs = hostFileIDs

	files, _, linked, credErr := credentialFiles(sb, nil)
	if credErr != nil {
		t.Fatal(credErr)
	}
	got := make([]string, 0, len(files))
	for _, f := range files {
		got = append(got, f.path)
	}
	if !linked {
		t.Error("a relocated credential with an extra link must open the gate")
	}
	for _, want := range []string{token, kube} {
		if !slices.Contains(got, want) {
			t.Errorf("relocated credential %q must anchor the scan; got %v", want, got)
		}
	}
}

// Every anchor the deny list declares must actually be REACHED by the walk. Being in the
// anchor list and being walked are different properties, and the gap between them has
// bitten this mechanism twice: an anchor nested inside a bulk store was declared and
// walked by nothing, and a relocated anchor was declared and then filtered out. Both were
// invisible to every test that inspected the list rather than the walk.
//
// What this does NOT check is whether an anchor names the right real-world path: it plants
// its probes at the declared paths, so a misspelled anchor is created misspelled and found
// misspelled. That claim is about the world outside the repo, and `make audit` is what
// tests it - cross-referencing firejail's profile list, where a renamed credential
// directory shows up as an uncovered gap and fails the audit.
func TestEveryDeclaredAnchorIsReached(t *testing.T) {
	home := t.TempDir()
	anchors := denylist.AliasAnchors(home)
	if len(anchors) < 50 {
		t.Fatalf("expected the full anchor set, got %d - is AliasAnchors wired up?", len(anchors))
	}

	want := make([]string, 0, len(anchors))
	for i, a := range anchors {
		if err := os.MkdirAll(a, 0o700); err != nil {
			t.Fatal(err)
		}
		probe := filepath.Join(a, fmt.Sprintf("probe%d", i))
		if err := os.WriteFile(probe, []byte("SECRET"), 0o600); err != nil {
			t.Fatal(err)
		}
		want = append(want, probe)
	}

	sb := testSandbox()
	sb.homes = []string{home}
	sb.resolve = func(p string) string { return p }
	sb.fileIDs = hostFileIDs

	files, _, _, credErr := credentialFiles(sb, nil)
	if credErr != nil {
		t.Fatal(credErr)
	}
	got := make(map[string]bool, len(files))
	for _, f := range files {
		got[f.path] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("declared anchor is never walked, so it protects nothing: %s", filepath.Dir(w))
		}
	}
}

// The acknowledgement names a TREE, not a path, because the tools that create these
// aliases rotate: a cp -al snapshot root is dated, so acknowledging exact paths would go
// stale every day and need one entry per credential per snapshot. Acknowledging the
// backup root covers today's snapshot and tomorrow's.
func TestSplitAcknowledgedAliasesAcceptsByTree(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string { return p }
	found := []credentialAlias{
		{Path: "/home/u/backups/2026-07-24/.ssh/id_rsa", Credential: "/home/u/.ssh/id_rsa"},
		{Path: "/home/u/backups/2026-07-25/.ssh/id_rsa", Credential: "/home/u/.ssh/id_rsa"},
		{Path: "/home/u/project/stolen", Credential: "/home/u/.aws/credentials"},
	}

	refuse, accepted, err := splitAcknowledgedAliases(sb, scanOf(shieldedStores, found...), []string{"/home/u/backups"})
	if err != nil {
		t.Fatalf("acknowledging a backup tree must not error: %v", err)
	}
	if !slices.Equal(accepted, found[:2]) {
		t.Errorf("both rotated snapshots must be accepted by one tree; got %v", accepted)
	}
	// An acknowledgement is not a blanket off-switch: an alias outside the named tree
	// still refuses, which is what keeps this narrower than exposing the store.
	if !slices.Equal(refuse, found[2:]) {
		t.Errorf("an alias outside the acknowledged tree must still refuse; got %v", refuse)
	}
}

// An acknowledgement that matches nothing must not quietly become an approval. Getting a
// path slightly wrong is the likeliest user error here, and this mechanism has been bitten
// repeatedly by comparisons that silently match nothing - so the run must still refuse,
// which makes the mistake visible instead of fatal.
func TestSplitAcknowledgedAliasesIgnoresANonMatchingTree(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string { return p }
	found := []credentialAlias{{Path: "/home/u/backups/x", Credential: "/home/u/.ssh/id_rsa"}}

	refuse, accepted, err := splitAcknowledgedAliases(sb, scanOf(shieldedStores, found...), []string{"/home/u/backup"}) // typo: no trailing s
	if err != nil {
		t.Fatalf("acknowledging a backup tree must not error: %v", err)
	}
	if len(accepted) != 0 {
		t.Errorf("a tree that contains no alias must accept nothing; got %v", accepted)
	}
	if !slices.Equal(refuse, found) {
		t.Errorf("the run must still refuse so the mistyped tree is visible; got %v", refuse)
	}
}

// The alias paths the scan produces are symlink-resolved, so an acknowledgement typed
// against the pre-symlink name must be resolved too or it matches nothing - the same
// silent no-op that has bitten every other path comparison in this mechanism.
func TestSplitAcknowledgedAliasesResolvesTheAcknowledgedTree(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string { return strings.Replace(p, "/home/u", "/var/home/u", 1) }
	found := []credentialAlias{{Path: "/var/home/u/backups/snap/.ssh/id_rsa", Credential: "/var/home/u/.ssh/id_rsa"}}

	refuse, accepted, err := splitAcknowledgedAliases(sb, scanOf(relocatedShieldedStores, found...), []string{"/home/u/backups"})
	if err != nil {
		t.Fatalf("acknowledging a backup tree must not error: %v", err)
	}
	if len(refuse) != 0 || !slices.Equal(accepted, found) {
		t.Errorf("the acknowledged tree must be resolved before comparing; refuse=%v accepted=%v", refuse, accepted)
	}
}

// The refusal must hand over the exact string the acknowledgement needs. A user retyping a
// resolved path by hand would produce something that does not compare equal, so describing
// the flag instead of printing it would send them into the silent-no-match trap.
func TestAliasRefusalPrintsThePasteableAcknowledgement(t *testing.T) {
	err := aliasRefusal([]credentialAlias{
		{Path: "/var/home/u/backups/2026-07-24/.ssh/id_rsa", Credential: "/var/home/u/.ssh/id_rsa"},
	}, []string{"/var/home/u/.ssh/id_rsa"})
	want := "--accept-alias /var/home/u/backups/2026-07-24/.ssh"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("refusal must print %q verbatim; got:\n%s", want, err)
	}
}

// End to end against a real Enforcer, a real hardlink and real bwrap: the same policy that
// TestRunRefusesAnAliasedCredential proves is refused must proceed once the tree is
// acknowledged, and the result must SAY the run read past a shield. Recording it is the
// point - an acknowledgement is per-invocation and easily left behind in a wrapper, so a
// run that proceeds over a known gap has to report the gap rather than look clean.
func TestRunProceedsOnAnAcknowledgedAlias(t *testing.T) {
	requireSandbox(t)
	bento := sandboxEnforcer(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "id_rsa")
	if err := os.WriteFile(key, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A cp -al style snapshot: a dated directory holding a second name for the live key.
	snapshot := filepath.Join(home, "backups", "2026-07-24", ".ssh")
	if err := os.MkdirAll(snapshot, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(snapshot, "id_rsa")
	if err := os.Link(key, alias); err != nil {
		t.Skipf("no hardlink support: %v", err)
	}
	entrypoint := filepath.Join(home, "backups", "run.sh")
	if err := os.WriteFile(entrypoint, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: entrypoint, Interpreter: "/bin/sh", Read: []string{filepath.Join(home, "backups")}}
	proc := enforce.Process{Env: map[string]string{"HOME": home}}

	// Control: without the acknowledgement this policy is refused.
	if _, err := bento.Run(context.Background(), p, proc, enforce.RunOptions{}); err == nil {
		t.Fatal("the aliased snapshot must refuse the run without an acknowledgement")
	}

	res, err := bento.Run(context.Background(), p, proc,
		enforce.RunOptions{AcceptAliasesUnder: []string{filepath.Join(home, "backups")}})
	if err != nil {
		t.Fatalf("acknowledging the snapshot tree must let the run proceed: %v", err)
	}
	want := enforce.CredentialAlias{Path: alias, Credential: key}
	if !slices.Contains(res.AcceptedAliases, want) {
		t.Errorf("the result must record the acknowledged alias %+v; got %+v", want, res.AcceptedAliases)
	}
}

// The suggested acknowledgement has to survive the rotation the triggering tools do. A
// cp -al backup root holds a dated snapshot per day, each with several credentials, so
// suggesting each alias's own parent hands back a flag per credential per snapshot that is
// stale tomorrow - the exact failure a tree-scoped acknowledgement exists to avoid. The
// shared tree is one stable flag.
func TestAcknowledgementRootsPrefersTheSharedTree(t *testing.T) {
	got := acknowledgementRoots([]credentialAlias{
		{Path: "/home/u/backups/2026-07-24/.ssh/id_rsa", Credential: "/home/u/.ssh/id_rsa"},
		{Path: "/home/u/backups/2026-07-24/.aws/credentials", Credential: "/home/u/.aws/credentials"},
		{Path: "/home/u/backups/2026-07-25/.ssh/id_rsa", Credential: "/home/u/.ssh/id_rsa"},
	}, []string{"/home/u/.ssh/id_rsa", "/home/u/.aws/credentials"})
	if !slices.Equal(got, []string{"/home/u/backups"}) {
		t.Errorf("acknowledgementRoots = %v, want the one shared tree [/home/u/backups]", got)
	}
}

// The shared tree must never be suggested when it also contains a shielded credential:
// aliases scattered across a home share the home as their ancestor, and one
// "--accept-alias ~" would accept every alias of every credential store - an off-switch,
// not an acknowledgement. Fall back to the individual parents, which stay narrow.
func TestAcknowledgementRootsRefusesATreeHoldingACredential(t *testing.T) {
	aliases := []credentialAlias{
		{Path: "/home/u/notes/copy", Credential: "/home/u/.ssh/id_rsa"},
		{Path: "/home/u/build/key", Credential: "/home/u/.aws/credentials"},
	}
	got := acknowledgementRoots(aliases, []string{"/home/u/.ssh/id_rsa", "/home/u/.aws/credentials"})
	if slices.Contains(got, "/home/u") {
		t.Errorf("must not suggest a tree containing the credential stores; got %v", got)
	}
	if !slices.Equal(got, []string{"/home/u/notes", "/home/u/build"}) {
		t.Errorf("expected the narrow parents; got %v", got)
	}
}

// Aliases with nothing in common share only the root, and "--accept-alias /" would accept
// every alias anywhere - the same off-switch. Fall back to the parents.
func TestAcknowledgementRootsNeverSuggestsTheFilesystemRoot(t *testing.T) {
	got := acknowledgementRoots([]credentialAlias{
		{Path: "/srv/a/key", Credential: "/home/u/.ssh/id_rsa"},
		{Path: "/mnt/b/key", Credential: "/home/u/.ssh/id_rsa"},
	}, []string{"/home/u/.ssh/id_rsa"})
	if slices.Contains(got, "/") {
		t.Errorf("must never suggest the filesystem root; got %v", got)
	}
	if !slices.Equal(got, []string{"/srv/a", "/mnt/b"}) {
		t.Errorf("expected the narrow parents; got %v", got)
	}
}

// The invariant the two tests above only sample: whatever acknowledgementRoots suggests,
// checkAcknowledgementScope accepts. A hardlink dropped beside the credential store itself
// gives every alias the same parent the shared tree was rejected for, so the fallback used
// to hand back a flag that the very next run refused.
func TestAcknowledgementRootsSuggestsNothingItWouldRefuse(t *testing.T) {
	credentials := []string{"/home/u/.ssh/id_rsa", "/home/u/.aws/credentials"}
	// want is spelled out rather than only checked against the predicate: two of these
	// cases have no acceptable tree, and asserting the invariant alone would pass over an
	// empty result whatever produced it.
	for name, tc := range map[string]struct {
		aliases []credentialAlias
		want    []string
	}{
		"an alias beside the store": {
			aliases: []credentialAlias{{Path: "/home/u/keybackup", Credential: "/home/u/.ssh/id_rsa"}},
			want:    nil,
		},
		"one alias under a whole-filesystem grant": {
			aliases: []credentialAlias{{Path: "/keybak", Credential: "/home/u/.ssh/id_rsa"}},
			want:    nil,
		},
		// A partial suggestion, not a dead end: the accepted tree covers one of the two
		// aliases, so the run refuses again and then offers nothing.
		"a narrow one and an overbroad one together": {
			aliases: []credentialAlias{
				{Path: "/home/u/backups/key", Credential: "/home/u/.ssh/id_rsa"},
				{Path: "/home/u/keybackup", Credential: "/home/u/.ssh/id_rsa"},
			},
			want: []string{"/home/u/backups"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := acknowledgementRoots(tc.aliases, credentials)
			for _, r := range got {
				if err := checkAcknowledgementScope(r, credentials); err != nil {
					t.Errorf("suggested --accept-alias %s, which the run then refuses: %v", r, err)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("acknowledgementRoots = %v, want %v", got, tc.want)
			}
		})
	}
}

// Where no tree holds the aliases without also holding a credential store there is nothing
// to suggest, and the refusal must say only what applies. Printing the header with no flag
// under it, or a flag the run refuses, both send the reader nowhere.
func TestAliasRefusalOmitsTheAcknowledgementWhenNoneWouldBeAccepted(t *testing.T) {
	err := aliasRefusal([]credentialAlias{
		{Path: "/home/u/keybackup", Credential: "/home/u/.ssh/id_rsa"},
	}, []string{"/home/u/.ssh/id_rsa"})
	if strings.Contains(err.Error(), "--accept-alias") {
		t.Errorf("no acceptable tree exists, so the refusal must not offer one:\n%s", err)
	}
	if strings.Contains(err.Error(), "acknowledge the tree") {
		t.Errorf("the acknowledgement header must not stand alone:\n%s", err)
	}
	if !strings.Contains(err.Error(), "remove the alias") {
		t.Errorf("the remedies that do apply must still be named:\n%s", err)
	}
}

// An acknowledgement wide enough to hold a shielded credential is the mechanism switched
// off, not an acknowledgement: every alias on the host falls inside it, including one
// planted later in a directory the user never had in mind. Refuse it rather than silently
// narrowing, which would answer a different question than the one asked. The same
// predicate governs what the refusal is willing to suggest, so advice and enforcement
// cannot drift apart.
func TestSplitAcknowledgedAliasesRejectsAnOffSwitch(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string { return p }
	found := []credentialAlias{{Path: "/home/u/backups/x", Credential: "/home/u/.ssh/id_rsa"}}

	for _, tree := range []string{"/", "/home/u", "/home/u/.."} {
		_, accepted, err := splitAcknowledgedAliases(sb, scanOf(shieldedStores, found...), []string{tree})
		if err == nil {
			t.Errorf("--accept-alias %s must be refused as an off-switch; accepted %v", tree, accepted)
		}
	}

	// The legitimate case must still pass: a backup root holds second NAMES for
	// credentials, not the credentials themselves.
	refuse, accepted, err := splitAcknowledgedAliases(sb, scanOf(shieldedStores, found...), []string{"/home/u/backups"})
	if err != nil || len(refuse) != 0 || len(accepted) != 1 {
		t.Errorf("a backup root must be acceptable; err=%v refuse=%v accepted=%v", err, refuse, accepted)
	}
}

// jx5f: the guard has to judge an acknowledgement against every credential the host
// shields, not the ones this run happened to alias. A run whose aliases all name a store
// outside the home would otherwise accept "--accept-alias ~" - and bento would print it
// as a paste-ready suggestion - after which every alias planted under the home is
// accepted silently on later runs.
func TestSplitAcknowledgedAliasesJudgesTheWholeCredentialSet(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string { return p }
	// The run's only alias names a relocated KUBECONFIG, so nothing in found sits under
	// the home - but ~/.ssh/id_rsa is shielded all the same.
	scan := aliasScan{
		found:       []credentialAlias{{Path: "/home/u/project/copy", Credential: "/mnt/kube/config"}},
		credentials: []string{"/home/u/.ssh/id_rsa", "/mnt/kube/config"},
	}

	if _, _, err := splitAcknowledgedAliases(sb, scan, []string{"/home/u"}); err == nil {
		t.Error("--accept-alias /home/u holds a shielded credential and must be refused, whatever this run's aliases named")
	}
	// The narrow tree the user actually meant still passes.
	if _, accepted, err := splitAcknowledgedAliases(sb, scan, []string{"/home/u/project"}); err != nil || len(accepted) != 1 {
		t.Errorf("the tree the alias lives in must still be acceptable; err=%v accepted=%v", err, accepted)
	}
}

// The same guard on a run that found nothing. An acknowledgement is typed once and lives
// in a wrapper script forever, so validating it only when the current run has aliases to
// compare against means "--accept-alias /" is accepted on the clean run that installs it
// and never questioned again.
func TestSplitAcknowledgedAliasesJudgesAnOffSwitchWithNoAliasesFound(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string { return p }
	scan := aliasScan{credentials: []string{"/home/u/.ssh/id_rsa"}}

	for _, tree := range []string{"/", "/home/u"} {
		if _, _, err := splitAcknowledgedAliases(sb, scan, []string{tree}); err == nil {
			t.Errorf("--accept-alias %s must be refused even when the run found no alias", tree)
		}
	}
	if _, _, err := splitAcknowledgedAliases(sb, scan, []string{"/home/u/backups"}); err != nil {
		t.Errorf("a narrow tree must stay acceptable on a run that found nothing: %v", err)
	}
}

// 9aj1: a mount table that cannot be read to the end refuses the run. The hardlink half
// does not cover for it - a bind adds no directory entry, so it bumps no link count and
// the hardlink gate never opens for one - so returning an empty list here would report
// clean because the scan could not look.
func TestAliasedCredentialsRefusesAnUnreadableMountTable(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.ssh": {{path: "/home/u/.ssh/id_rsa", id: fileID{dev: 1, ino: 11}, links: 1}},
	}
	sb := aliasSandbox(creds, nil)
	sb.mountpoints = func([]uint64) ([]mountPoint, error) { return nil, errors.New("mountinfo truncated") }

	_, err := aliasedCredentials(sb, []string{"/home/u/project"}, nil)
	if err == nil || !strings.Contains(err.Error(), "mountinfo truncated") {
		t.Fatalf("an unreadable mount table must refuse the run, naming the cause; got %v", err)
	}
}

// Neither walk may report clean because it broke. The link counts fileIDs returns gate
// the granted-tree walk outright, so a truncated credential enumeration reads as proof
// that no hardlink exists; a granted tree the walk could not finish reading is the same
// shape one level down.
func TestAliasedCredentialsRefusesAWalkThatFailed(t *testing.T) {
	creds := map[string][]identifiedFile{
		"/home/u/.ssh": {{path: "/home/u/.ssh/id_rsa", id: fileID{dev: 1, ino: 11}, links: 2}},
	}
	t.Run("credential anchors", func(t *testing.T) {
		sb := aliasSandbox(creds, nil)
		sb.fileIDs = func(string) ([]identifiedFile, error) { return nil, errors.New("anchor walk broke") }
		if _, err := aliasedCredentials(sb, []string{"/home/u/project"}, nil); err == nil ||
			!strings.Contains(err.Error(), "anchor walk broke") {
			t.Fatalf("a failed credential walk must refuse the run, naming the cause; got %v", err)
		}
	})
	t.Run("granted tree", func(t *testing.T) {
		sb := aliasSandbox(creds, nil)
		sb.aliasesUnder = func(string, map[fileID]string) ([]credentialAlias, error) {
			return nil, errors.New("tree walk broke")
		}
		if _, err := aliasedCredentials(sb, []string{"/home/u/project"}, nil); err == nil ||
			!strings.Contains(err.Error(), "tree walk broke") {
			t.Fatalf("a failed granted-tree walk must refuse the run, naming the cause; got %v", err)
		}
	})
}

// The permission axis, which is what makes the two walks differ. Under a credential
// anchor the invoking user owns, an unreadable subtree is anomalous and under-counts the
// links the whole scan gates on, so it refuses. Under a granted tree it is routine - a
// run's exposed trees include /etc, whose ssl/private is unreadable on any ordinary host
// - and it is provably harmless: the sandboxed process is the same uid at the same path,
// so what the scan cannot read the run cannot read either.
func TestWalksDivergeOnAnUnreadableSubtree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not refused by directory permissions, so there is no EACCES to raise")
	}
	root := t.TempDir()
	closed := filepath.Join(root, "closed")
	if err := os.Mkdir(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })

	if _, err := hostFileIDs(root); err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("hostFileIDs over an unreadable credential subtree = %v, want a permission error", err)
	}

	// An anchor with nothing behind it is not an anchor the walk failed to read, and
	// only ENOENT reaches fs.ErrNotExist - a component that is a regular file or a
	// symlink loop names no file just as squarely, and refusing on either would refuse
	// every run on a host where a store bento models happens not to be a directory.
	notThere := filepath.Join(root, "plain")
	if err := os.WriteFile(notThere, []byte("not a store"), 0o600); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(root, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	for _, anchor := range []string{
		filepath.Join(notThere, "auth"), // ENOTDIR
		filepath.Join(loop, "auth"),     // ELOOP
		filepath.Join(root, "absent"),   // ENOENT
	} {
		if ids, err := hostFileIDs(anchor); err != nil || ids != nil {
			t.Errorf("hostFileIDs(%q) = %v, %v; want it skipped as an anchor with no file behind it", anchor, ids, err)
		}
	}
	if _, err := hostAliasesUnder(root, map[fileID]string{{dev: 1, ino: 1}: "/home/u/.ssh/id_rsa"}); err != nil {
		t.Errorf("hostAliasesUnder over an unreadable granted subtree = %v, want it skipped", err)
	}
}

// failingEntry is a walk entry whose second lstat fails - what a rotating credential
// store hands the walk when readdir saw a name that the following Info() no longer finds.
type failingEntry struct {
	fs.DirEntry
	err error
}

func (e failingEntry) Info() (fs.FileInfo, error) { return nil, e.err }

// A second-lstat failure is not evidence about the file. Swallowing it in hostFileIDs
// under-counts links, and linked == false skips the entire granted-tree walk - "could not
// look" read as proof no hardlink exists.
func TestIdentifyReportsASecondLstatFailure(t *testing.T) {
	dir := t.TempDir()
	cred := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(cred, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := identify(cred, entries[0]); err != nil {
		t.Fatalf("identify of a readable credential = %v, want it identified", err)
	}
	// EIO stands in for the class the anchors' walk must refuse; ENOENT for the rotation
	// that names no file at all and is skipped by the caller.
	for _, want := range []error{syscall.EIO, syscall.ENOENT} {
		_, err := identify(cred, failingEntry{DirEntry: entries[0], err: &fs.PathError{Op: "lstat", Path: cred, Err: want}})
		if !errors.Is(err, want) {
			t.Errorf("identify with a failing Info = %v, want %v", err, want)
		}
	}
}

// The device filter is on the mount, not on the path to it: a bind of a credential
// directory made underneath a dead NFS export carries the home's device and passes it. The
// ancestor chain is what catches that, from the same lines the filter already reads, so
// the mount is reported separately rather than stat'd - and the caller refuses instead of
// blocking forever in the kernel with nothing to cancel.
func TestMountinfoPathsSeparatesAMountBehindANetworkFilesystem(t *testing.T) {
	const info = `26 30 8:2 / / rw,relatime - ext4 /dev/sda2 rw
29 26 0:99 / /mnt/dead-nfs rw - nfs4 srv:/export rw
31 29 8:2 /home/u/.ssh /mnt/dead-nfs/keys rw,relatime - ext4 /dev/sda2 rw
32 26 8:2 /home/u/.ssh /srv/backup/.ssh rw,relatime - ext4 /dev/sda2 rw`

	got, behind, err := mountinfoPaths(strings.NewReader(info), []uint64{uint64(unix.Mkdev(8, 2))})
	if err != nil {
		t.Fatalf("mountinfoPaths: %v", err)
	}
	if slices.Contains(got, "/mnt/dead-nfs/keys") {
		t.Errorf("mountinfoPaths = %v; a mount reached through NFS must never be handed back to be lstat'd", got)
	}
	if !slices.Equal(behind, []string{"/mnt/dead-nfs/keys"}) {
		t.Errorf("mountinfoPaths behindNetwork = %v, want just the nested bind - dropping it silently is the short list the seam forbids", behind)
	}
	// An ordinary bind on the same host is unaffected: the screen is on the chain, not on
	// the presence of a network mount somewhere in the table.
	if !slices.Contains(got, "/srv/backup/.ssh") {
		t.Errorf("mountinfoPaths = %v; a bind with no network ancestor must still be scanned", got)
	}
}

// A mountpoint that cannot be identified is either gone or unreachable to this uid - both
// skippable - or a could-not-look, which must not shorten the mount list.
func TestHostStatIDSeparatesAbsenceFromFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not refused by directory permissions, so there is no EACCES to raise")
	}
	dir := t.TempDir()
	if _, err := hostStatID(filepath.Join(dir, "absent")); !nothingBehind(err) {
		t.Errorf("hostStatID of an absent path = %v, want it read as nothing behind the path", err)
	}
	closed := filepath.Join(dir, "closed")
	if err := os.Mkdir(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	if _, err := hostStatID(filepath.Join(closed, "mnt")); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("hostStatID under an untraversable parent = %v, want a permission error", err)
	}
}

// The entrypoint and interpreter are bound as individual FILES on the bwrap tier and
// granted as Landlock exec paths on the degraded one, so neither tier's visible set
// contains them - and a hardlink named as the entrypoint is read by the target as its
// own program text.
func TestCheckAliasedCredentialsScansTheExecPaths(t *testing.T) {
	key := identifiedFile{path: "/home/u/.ssh/id_rsa", id: fileID{dev: 1, ino: 11}, links: 2}
	creds := map[string][]identifiedFile{"/home/u/.ssh": {key}}
	for _, tc := range []struct {
		name string
		exec string
	}{
		{"entrypoint", "/work/run.py"},
		{"interpreter", "/opt/py/bin/python3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := aliasSandbox(creds, map[string][]identifiedFile{
				tc.exec: {{path: tc.exec, id: key.id, links: 2}},
			})
			if tc.name == "interpreter" {
				sb.interpreter = tc.exec
			}
			_, err := checkAliasedCredentials(sb, nil, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.exec) {
				t.Fatalf("a %s hardlinked to a credential must refuse the run; got %v", tc.name, err)
			}
		})
	}
}

// A host whose credential stores are still empty shields them all the same, and the
// acknowledgement flag outlives the run that suggested it: validating it against the files
// found today would accept "--accept-alias $HOME" until the first ssh-keygen and keep
// accepting it afterwards.
func TestCheckAliasedCredentialsJudgesAnOffSwitchOnAnEmptyHost(t *testing.T) {
	sb := aliasSandbox(nil, nil)

	_, err := checkAliasedCredentials(sb, nil, nil, []string{"/home/u"})
	if err == nil || !strings.Contains(err.Error(), "would accept every alias") {
		t.Fatalf("a tree holding an empty credential store is still an off-switch; got %v", err)
	}
}

// A credential store on a live network filesystem gives every file in it the export's
// device, so the export's own mount line is wanted. Screening it would refuse every launch
// on an ordinary NFS home - and would protect nothing, because credentialFiles walked that
// same export earlier in the run to identify the credentials. Only a mount reached THROUGH
// a network filesystem is screened.
func TestMountinfoPathsScansAMountThatIsItselfTheNetworkFilesystem(t *testing.T) {
	const info = `26 30 8:2 / / rw,relatime - ext4 /dev/sda2 rw
29 26 0:99 / /home rw - nfs4 srv:/export rw
31 26 0:99 /u/.ssh /srv/backup/.ssh rw - nfs4 srv:/export rw`

	got, behind, err := mountinfoPaths(strings.NewReader(info), []uint64{uint64(unix.Mkdev(0, 99))})
	if err != nil {
		t.Fatalf("mountinfoPaths: %v", err)
	}
	if len(behind) > 0 {
		t.Fatalf("mountinfoPaths behindNetwork = %v; an NFS home is a live mount the run already walked, not a hang risk", behind)
	}
	if !slices.Equal(got, []string{"/home", "/srv/backup/.ssh"}) {
		t.Errorf("mountinfoPaths = %v, want both NFS mounts scanned", got)
	}
}

// An anchor does not subsume the files behind it in both directions: a tree strictly
// inside an anchor covers a credential without covering the anchor, so judging on anchors
// alone would accept an off-switch the file set caught.
func TestOverbroadAcknowledgementCatchesATreeInsideAnAnchor(t *testing.T) {
	if !overbroadAcknowledgement("/home/u/.ssh/keys", []string{"/home/u/.ssh", "/home/u/.ssh/keys/id_rsa"}) {
		t.Error("a tree between an anchor and a credential it holds is still an off-switch for that credential")
	}
}

// A credential store on an unresponsive network mount blocks the walk that identifies
// it for as long as the mount hangs - before the sandbox is built, with no output, no
// timeout and no exit. The scan has to give up on it and say so.
func TestACredentialWalkThatNeverAnswersIsBounded(t *testing.T) {
	credentialWalkTimeout = 100 * time.Millisecond
	t.Cleanup(func() { credentialWalkTimeout = 30 * time.Second })

	// Stands in for the walk of a hung export: it answers only when the test is over.
	hung := make(chan struct{})
	t.Cleanup(func() { close(hung) })
	sb := sandbox{homes: []string{t.TempDir()}, resolve: hostResolve, isDir: hostIsDir,
		listDir: hostListDir, mountpoints: hostMountpoints, statID: hostStatIDOK,
		fileIDs:      func(string) ([]identifiedFile, error) { <-hung; return nil, nil },
		aliasesUnder: hostAliasesUnder}

	done := make(chan error, 1)
	go func() {
		_, err := aliasedCredentials(sb, nil, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "did not answer within") {
			t.Fatalf("aliasedCredentials error = %v, want one naming the walk that never answered", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("aliasedCredentials never returned: a credential store on a dead mount hangs the preflight with no output and no exit")
	}
}

// The walks were bounded first; these are the error-free seams a dead mount blocks just as
// thoroughly - so before this a write grant or a credential store on an unresponsive export
// still hung the preflight, just later.
func TestTheSandboxsErrorFreeHostSeamsAreBounded(t *testing.T) {
	credentialWalkTimeout = 100 * time.Millisecond
	t.Cleanup(func() { credentialWalkTimeout = 30 * time.Second })

	hung := make(chan struct{})
	t.Cleanup(func() { close(hung) })
	sb := boundHostSeams(sandbox{
		deadMount: &deadMount{},
		isDir:     func(string) bool { <-hung; return true },
		resolve:   func(p string) string { <-hung; return p },
		listDir:   func(string) (names, links []string, ok bool) { <-hung; return nil, nil, true },
		exists:    func(string) bool { <-hung; return true },
		writable:  func(string) bool { <-hung; return true },
	})

	// Each seam separately: one of them answering is not the others answering, and a
	// grant's checkout root reaches all of them.
	for _, seam := range []struct {
		name string
		call func()
	}{
		{"isDir", func() { sb.isDir("/export/checkout") }},
		{"resolve", func() { sb.resolve("/export/checkout") }},
		{"listDir", func() { sb.listDir("/export/checkout") }},
		{"exists", func() { sb.exists("/export/checkout") }},
		{"writable", func() { sb.writable("/export/checkout") }},
	} {
		done := make(chan struct{})
		go func() { seam.call(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("sb.%s never returned: a write grant on a dead mount hangs the preflight with no output and no exit", seam.name)
		}
	}
	if err := sb.deadMount.expired(); err == nil || !strings.Contains(err.Error(), "did not answer within") {
		t.Fatalf("deadMount.expired() = %v, want the expiry recorded; an unrecorded one is a shield silently dropped", err)
	}

	// The two fallbacks whose direction is load-bearing rather than merely conservative.
	if !sb.exists("/export/checkout") {
		t.Error("an expired exists answered 'missing'; checkShieldsCarvable's `for !sb.exists(parent)` walk then loops forever at /")
	}
	if sb.writable("/export/checkout") {
		t.Error("an expired writable answered 'writable'; the grant is then carried into a bwrap mkdir on a mount that never answered instead of being refused by name")
	}
}

// The recording is what makes the fallback answers safe. A seam that expired handed back
// "not a directory" or "does not resolve", which reads as a real answer and quietly
// narrows the shields built from it - a write grant whose isDir expired loses its
// checkout's git-hook and editor-task shields, and nothing else walks a write grant
// fatally. So the run is refused where it can still be refused.
func TestCompileRefusesARunWhoseHostSeamExpired(t *testing.T) {
	sb := testSandbox("/work/run.py")
	sb.deadMount = &deadMount{}
	p := &policy.Policy{}

	if _, _, err := compile(p, enforce.Process{}, sb); err != nil {
		t.Fatalf("compile refused a sandbox whose seams all answered: %v", err)
	}
	sb.deadMount.note(errors.New("linux: the directory check of /export/checkout did not answer within 30s, which is what an unresponsive network mount looks like"))
	_, _, err := compile(p, enforce.Process{}, sb)
	if err == nil {
		t.Fatal("compile built a sandbox whose shields were derived from a mount that never answered")
	}
	if !strings.Contains(err.Error(), "/export/checkout") {
		t.Errorf("compile error = %v, want it to name the seam that expired", err)
	}
}
