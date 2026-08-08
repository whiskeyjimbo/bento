package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// newTestStore is an empty in-memory store whose dir cannot cover any test grant.
func newTestStore() *store {
	return &store{Version: 1, Apps: map[string]*appPerms{}, dir: "/nonexistent/bento-supervise"}
}

// Deny wins across the global and per-app layers, and network keys normalize so a
// deny cannot be evaded by case or a trailing dot.
func TestStoreDecideNetworkDenyWinsAndNormalizes(t *testing.T) {
	s := newTestStore()
	s.rememberNetwork("k", "example.com", "443", allow, false) // per-app allow
	s.rememberNetwork("k", "example.com", "443", deny, true)   // global deny of the same

	if d, ok := s.decideNetwork("k", "EXAMPLE.com.", "443"); !ok || d != deny {
		t.Errorf("decideNetwork = %v,%v; want deny (global deny beats per-app allow, case/dot normalized)", d, ok)
	}
	if _, ok := s.decideNetwork("k", "unknown.example", "443"); ok {
		t.Error("an unseen host must be unknown (prompt), not decided")
	}
}

// A directory allow answers a prompt for a file inside it (longest-prefix), and a
// more-specific deny wins over a broader allow.
func TestStoreDecidePathLongestPrefix(t *testing.T) {
	s := newTestStore()
	s.rememberPath("k", "read", "/home/u/proj", allow, false)
	s.rememberPath("k", "read", "/home/u/proj/secret", deny, false)

	if d, ok := s.decidePath("k", "read", "/home/u/proj/data.csv"); !ok || d != allow {
		t.Errorf("data.csv under an allowed dir = %v,%v; want allow", d, ok)
	}
	if d, ok := s.decidePath("k", "read", "/home/u/proj/secret/key"); !ok || d != deny {
		t.Errorf("under a more-specific deny = %v,%v; want deny", d, ok)
	}
	if _, ok := s.decidePath("k", "read", "/home/u/other"); ok {
		t.Error("an unrelated path must be unknown")
	}
	// A sibling that only shares a string prefix must not match (/projX vs /proj).
	if _, ok := s.decidePath("k", "read", "/home/u/projX"); ok {
		t.Error("/home/u/projX must not match the allow of /home/u/proj (component boundary)")
	}
}

// A grant that would expose the store is refused outright, never granted or
// prompted.
func TestApproveRefusesStoreCoveringGrant(t *testing.T) {
	s := newTestStore()
	s.dir = "/home/u/.config/bento-supervise"
	var out strings.Builder
	// No input: if the covering grant prompted, ask would block/deny; we assert it
	// is refused without consuming input.
	p := newPrompter(strings.NewReader(""), &out)
	proposal := &policy.Policy{Read: []string{"/home/u/.config"}} // contains the store dir

	got := approve(t.Context(), p, s, "k", "/s", "sh", nil, proposal)
	if len(got.Read) != 0 {
		t.Errorf("a grant covering the store must be refused; got Read=%v", got.Read)
	}
	if !strings.Contains(out.String(), "refused") {
		t.Errorf("the refusal should be reported; got %q", out.String())
	}
}

// A path from the untrusted trial can carry terminal escapes; the approval prompt
// must quote it (as the gate quotes a host), or a crafted filename spoofs what the
// operator sees while a different path is stored/granted.
func TestApproveQuotesAttackerPath(t *testing.T) {
	s := newTestStore()
	evil := "/home/u/proj/\x1b[2Kinnocent"
	var out strings.Builder
	// "y" grants it; the display must not contain the raw ESC byte.
	p := newPrompter(strings.NewReader("y\n"), &out)
	got := approve(t.Context(), p, s, "k", "/s", "sh", nil, &policy.Policy{Read: []string{evil}})

	if len(got.Read) != 1 || got.Read[0] != evil {
		t.Fatalf("the literal path must be granted; got %v", got.Read)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Errorf("the approval prompt leaked a raw escape byte: %q", out.String())
	}
}

// save folds in a concurrent run's writes instead of clobbering them: after run A
// saves app "a", run B (which loaded before A saved) saves app "b" and both survive.
func TestStoreSaveMergesConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	mk := func() *store {
		return &store{Version: 1, Apps: map[string]*appPerms{}, dir: dir, path: filepath.Join(dir, "permissions.json")}
	}
	a := mk()
	a.rememberNetwork("a", "a.example", "443", allow, false)
	if err := a.save(); err != nil {
		t.Fatal(err)
	}
	// b was loaded empty before a's save; it must not erase a's record on its own save.
	b := mk()
	b.rememberNetwork("b", "b.example", "443", deny, false)
	if err := b.save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "permissions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var final store
	if err := json.Unmarshal(data, &final); err != nil {
		t.Fatal(err)
	}
	if _, ok := final.Apps["a"]; !ok {
		t.Error("app 'a' was clobbered by a concurrent save")
	}
	if _, ok := final.Apps["b"]; !ok {
		t.Error("app 'b' was not saved")
	}
}

// On a conflicting key, the concurrent-merge fold is deny-preferring: a deny another
// run wrote to disk must survive this run's save even when this run holds an allow
// for the same key, matching the store's deny-wins model.
func TestStoreSaveDenyWinsConcurrentConflict(t *testing.T) {
	dir := t.TempDir()
	mk := func() *store {
		return &store{Version: 1, Apps: map[string]*appPerms{}, dir: dir, path: filepath.Join(dir, "permissions.json")}
	}
	// a saves first, becoming the on-disk deny for both the host and exec.
	a := mk()
	a.rememberNetwork("app", "x.example", "443", deny, false)
	a.rememberExec("app", deny, false)
	if err := a.save(); err != nil {
		t.Fatal(err)
	}
	// b loaded empty before a's save and holds an allow for both. Its save must not
	// overwrite a's disk deny - the discriminating case for the deny-preferring fold.
	b := mk()
	b.rememberNetwork("app", "x.example", "443", allow, false)
	b.rememberExec("app", allow, false)
	if err := b.save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "permissions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var final store
	if err := json.Unmarshal(data, &final); err != nil {
		t.Fatal(err)
	}
	if got := final.Apps["app"].Network["x.example:443"]; got != deny {
		t.Errorf("network conflict = %v; a concurrent deny must survive this run's allow", got)
	}
	if got := final.Apps["app"].Exec; got != "none" {
		t.Errorf("exec conflict = %q; a concurrent exec deny must survive this run's allow", got)
	}
}

// The core loop: approve once with answers, then a second run with NO input
// auto-applies the remembered decisions (allow silently, deny silently) and never
// prompts - the "run twice, silent" behavior.
func TestApproveRemembersAcrossRuns(t *testing.T) {
	s := newTestStore()
	proposal := &policy.Policy{
		Read:    []string{"/data", "/secret"},
		Network: []policy.NetworkRule{{Host: "ok.example", Port: "443"}},
		Exec:    policy.ExecAll,
	}

	// First run: allow /data, deny /secret, allow exec, allow the host.
	first := approve(t.Context(), newPrompter(strings.NewReader("y\nn\ny\ny\n"), &strings.Builder{}), s, "k", "/s", "sh", nil, proposal)
	if len(first.Read) != 1 || first.Read[0] != "/data" {
		t.Fatalf("first run Read = %v, want just /data", first.Read)
	}

	// Second run: no input at all. Every item is remembered, so nothing prompts and
	// the same policy is produced.
	var out strings.Builder
	second := approve(t.Context(), newPrompter(strings.NewReader(""), &out), s, "k", "/s", "sh", nil, proposal)
	if len(second.Read) != 1 || second.Read[0] != "/data" || second.Exec != policy.ExecAll || len(second.Network) != 1 {
		t.Errorf("second run did not reproduce the approved policy from memory: %+v", second)
	}
	if strings.Contains(out.String(), "[y]es") {
		t.Errorf("second run must not prompt; output was %q", out.String())
	}
}

// The store shields (approve's grant refusal and assertStoreShielded) compare through
// EvalSymlinks, which falls back to the raw string on a path that does not exist. With
// a symlinked config home that fallback compares two spellings of the same directory
// and finds no overlap, so on run one a grant of the store's own directory sailed past
// both checks and a permissions.json planted in that window was trusted forever.
// loadStore creating the directory is what closes it.
func TestLoadStoreCreatesDirSoShieldsResolve(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "config")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", link)

	s, err := loadStore()
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	if fi, err := os.Stat(s.dir); err != nil || !fi.IsDir() {
		t.Fatalf("loadStore must create the store dir; stat = %v, %v", fi, err)
	}
	// A grant must be refused however it is spelled, and whether or not it exists yet:
	// coversStore compares through resolveSymlinks, and resolving only fully-existing
	// paths would put the store dir in the real namespace and a not-yet-created file
	// inside it in the link namespace, where neither contains the other.
	for _, grant := range []string{
		filepath.Join(real, "bento-supervise"), // resolved spelling of the dir
		filepath.Join(link, "bento-supervise"), // link spelling of the dir
		filepath.Join(real, "bento-supervise", "perms.json"),
		filepath.Join(link, "bento-supervise", "perms.json"), // does not exist yet
		link, real, // a grant enclosing the store
	} {
		if !coversStore(grant, s.dir) {
			t.Errorf("coversStore(%q, %q) = false; a grant reaching the permission store must be refused", grant, s.dir)
		}
	}
	// A sibling that merely shares a prefix is not the store.
	if coversStore(filepath.Join(real, "bento-supervise-other"), s.dir) {
		t.Error("a sibling directory must not read as covering the store")
	}
}

// The merge re-read used to swallow both the read and the parse error and then write
// this run's delta ALONE - so an unreadable store was silently replaced by an empty
// one and every remembered deny was destroyed. loadStore treats the same bytes as
// fatal; the write path has to agree.
func TestSaveRefusesToMergeOntoAnUnreadableStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	s.rememberNetwork("", "tracker.example", "443", deny, true)
	if err := s.save(); err != nil {
		t.Fatalf("first save: %v", err)
	}
	before, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}

	for name, corrupt := range map[string]func(){
		"unreadable": func() {
			if os.Geteuid() == 0 {
				t.Skip("root reads through mode 0000")
			}
			if err := os.Chmod(s.path, 0o000); err != nil {
				t.Fatal(err)
			}
		},
		"corrupt": func() {
			if err := os.WriteFile(s.path, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.Chmod(s.path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			corrupt()
			t.Cleanup(func() { _ = os.Chmod(s.path, 0o600) })
			// Whatever state corrupt() left, the save must not replace it - the
			// destructive half of the bug is what matters, not just the swallowed error.
			untouched, readErr := os.ReadFile(s.path)

			next := &store{Version: storeVersion, Apps: map[string]*appPerms{}, dir: s.dir, path: s.path}
			next.rememberPath("", "read", "/tmp/x", deny, true)
			if err := next.save(); err == nil {
				t.Error("save must fail rather than write this run's delta over a store it could not read")
			}
			if readErr != nil {
				return // unreadable to the test too; the no-clobber check below cannot run
			}
			after, err := os.ReadFile(s.path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(untouched) {
				t.Errorf("the store was rewritten over content the save could not read:\n%s", after)
			}
		})
	}
	// The remembered deny must have survived both attempts.
	if err := os.Chmod(s.path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := reloaded.decideNetwork("", "tracker.example", "443"); !ok || d != deny {
		t.Errorf("the standing block did not survive; decideNetwork = %v,%v", d, ok)
	}
}

// A store written by a newer build is refused rather than reinterpreted: applying a
// deny under the wrong semantics is the failure that matters.
func TestLoadStoreRefusesANewerVersion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path, []byte(`{"version":99,"apps":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil {
		t.Error("loadStore must refuse a store newer than this build understands")
	}

	// A store predating the version field is this format, not a newer one.
	if err := os.WriteFile(s.path, []byte(`{"apps":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err != nil {
		t.Errorf("a version-less legacy store must still load; got %v", err)
	}
}

// A FIFO at permissions.json blocks in ReadFile before anything is prompted, so the
// tool hangs instead of failing. appKey already refuses a non-regular entrypoint for
// this reason; the store files get the same treatment.
func TestLoadStoreRefusesANonRegularStoreFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path := filepath.Join(dir, "bento-supervise", "permissions.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	if _, err := loadStore(); err == nil {
		t.Error("loadStore must refuse a non-regular permissions.json rather than block on it")
	}
}

// MkdirAll is a no-op on an existing directory, so a store dir created under a
// permissive umask kept its mode forever - and anyone who could write there could
// plant an allow the next run applies without prompting.
func TestWriteTightensAPermissiveStoreDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := s.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	fi, err := os.Stat(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("store dir mode = %#o, want group/world access removed", got)
	}
}

// The write is atomic AND durable, and leaves no temporary file behind - a stale
// store that comes back after power loss silently reverts a deny.
func TestSaveLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	s.rememberPath("k", "read", "/tmp/x", deny, false)
	if err := s.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("left a temporary file behind: %s", e.Name())
		}
	}
	if fi, err := os.Stat(s.path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("store mode = %v (%v), want 0600", fi, err)
	}
}

// A hand-edited or truncated store can carry an app entry decoded as null. Every read
// path treats an entry as a record and dereferences it, so before loadStore dropped
// them a single `"apps": {"sha256:...": null}` panicked the tool on startup - including
// `perms list` and `perms reset`, the two commands a human reaches for to fix it.
func TestLoadStoreDropsNullAppEntries(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	s.rememberPath("sha256:real", "read", "/data", allow, false)
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["apps"].(map[string]any)["sha256:null"] = nil
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadStore()
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	if _, ok := loaded.Apps["sha256:null"]; ok {
		t.Error("a null app entry must be dropped, not kept as a nil record")
	}
	if a := loaded.Apps["sha256:real"]; a == nil || a.Read["/data"] != allow {
		t.Errorf("the real app's decisions must survive: %+v", a)
	}
	// The read paths that dereference an entry: list, and the save merge's re-read.
	listPerms(loaded, &strings.Builder{})
	loaded.rememberPath("sha256:real", "read", "/other", allow, false)
	if err := loaded.save(); err != nil {
		t.Fatalf("save over a store holding a null entry: %v", err)
	}
}

// coversStore compared a relative grant against the absolute store dir, and
// filepath.Rel errors on that pair - which CoversResolved reads as "not under". A
// remembered grant spelled relatively (a manifest's read path, seeded by `perms
// import`; nothing validates it as absolute) therefore reported false and reached the
// store it names. The working directory is the anchor this pins, which is
// the right one for the enforced run (it executes in the supervise process) and the
// WRONG one for an exported manifest - which is why export refuses a relative grant
// outright rather than trusting this predicate to judge it.
func TestCoversStoreJudgesRelativeGrants(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{s.dir, filepath.Join(s.dir, "permissions.json"), dir} {
		rel, err := filepath.Rel(cwd, target)
		if err != nil {
			t.Fatal(err)
		}
		if !coversStore(rel, s.dir) {
			t.Errorf("coversStore(%q, %q) = false; a relative grant reaching the store must be refused", rel, s.dir)
		}
	}
	// A relative spelling of an unrelated directory is still judged on its merits.
	sibling, err := filepath.Rel(cwd, filepath.Join(dir, "elsewhere"))
	if err != nil {
		t.Fatal(err)
	}
	if coversStore(sibling, s.dir) {
		t.Errorf("coversStore(%q, %q) = true; a relative grant outside the store must not be refused", sibling, s.dir)
	}
}

// The dir was tightened only on the way out, so a run whose store dir was writable
// read the allow another uid planted there, applied it with no prompt, and warned
// about the exposure afterwards. The tighten has to happen before the read.
func TestLoadTightensAPermissiveStoreDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	fi, err := os.Stat(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("store dir mode after load = %#o, want group/world access removed", got)
	}
}

// A forget wrote its pre-lock snapshot, and the flock guaranteed it landed AFTER a
// concurrent run's save - so surgically deleting one key silently reverted every deny
// that run had just recorded. The deletion has to be applied as a delete-set under the
// lock, not as a whole-store overwrite.
func TestForgetDeletesUnderTheLockWithoutRevertingAConcurrentSave(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	seed, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	seed.rememberNetwork("", "tracker.example", "443", allow, true)
	seed.Global.Exec = string(policy.ExecAll)
	seed.app("sha256:aa").Entrypoint = "/w/a.sh"
	seed.app("sha256:bb").Entrypoint = "/w/b.sh"
	if err := seed.save(); err != nil {
		t.Fatal(err)
	}

	// The editing command loads first, mutates, and writes last - the losing side of
	// the race the lock decides.
	editor, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	delete(editor.Apps, "sha256:aa")
	delete(editor.Global.Network, netKey("tracker.example", "443"))
	editor.Global.Exec = ""

	run, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	run.rememberPath("sha256:bb", "read", "/etc/shadow", deny, false)
	if err := run.save(); err != nil {
		t.Fatal(err)
	}
	if err := editor.save(); err != nil {
		t.Fatal(err)
	}

	got, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Apps["sha256:aa"]; ok {
		t.Error("the forgotten app is still on disk; the deletion did not survive the merge")
	}
	if _, ok := got.Global.Network[netKey("tracker.example", "443")]; ok {
		t.Error("the forgotten global network rule is still on disk")
	}
	if got.Global.Exec != "" {
		t.Errorf("global exec = %q, want the forgotten rule gone", got.Global.Exec)
	}
	if d, ok := got.decidePath("sha256:bb", "read", "/etc/shadow"); !ok || d != deny {
		t.Errorf("the concurrent run's deny = (%q, %v), want deny; forget clobbered it", d, ok)
	}
}
