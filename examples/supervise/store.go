package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/whiskeyjimbo/bento/policy"
)

// The permission store is the wrapper's persistent memory of human decisions - the
// Claude-Code analog of a settings allow/deny list. It is NOT bento policy and
// bento never sees it: it records what a human answered so a later run auto-applies
// known decisions and prompts only for the unknown. It changes which questions are
// asked, never what bento enforces.
//
// Two layers: per-app decisions keyed by the SHA of the entrypoint's bytes (so
// changed code re-prompts), and global decisions that apply to every app. Deny
// wins across layers: deny (either layer) > per-app allow > global allow > prompt.

type decision string

const (
	allow decision = "allow"
	deny  decision = "deny"
)

// appPerms are the decisions remembered for one app. exec is bento's tri-state
// (none / none-strict / all), stored verbatim.
type appPerms struct {
	Entrypoint  string `json:"entrypoint"`
	Interpreter string `json:"interpreter,omitempty"`
	// InterpreterArgs are the interpreter's own options; the script's arguments are
	// not remembered here at all.
	InterpreterArgs []string            `json:"interpreter_args,omitempty"`
	Read            map[string]decision `json:"read,omitempty"`
	Write           map[string]decision `json:"write,omitempty"`
	Exec            string              `json:"exec,omitempty"`
	Network         map[string]decision `json:"network,omitempty"`
}

// globalPerms are decisions that apply to every app, standing above the per-app
// layer: a global deny is the headline standing-denylist (e.g. block a tracker
// across every script, surviving code changes, since a fresh app key still sees it).
type globalPerms struct {
	Read    map[string]decision `json:"read,omitempty"`
	Write   map[string]decision `json:"write,omitempty"`
	Exec    string              `json:"exec,omitempty"`
	Network map[string]decision `json:"network,omitempty"`
}

type store struct {
	Version int                  `json:"version"`
	Global  globalPerms          `json:"global"`
	Apps    map[string]*appPerms `json:"apps"`

	dir  string // the store directory (shielded from the trial; refused as a grant)
	path string // permissions.json inside dir

	// recordedDeny is set when this run stored a deny or standing block. It lets the
	// caller tell a lost security decision (a save that failed after a deny) from a
	// benign one, so an exit code never reports a clean run over a dropped block.
	recordedDeny bool

	// base is a deep copy of the decisions as loaded, so save can persist only what
	// THIS process changed rather than its whole snapshot. Without it, a run that
	// loads the store, parks at a prompt, and saves last would rewrite every key it
	// merely read - resurrecting one a concurrent `perms forget`/`reset` deleted in
	// the meantime, silently undoing the revoke. Nil for a store never loaded (a
	// fresh empty one), where every entry is by definition new.
	base *store
}

// clone deep-copies the persisted decisions (not the dir/path/base bookkeeping), so
// a snapshot survives later mutation of the original.
func (s *store) clone() *store {
	cp := &store{Version: s.Version, Apps: map[string]*appPerms{}}
	cp.Global = globalPerms{
		Read:    cloneDecisions(s.Global.Read),
		Write:   cloneDecisions(s.Global.Write),
		Network: cloneDecisions(s.Global.Network),
		Exec:    s.Global.Exec,
	}
	for k, a := range s.Apps {
		ac := *a
		ac.Read = cloneDecisions(a.Read)
		ac.Write = cloneDecisions(a.Write)
		ac.Network = cloneDecisions(a.Network)
		cp.Apps[k] = &ac
	}
	return cp
}

// normalizeApps makes a decoded app map safe to use: it supplies the map when the
// JSON omitted it, and drops any entry decoded as null. Every read path treats an app
// entry as a record and dereferences it, so a hand-edited `"apps": {"sha256:...": null}`
// would panic on load, on list, on export. A null entry records no decision, so
// dropping it loses nothing - unlike bytes that will not parse at all, which stay fatal
// because a deny could be hiding in them.
func normalizeApps(apps map[string]*appPerms) map[string]*appPerms {
	if apps == nil {
		return map[string]*appPerms{}
	}
	for k, a := range apps {
		if a == nil {
			delete(apps, k)
		}
	}
	return apps
}

func cloneDecisions(m map[string]decision) map[string]decision {
	if m == nil {
		return nil
	}
	out := make(map[string]decision, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// storeDir resolves the store directory, honoring XDG_CONFIG_HOME.
func storeDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "bento-supervise"), nil
}

// loadStore reads the store, or returns an empty one if it does not exist yet.
func loadStore() (*store, error) {
	dir, err := storeDir()
	if err != nil {
		return nil, err
	}
	// Create the store directory now rather than at first write, so the shields and
	// the trial's DenyPaths compare a directory that really exists rather than one
	// spelling of a path that does not. Best-effort on purpose: reading the store must
	// not require permission to create it, or `perms list` on a read-only config home
	// fails where it used to print what is there. resolveSymlinks keeps the shields
	// correct either way, and the write path below reports the failure loudly.
	_ = os.MkdirAll(dir, 0o700)
	// Tighten BEFORE reading, not only on the way out: a dir left group/world-writable
	// is one another uid can plant an allow in, and tightening it after the run has
	// already applied that allow warns about an exposure that has happened. A dir that
	// is not there yet has nothing to tighten and nothing to read; any other failure
	// (someone else owns it, so the chmod is refused) is fatal, because it says the
	// decisions in there are not ours to trust.
	if err := tightenStoreDir(dir); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	s := &store{Version: storeVersion, Apps: map[string]*appPerms{}, dir: dir, path: filepath.Join(dir, "permissions.json")}
	if err := requireRegular(s.path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("permission store %s is corrupt: %w", s.path, err)
	}
	if err := checkVersion(s.Version, s.path); err != nil {
		return nil, err
	}
	// A store predating the version field is this format; stamp it so the write back
	// carries the version it is actually in.
	s.Version = storeVersion
	s.Apps = normalizeApps(s.Apps)
	s.base = s.clone()
	return s, nil
}

// emptyStore is a store with no decisions, pointed at the real store location. It is
// what `perms reset` recovers with when the file on disk cannot be read: reset
// discards the contents wholesale, so it needs nothing from them.
func emptyStore() (*store, error) {
	dir, err := storeDir()
	if err != nil {
		return nil, err
	}
	return &store{Version: storeVersion, Apps: map[string]*appPerms{}, dir: dir, path: filepath.Join(dir, "permissions.json")}, nil
}

// save persists the decisions this run changed, applied onto the current on-disk
// store under the lock. It deliberately does NOT write back the whole in-memory
// snapshot: a key the run only read must survive a concurrent `perms forget`/`reset`
// that deleted it while the run was parked at a prompt. Only entries this run added,
// changed, or DELETED (relative to what it loaded) are reapplied, so concurrent
// additions and deletions both stand.
func (s *store) save() error { return s.write(true) }

// overwrite writes the store atomically WITHOUT reconciling with the on-disk copy, so
// the in-memory value wins outright. The tradeoff is that a run which saves in the
// window between an unlocked load and this write is clobbered, so it is used only where
// the merge would give the wrong answer: an operator-typed `perms global allow`, which
// the merge's deny-preference would override, and a reset recovering a store that could
// not be read, which has no base to diff a deletion against.
func (s *store) overwrite() error { return s.write(false) }

// write persists the store atomically (temp + rename) at mode 0600, serialized by
// an advisory lock on a SEPARATE lockfile - never the store file, whose inode the
// rename replaces. When merge is set it writes this run's changes onto the current
// on-disk store; otherwise it writes the in-memory store wholesale.
func (s *store) write(merge bool) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	// MkdirAll is a no-op on a directory that already exists, so a store dir created
	// with a permissive umask (or by an earlier version) keeps whatever mode it has.
	// loadStore tightens it too, which is where the exposure actually closes; this one
	// covers the write paths that never loaded (a reset recovering an unreadable store)
	// and the directory being widened while the run was parked at a prompt.
	if err := tightenStoreDir(s.dir); err != nil {
		return err
	}
	lockPath := filepath.Join(s.dir, ".lock")
	if err := requireRegular(lockPath); err != nil {
		return err
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	target := s
	if merge {
		// Re-read the current store under the lock and apply only what this run changed,
		// so finishing last preserves both a concurrent run's additions and a concurrent
		// edit command's deletions. A key this run merely read is left as disk has it.
		target = &store{Version: s.Version, Apps: map[string]*appPerms{}}
		// A store that cannot be read or parsed must NOT be merged onto: doing so writes
		// this run's delta alone over decisions that are still on disk, so an unreadable
		// store silently becomes an empty one and every remembered deny is gone. Only a
		// missing file is tolerable - that is the genuine first write. loadStore treats
		// these same bytes as fatal; the write path has to agree.
		disk, err := os.ReadFile(s.path)
		switch {
		case err == nil:
			if err := json.Unmarshal(disk, target); err != nil {
				return fmt.Errorf("permission store %s is corrupt: %w", s.path, err)
			}
			if err := checkVersion(target.Version, s.path); err != nil {
				return err
			}
			target.Apps = normalizeApps(target.Apps)
		case !os.IsNotExist(err):
			return err
		}
		target.mergeChanges(s, s.base)
	}

	data, err := json.MarshalIndent(target, "", "  ")
	if err != nil {
		return err
	}
	return writeFileDurably(s.path, data)
}

// writeFileDurably replaces path with data atomically and durably: the content is
// written to a temporary file in the same directory, flushed, and renamed over the
// target, then the directory itself is flushed so the rename survives too. Without the
// flushes the rename is atomic against a torn write but not against power loss - the
// store could come back with stale content, which silently reverts a deny. A
// zero-length store fails closed on the next load, which is the tolerable outcome;
// stale content is not.
func writeFileDurably(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once the rename below has moved it away
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// The rename has already succeeded, so the data IS on disk; a directory that will
	// not flush only means it might not survive a power loss. Reporting that as a
	// failed save would tell the caller a deny was lost when it was not, and that one
	// message has to stay trustworthy.
	d, err := os.Open(dir)
	if err == nil {
		defer d.Close()
		err = d.Sync()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: could not flush %s; the store is written but may not survive a power loss: %v\n", dir, err)
	}
	return nil
}

// tightenStoreDir removes group and world access from an existing store directory,
// warning when it does. The store is the record of what a human approved, so a
// directory others can write is one where they can plant an allow this tool then
// applies without prompting.
func tightenStoreDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	mode := fi.Mode().Perm()
	if mode&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "supervise: permission store %s was group/world-accessible (%#o); tightened to 0700 - it records what you approved.\n", dir, mode)
	return nil
}

// requireRegular refuses a store file that is not a regular file, for the reason
// appKey refuses a non-regular entrypoint: a FIFO or device at permissions.json or
// .lock blocks in ReadFile or OpenFile before anything is prompted, so the tool hangs
// instead of failing. A path that does not exist yet is the first-write case.
//
// It refuses a file somebody else owns for a separate reason: tightening the directory
// stops the NEXT plant, not the one already sitting there from when the directory was
// writable. These bytes are read as decisions a human made, and a run applies a
// remembered allow with no prompt, so a file this uid did not write is not a store to
// read - it is somebody else's answers. `perms reset` is the way out, and survives this
// error by design.
func requireRegular(path string) error {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("permission store %s is not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read ownership of %s", path)
	}
	if euid := uint32(os.Geteuid()); st.Uid != euid {
		return fmt.Errorf("permission store %s is owned by uid %d, not you (%d); it records what YOU approved, so it will not be read. remove it, or clear it with `supervise perms reset`", path, st.Uid, euid)
	}
	return nil
}

// storeVersion is the format this build writes and understands. A store written by a
// newer build is refused rather than reinterpreted: its decisions may mean something
// this build would apply wrongly, and applying a deny wrongly is the failure that
// matters. Version 0 is a store written before the field existed.
const storeVersion = 1

func checkVersion(v int, path string) error {
	if v > storeVersion {
		return fmt.Errorf("permission store %s is version %d, newer than this build understands (%d); upgrade supervise rather than letting it reinterpret your decisions", path, v, storeVersion)
	}
	return nil
}

// mergeChanges applies onto the on-disk store (the receiver) the decisions mem
// changed since it loaded (mem vs base) - including the ones it REMOVED, so a
// `perms forget`/`reset` is a delete-set applied under the lock rather than a
// pre-lock snapshot written over whatever landed meanwhile. Disk stays authoritative
// for everything else, so a concurrent run's additions and a concurrent deletion both
// survive; a concurrent deny still wins a per-key conflict. A nil base (a store never
// loaded from disk) treats every entry as new and can express no deletion.
func (disk *store) mergeChanges(mem, base *store) {
	if base == nil {
		base = &store{}
	}
	mergeDecisionChanges(&disk.Global.Read, mem.Global.Read, base.Global.Read)
	mergeDecisionChanges(&disk.Global.Write, mem.Global.Write, base.Global.Write)
	mergeDecisionChanges(&disk.Global.Network, mem.Global.Network, base.Global.Network)
	if mem.Global.Exec != base.Global.Exec {
		disk.Global.Exec = mergeExec(mem.Global.Exec, disk.Global.Exec)
	}
	// An app present at load and gone now was forgotten; drop it from disk. Done before
	// the change loop so nothing depends on the order the maps iterate in.
	for key := range base.Apps {
		if _, ok := mem.Apps[key]; !ok {
			delete(disk.Apps, key)
		}
	}
	for key, ma := range mem.Apps {
		ba := base.Apps[key]
		// An app this run did not touch is left exactly as disk has it - including
		// absent, if a concurrent forget deleted it. Only a real change this run made
		// may (re)create the disk entry, so an untouched app is never resurrected.
		if ba != nil && reflect.DeepEqual(*ma, *ba) {
			continue
		}
		da := disk.Apps[key]
		if da == nil {
			da = &appPerms{}
			disk.Apps[key] = da
		}
		var baseApp appPerms
		if ba != nil {
			baseApp = *ba
		}
		mergeDecisionChanges(&da.Read, ma.Read, baseApp.Read)
		mergeDecisionChanges(&da.Write, ma.Write, baseApp.Write)
		mergeDecisionChanges(&da.Network, ma.Network, baseApp.Network)
		if ma.Exec != baseApp.Exec {
			da.Exec = mergeExec(ma.Exec, da.Exec)
		}
		if ma.Entrypoint != "" {
			da.Entrypoint = ma.Entrypoint
		}
		if ma.Interpreter != "" {
			da.Interpreter = ma.Interpreter
			// Taken with it rather than tested on its own: they are one invocation, and a
			// concurrent write that kept the other run's options beside this run's
			// interpreter would name a command neither run made.
			da.InterpreterArgs = ma.InterpreterArgs
		}
	}
}

// mergeDecisionChanges writes onto dst the entries of mem this run added, changed, or
// removed since load (those differing from base). An entry unchanged since load is left
// alone, so a concurrent delete is not undone. A concurrent deny already on dst wins
// over this run's non-deny, matching the store's deny-wins model - but not over a
// removal, which is the operator saying that decision should not exist at all.
func mergeDecisionChanges(dst *map[string]decision, mem, base map[string]decision) {
	for k := range base {
		if _, ok := mem[k]; !ok {
			delete(*dst, k)
		}
	}
	for k, v := range mem {
		if bv, ok := base[k]; ok && bv == v {
			continue
		}
		if *dst == nil {
			*dst = map[string]decision{}
		}
		if cur, ok := (*dst)[k]; ok && cur == deny && v != deny {
			continue
		}
		(*dst)[k] = v
	}
}

// mergeExec folds a disk exec value into this run's, deny-preferring: a disk deny beats
// this run's non-deny, so a concurrent exec deny survives the merge. It is reached only
// where mem differs from base, so an empty mem is a REMOVAL (forget/reset cleared the
// rule) rather than "this run has no opinion" - taking disk's value there would leave
// the rule the operator just forgot standing.
func mergeExec(mem, disk string) string {
	if mem == "" {
		return ""
	}
	if execDecision(disk) == deny && execDecision(mem) != deny {
		return disk
	}
	return mem
}

// appKey identifies an app by the SHA-256 of its entrypoint bytes: same code, same
// key, so approvals are shared regardless of where the script lives, and changed
// code gets a fresh key and re-prompts. It is launcher identity, not behavior
// identity (a script that sources or downloads more code keeps its key) - so it is
// convenience memory, not a security boundary.
func appKey(entrypoint string) (string, error) {
	// Only hash a regular file: a FIFO or device entrypoint would otherwise block or
	// misbehave in ReadFile.
	if fi, err := os.Stat(entrypoint); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("entrypoint %q is not a regular file", entrypoint)
	}
	data, err := os.ReadFile(entrypoint)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// shortKey is the human-typeable handle for an app: the leading hex of its
// content hash, git-style. list prints it and forget accepts any unambiguous
// prefix of it.
func shortKey(key string) string {
	hex := strings.TrimPrefix(key, "sha256:")
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

// resolveAppPrefix maps a hex prefix (as printed by shortKey) to the one app key
// it identifies. It errors if the prefix matches no app or more than one, so
// forget never deletes the wrong record on an ambiguous handle.
func (s *store) resolveAppPrefix(prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimPrefix(prefix, "sha256:"))
	if prefix == "" {
		return "", fmt.Errorf("empty app handle")
	}
	var matched []string
	for key := range s.Apps {
		hex := strings.TrimPrefix(key, "sha256:")
		if strings.HasPrefix(hex, prefix) {
			matched = append(matched, key)
		}
	}
	switch len(matched) {
	case 0:
		return "", fmt.Errorf("no app matches %q", prefix)
	case 1:
		return matched[0], nil
	default:
		return "", fmt.Errorf("%q is ambiguous (%d apps match); use a longer prefix", prefix, len(matched))
	}
}

// resolveLattice applies deny-wins to a (global, app) decision pair.
func resolveLattice(global, app decision) (decision, bool) {
	if global == deny || app == deny {
		return deny, true
	}
	if app == allow || global == allow {
		return allow, true
	}
	return "", false
}

// normalizeHost lowercases and strips a trailing dot, matching bento's own host
// matching - so a store key cannot be evaded by case or a trailing dot. It does
// NOT fold IDN homographs (neither does bento); a hostname key never covers the
// server's IP literal. These are advisory against a determined target.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func netKey(host, port string) string { return normalizeHost(host) + ":" + port }

// splitNetKey reverses netKey. The key always ends in ":port" (netKey builds it),
// so the host is everything before the last colon - correct for an IPv6 literal too.
func splitNetKey(k string) (host, port string) {
	if i := strings.LastIndex(k, ":"); i >= 0 {
		return k[:i], k[i+1:]
	}
	return k, ""
}

// denyUnderAllow names a filesystem deny that lies under an allowed grant of the
// same kind. bento has no per-path deny, so the covering grant binds the whole
// tree: the enforced run cannot honor the sub-deny, and a manifest (a pure
// allowlist) cannot express it at all.
type denyUnderAllow struct{ kind, deny, allow string }

// readGrants is the set of paths readable under a policy: everything granted read,
// plus everything granted write, since a write grant is read-write (bento binds
// writes RW). Read coverage is checked against this union so a read-deny under a
// write-allow is caught; write coverage stays write-only, since a read grant does
// not confer write. The union is deduplicated so a path granted both read and write
// is not double-counted.
func readGrants(read, write []string) []string {
	seen := make(map[string]bool, len(read)+len(write))
	out := make([]string, 0, len(read)+len(write))
	for _, p := range read {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range write {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// deniesUnderAllows returns each deny that a grant would cover, so one caller can
// warn about it and another (export) can refuse it. Both sets are passed explicitly
// so export can supply effective, cross-layer decisions. The match is reflexive: a
// deny at the exact same path as a grant is covered too - a write-allow and a
// read-deny on the same path leave that path readable, which the grant/deny sets
// never collide on within one kind (a path is allow xor deny there) but do across
// kinds through readGrants.
func deniesUnderAllows(grants, denies []string, kind string) []denyUnderAllow {
	var out []denyUnderAllow
	for _, path := range denies {
		for _, g := range grants {
			if policy.CoversResolved(g, path) {
				out = append(out, denyUnderAllow{kind, path, g})
			}
		}
	}
	return out
}

// decideNetwork returns the remembered decision for a host:port, or false if
// unknown (prompt). Deny wins across the global and per-app layers.
func (s *store) decideNetwork(key, host, port string) (decision, bool) {
	k := netKey(host, port)
	var app decision
	if a := s.Apps[key]; a != nil {
		app = a.Network[k]
	}
	return resolveLattice(s.Global.Network[k], app)
}

// decidePath returns the remembered decision for a filesystem path, or false if
// unknown. Each layer is matched by longest path-component prefix (an allow of a
// directory answers a prompt for a file inside it), deny-winning on an equal-length
// tie WITHIN a layer; the global and per-app results are then combined deny-wins.
// The layers are matched separately on purpose: a broad global deny must beat a
// more-specific per-app allow (the standing denylist), which a union match would
// invert. The global layer is consulted even when the app is unknown, so a global
// rule survives a code change that mints a fresh app key.
func (s *store) decidePath(key, kind, path string) (decision, bool) {
	globalM, appM := s.Global.Read, map[string]decision(nil)
	if kind == "write" {
		globalM = s.Global.Write
	}
	if a := s.Apps[key]; a != nil {
		appM = a.Read
		if kind == "write" {
			appM = a.Write
		}
	}
	g, _ := longestPrefixMatch(globalM, path)
	app, _ := longestPrefixMatch(appM, path)
	return resolveLattice(g, app)
}

// longestPrefixMatch returns the decision stored for the longest path-component
// prefix of path within one layer's map, deny-winning on an equal-length tie. The
// empty decision with false means no stored path covers it.
func longestPrefixMatch(m map[string]decision, path string) (decision, bool) {
	best, bestDec := "", decision("")
	for stored, d := range m {
		if !policy.CoversResolved(stored, path) {
			continue
		}
		if len(stored) > len(best) || (len(stored) == len(best) && d == deny) {
			best, bestDec = stored, d
		}
	}
	if best == "" {
		return "", false
	}
	return bestDec, true
}

// decideExec returns the remembered subprocess-spawning decision, combining the
// global and per-app layers deny-wins. Unknown (false) means prompt. The global
// layer applies to an unknown app too.
func (s *store) decideExec(key string) (decision, bool) {
	var app decision
	if a := s.Apps[key]; a != nil {
		app = execDecision(a.Exec)
	}
	return resolveLattice(execDecision(s.Global.Exec), app)
}

// execDecision maps a stored exec tri-state to a lattice decision: allow for "all",
// deny for any other non-empty value (none / none-strict), unknown for "".
func execDecision(e string) decision {
	switch {
	case e == "":
		return ""
	case e == string(policy.ExecAll):
		return allow
	default:
		return deny
	}
}

// rememberNetwork records a network decision, per-app or (global) for every app.
func (s *store) rememberNetwork(key, host, port string, d decision, global bool) {
	if d == deny {
		s.recordedDeny = true
	}
	k := netKey(host, port)
	if global {
		if s.Global.Network == nil {
			s.Global.Network = map[string]decision{}
		}
		s.Global.Network[k] = d
		return
	}
	a := s.app(key)
	if a.Network == nil {
		a.Network = map[string]decision{}
	}
	a.Network[k] = d
}

// rememberPath records a filesystem decision, per-app or (global) for every app.
func (s *store) rememberPath(key, kind, path string, d decision, global bool) {
	if d == deny {
		s.recordedDeny = true
	}
	m := &s.Global.Read
	if global {
		if kind == "write" {
			m = &s.Global.Write
		}
	} else {
		a := s.app(key)
		m = &a.Read
		if kind == "write" {
			m = &a.Write
		}
	}
	if *m == nil {
		*m = map[string]decision{}
	}
	(*m)[path] = d
}

// rememberExec records a subprocess-spawning decision, per-app or (global) for
// every app, storing bento's tri-state verbatim.
func (s *store) rememberExec(key string, d decision, global bool) {
	mode := string(policy.ExecAll)
	if d == deny {
		mode = string(policy.ExecNone)
		s.recordedDeny = true
	}
	if global {
		s.Global.Exec = mode
		return
	}
	s.app(key).Exec = mode
}

// app returns the per-app record, creating it if absent.
func (s *store) app(key string) *appPerms {
	a := s.Apps[key]
	if a == nil {
		a = &appPerms{}
		s.Apps[key] = a
	}
	return a
}

// coversStore reports whether a grant path would expose the store: the grant
// contains the store dir, or lies inside it. Symlinks are resolved so an alias
// cannot slip past. The wrapper refuses such a grant so the target can never read
// or tamper with the store through an approved path.
func coversStore(grant, dir string) bool {
	g, d := resolveSymlinks(grant), resolveSymlinks(dir)
	// Both sides must be absolute for the comparison to mean anything: filepath.Rel
	// errors out on a relative/absolute pair and CoversResolved reads that error as
	// "not under", which answers "this grant does not touch the store" about a path
	// that does. resolveSymlinks anchors to the working directory, so this only fires
	// when there is no working directory to anchor to (it was deleted out from under
	// the process) - unjudgeable, and the store is what is at stake.
	if !filepath.IsAbs(g) || !filepath.IsAbs(d) {
		return true
	}
	return policy.CoversResolved(g, d) || policy.CoversResolved(d, g)
}

// resolveSymlinks resolves p through its deepest EXISTING ancestor, rejoining the
// part that does not exist yet. EvalSymlinks alone fails on any path that is not
// fully present, and falling back to the raw string then compares two different
// namespaces: with a symlinked config home, the store dir resolves to its real
// location while a file that does not exist inside it keeps the link spelling, and
// coversStore finds no overlap between them - answering "this grant does not touch
// the store" about a path directly inside it. Resolving the ancestor keeps both sides
// in one namespace whether or not the leaf exists. A relative path is anchored to the
// working directory first, for the same one-namespace reason: EvalSymlinks resolves a
// relative path to a relative result, which no absolute store dir can be compared against.
func resolveSymlinks(p string) string {
	cleaned := filepath.Clean(p)
	if abs, err := filepath.Abs(cleaned); err == nil {
		cleaned = abs
	}
	rest := ""
	for cur := cleaned; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return cleaned // nothing along the path exists; the raw spelling is all there is
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}
