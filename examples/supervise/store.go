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
	Entrypoint  string              `json:"entrypoint"`
	Interpreter string              `json:"interpreter,omitempty"`
	Read        map[string]decision `json:"read,omitempty"`
	Write       map[string]decision `json:"write,omitempty"`
	Exec        string              `json:"exec,omitempty"`
	Network     map[string]decision `json:"network,omitempty"`
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
	s := &store{Version: 1, Apps: map[string]*appPerms{}, dir: dir, path: filepath.Join(dir, "permissions.json")}
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
	if s.Apps == nil {
		s.Apps = map[string]*appPerms{}
	}
	s.base = s.clone()
	return s, nil
}

// save persists the decisions this run changed, applied onto the current on-disk
// store under the lock. It deliberately does NOT write back the whole in-memory
// snapshot: a key the run only read must survive a concurrent `perms forget`/`reset`
// that deleted it while the run was parked at a prompt. Only entries this run added
// or changed (relative to what it loaded) are reapplied, so concurrent additions and
// deletions both stand.
func (s *store) save() error { return s.write(true) }

// overwrite writes the store atomically WITHOUT reconciling with the on-disk copy,
// so a deletion (forget/reset) sticks. The tradeoff is the other direction: a run
// that saves in the window between an edit command's unlocked load and this write is
// clobbered. That window is acceptable for a manual admin command.
func (s *store) overwrite() error { return s.write(false) }

// write persists the store atomically (temp + rename) at mode 0600, serialized by
// an advisory lock on a SEPARATE lockfile - never the store file, whose inode the
// rename replaces. When merge is set it writes this run's changes onto the current
// on-disk store; otherwise it writes the in-memory store wholesale.
func (s *store) write(merge bool) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(s.dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
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
		if disk, err := os.ReadFile(s.path); err == nil {
			if json.Unmarshal(disk, target) == nil && target.Apps == nil {
				target.Apps = map[string]*appPerms{}
			}
		}
		target.mergeChanges(s, s.base)
	}

	data, err := json.MarshalIndent(target, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// mergeChanges applies onto the on-disk store (the receiver) the decisions mem
// changed since it loaded (mem vs base). Disk stays authoritative for everything
// else, so a concurrent run's additions and a concurrent forget/reset's deletions
// both survive; a concurrent deny still wins a per-key conflict. A nil base (a store
// never loaded from disk) treats every entry as new.
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
		}
	}
}

// mergeDecisionChanges writes onto dst the entries of mem this run added or changed
// since load (those differing from base). An entry unchanged since load is left
// alone, so a concurrent delete is not undone. A concurrent deny already on dst wins
// over this run's non-deny, matching the store's deny-wins model.
func mergeDecisionChanges(dst *map[string]decision, mem, base map[string]decision) {
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

// mergeExec folds a disk exec value into this run's, deny-preferring: an unknown
// (empty) run value takes the disk value, and a disk deny beats this run's non-deny,
// so a concurrent exec deny survives the merge.
func mergeExec(mem, disk string) string {
	if mem == "" {
		return disk
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
			if underComponent(path, g) {
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
		if !underComponent(path, stored) {
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

// underComponent reports whether child is parent or lies beneath it on a path
// component boundary (so /a/b is under /a but /ab is not).
func underComponent(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
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
	return underComponent(resolveSymlinks(dir), resolveSymlinks(grant)) ||
		underComponent(resolveSymlinks(grant), resolveSymlinks(dir))
}

func resolveSymlinks(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}
