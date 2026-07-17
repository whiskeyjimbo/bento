package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

type store struct {
	Version int `json:"version"`
	Global  struct {
		Network map[string]decision `json:"network,omitempty"`
	} `json:"global"`
	Apps map[string]*appPerms `json:"apps"`

	dir  string // the store directory (shielded from the trial; refused as a grant)
	path string // permissions.json inside dir
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
	return s, nil
}

// save writes the store atomically (temp + rename) at mode 0600, serialized by an
// advisory lock on a SEPARATE lockfile - never the store file, whose inode the
// rename replaces.
func (s *store) save() error {
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

	// Re-read under the lock and fold in anything a concurrent run wrote, so
	// finishing last does not clobber another run's newly-remembered decisions (in
	// particular a deny). This run's own values win on a per-key conflict.
	if disk, err := os.ReadFile(s.path); err == nil {
		var d store
		if json.Unmarshal(disk, &d) == nil {
			s.fillMissing(&d)
		}
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// fillMissing copies entries present on disk but absent in s, so a concurrent
// run's writes survive this run's save. This run's values win where both have a
// key; disk-only keys (another run's additions) are preserved.
func (s *store) fillMissing(disk *store) {
	fill := func(dst *map[string]decision, src map[string]decision) {
		for k, v := range src {
			if *dst == nil {
				*dst = map[string]decision{}
			}
			if _, ok := (*dst)[k]; !ok {
				(*dst)[k] = v
			}
		}
	}
	fill(&s.Global.Network, disk.Global.Network)
	for key, da := range disk.Apps {
		ma := s.Apps[key]
		if ma == nil {
			s.Apps[key] = da
			continue
		}
		fill(&ma.Read, da.Read)
		fill(&ma.Write, da.Write)
		fill(&ma.Network, da.Network)
		if ma.Exec == "" {
			ma.Exec = da.Exec
		}
		if ma.Entrypoint == "" {
			ma.Entrypoint = da.Entrypoint
		}
		if ma.Interpreter == "" {
			ma.Interpreter = da.Interpreter
		}
	}
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
// unknown. It matches by longest path-component prefix (an allow of a directory
// answers a prompt for a file inside it), deny-winning on an equal-length tie.
func (s *store) decidePath(key, kind, path string) (decision, bool) {
	a := s.Apps[key]
	if a == nil {
		return "", false
	}
	m := a.Read
	if kind == "write" {
		m = a.Write
	}
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

// rememberPath records a filesystem decision for an app.
func (s *store) rememberPath(key, kind, path string, d decision) {
	a := s.app(key)
	m := &a.Read
	if kind == "write" {
		m = &a.Write
	}
	if *m == nil {
		*m = map[string]decision{}
	}
	(*m)[path] = d
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
