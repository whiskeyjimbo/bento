package bento

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}

// NetworkObservation is one host:port pair the script connected to, with the connect count.
type NetworkObservation struct {
	Host  string
	Port  int
	Count int
}

// ProfileResult holds the exit code, observed behavior, and a manifest
// pre-populated with the discovered rules.
type ProfileResult struct {
	ExitCode          int
	Observations      []NetworkObservation // sorted by Host, Port
	FSObservations    []string             // host paths the script opened successfully (deduped, sorted, noise-filtered)
	DeniedAttempts    []string             // host paths the script tried to open but were blocked (e.g. DangerousFiles)
	SuggestedManifest *Manifest
}

// Profile runs the script in permissive-network mode: every outbound host:port
// is allowed AND recorded. Other isolation (filesystem, exec, limits) stays in place.
func Profile(ctx context.Context, m *Manifest, opts ...Option) (*ProfileResult, error) {
	obs := &observations{counts: make(map[obsKey]int)}
	cb := func(req GrantRequest) GrantDecision {
		obs.record(req.Host, req.Port)
		return GrantAllow
	}

	var fsOpens []FSOpen
	fsCB := func(opens []FSOpen) { fsOpens = opens }

	// Non-nil but empty Network routes every connect through the grant callback.
	profile := *m
	profile.Network = &spec.NetworkPerm{Rules: nil}

	runOpts := append([]Option{
		WithGrantCallback(cb),
		WithFilesystemObserver(fsCB),
	}, opts...)
	code, err := Run(ctx, &profile, runOpts...)

	fsRead, denied := partitionFSObservations(fsOpens, m)
	result := &ProfileResult{
		ExitCode:          code,
		Observations:      obs.list(),
		FSObservations:    fsRead,
		DeniedAttempts:    denied,
		SuggestedManifest: synthesizeSuggested(m, obs.list(), fsRead),
	}
	return result, err
}

// partitionFSObservations splits the runner's open list into:
//   - read: successful opens worth suggesting (not covered, not dangerous, not the script,
//     and not interpreter library / locale / loader noise that bento auto-binds)
//   - denied: paths the script tried to open but bento's mandatory-deny list
//     blocks (regardless of success — even a "successful" open of a /dev/null
//     shadow is signal that the script tried to read a sensitive file)
func partitionFSObservations(opens []FSOpen, m *Manifest) (read, denied []string) {
	if len(opens) == 0 {
		return nil, nil
	}
	dangerous := make(map[string]struct{})
	for _, p := range spec.ExpandDangerousPaths(homeDir()) {
		dangerous[p] = struct{}{}
	}
	interpRoot := interpreterInstallRoot(m.Interpreter)
	for _, e := range opens {
		if _, bad := dangerous[e.Path]; bad {
			denied = append(denied, e.Path)
			continue
		}
		if !e.OK {
			continue // failed opens outside the deny list are noise
		}
		if e.Path == m.Script {
			continue
		}
		if isInterpreterDep(e.Path, interpRoot) {
			continue
		}
		if isUserToolNoise(e.Path) {
			continue
		}
		// Keep paths covered by the user's read grants: profile uses these
		// to tighten broad grants (e.g. `read: [./data]`) into the specific
		// files that were actually opened, so the generated manifest doesn't
		// over-grant.
		read = append(read, e.Path)
	}
	return read, denied
}

// isUserToolNoise reports whether a path is a known-noisy user-tool artifact
// that doesn't belong in a manifest's read list: build caches, editor
// scratch files, lockfiles, watcher state, language test caches. Including
// these makes the profile output unstable across runs and across machines.
// The list is conservative — paths a normal script would never legitimately
// declare as input. Callers can still hand-add any of these to a manifest.
func isUserToolNoise(p string) bool {
	base := filepath.Base(p)
	switch base {
	case ".DS_Store", "Thumbs.db", "desktop.ini":
		return true
	case ".python-version", ".node-version", ".ruby-version", ".tool-versions":
		// version manager probes — read on every script start, never user-relevant
		return true
	}
	// Editor lockfiles and swap files: ~lock.foo#, .#foo, .foo.swp, foo~
	if strings.HasPrefix(base, ".~lock.") || strings.HasPrefix(base, ".#") {
		return true
	}
	if strings.HasSuffix(base, ".swp") || strings.HasSuffix(base, ".swo") || strings.HasSuffix(base, "~") {
		return true
	}
	// Build / test / package-manager caches.
	for _, marker := range []string{
		"/__pycache__/", "/.pytest_cache/", "/.mypy_cache/", "/.ruff_cache/",
		"/.tox/", "/.coverage", "/.hypothesis/",
		"/node_modules/.cache/", "/.next/cache/", "/.turbo/", "/.parcel-cache/",
		"/.gradle/", "/.m2/repository/",
		"/.cargo/registry/", "/target/debug/", "/target/release/",
		"/.terraform/", "/.serverless/",
		"/.watchmanconfig", "/.watchman-cookie-",
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

// isInterpreterDep reports whether a path is part of the interpreter's
// runtime chain (shared libs, loader data, locale tables, gconv modules)
// rather than user data. Bento's bwrap setup already binds these via the
// interpreter resolution; including them in the manifest's read list bloats
// it with paths that vary across hosts.
func isInterpreterDep(p, interpRoot string) bool {
	// System library and loader directories.
	for _, prefix := range []string{
		"/nix/store/",
		"/usr/lib/", "/usr/lib64/",
		"/lib/", "/lib64/",
		"/usr/local/lib/", "/usr/local/lib64/",
		"/usr/share/locale/",
		"/run/current-system/sw/",
		"/proc/", "/sys/", "/dev/",
	} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	// Loader and libc data files anywhere on disk.
	if strings.Contains(p, "/locale/") || strings.Contains(p, "/gconv/") {
		return true
	}
	switch p {
	case "/etc/ld.so.cache", "/etc/ld.so.preload":
		return true
	}
	// Anything under the interpreter's installation prefix (e.g.
	// ~/.local/share/mise/installs/python/3.14.4/...).
	if interpRoot != "" && strings.HasPrefix(p, interpRoot) {
		return true
	}
	return false
}

// interpreterInstallRoot returns the directory above the interpreter's
// containing bin/ (e.g. for /home/u/.../python/3.14.4/bin/python3 it
// returns /home/u/.../python/3.14.4). Empty string if the interpreter
// cannot be resolved or has no bin/ in its path.
func interpreterInstallRoot(interp string) string {
	if interp == "" {
		return ""
	}
	resolved, err := exec.LookPath(interp)
	if err != nil {
		return ""
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return ""
	}
	dir := filepath.Dir(abs)
	if filepath.Base(dir) == "bin" {
		root := filepath.Dir(dir)
		// Don't filter the whole filesystem if interpreter is /bin/bash etc.
		if root == "/" || root == "/usr" {
			return ""
		}
		return root + "/"
	}
	return ""
}

type obsKey struct {
	host string
	port int
}

type observations struct {
	mu     sync.Mutex
	counts map[obsKey]int
}

func (o *observations) record(host string, port int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.counts[obsKey{host, port}]++
}

func (o *observations) list() []NetworkObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]NetworkObservation, 0, len(o.counts))
	for k, c := range o.counts {
		out = append(out, NetworkObservation{Host: k.host, Port: k.port, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// synthesizeSuggested copies the original manifest, populates Network.Rules
// with discovered host:port pairs, and uses FS observations to tighten Read.
//
// When the observer recorded specific file paths, those replace the blanket
// script-directory grant — the user can re-add the directory grant if they
// want broader access, but the default should be the minimum the script
// actually used. When the observer recorded nothing (script did no file IO,
// or the observer backend was unavailable), we keep the conservative
// script-directory grant from the original manifest.
func synthesizeSuggested(original *Manifest, obs []NetworkObservation, fsPaths []string) *Manifest {
	out := *original
	rules := make([]NetworkRule, 0, len(obs))
	for _, o := range obs {
		rules = append(rules, NetworkRule{
			Host: o.Host,
			Port: strconv.Itoa(o.Port),
		})
	}
	if len(rules) == 0 {
		// Profile saw no network use; emit no `network:` block at all so the
		// generated manifest reads "no network" by absence (the same default
		// as zero-config) rather than the ambiguous `network: { rules: [] }`.
		out.Network = nil
	} else {
		out.Network = &NetworkPerm{Rules: rules}
	}
	if len(fsPaths) > 0 {
		out.Read = append([]string{}, fsPaths...)
	}
	return &out
}
