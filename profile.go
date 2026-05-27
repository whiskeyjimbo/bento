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
		if isCovered(e.Path, m.Read) {
			continue
		}
		if isInterpreterDep(e.Path, interpRoot) {
			continue
		}
		read = append(read, e.Path)
	}
	return read, denied
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

func isCovered(p string, rules []string) bool {
	for _, r := range rules {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
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
// with discovered host:port pairs, and appends FS observations to Read.
func synthesizeSuggested(original *Manifest, obs []NetworkObservation, fsPaths []string) *Manifest {
	out := *original
	rules := make([]NetworkRule, 0, len(obs))
	for _, o := range obs {
		rules = append(rules, NetworkRule{
			Host: o.Host,
			Port: strconv.Itoa(o.Port),
		})
	}
	out.Network = &NetworkPerm{Rules: rules}
	if len(fsPaths) > 0 {
		out.Read = append(append([]string{}, original.Read...), fsPaths...)
	}
	return &out
}
