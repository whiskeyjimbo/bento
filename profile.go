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
	FSObservations    []string             // host paths the script opened for read, deduped/sorted/noise-filtered
	FSWrites          []string             // host paths the script opened for write, deduped/sorted/noise-filtered
	TmpfsWrites       []string             // /sandbox/* writes that landed on tmpfs (no host destination)
	DeniedAttempts    []string             // host paths the script tried to open but were blocked (e.g. DangerousFiles)
	BlockedReads      []string             // host paths the script tried to read but were not bind-mounted (deny-by-default; safe to add to `read:` if intentional)
	BlockedConnects   []ConnectAttempt     // outbound connect() calls that the libproxychains shim could not capture (typically denied by Landlock TCP for compiled binaries)
	SuggestedManifest *Manifest
	// NarrowedReadPaths lists read paths that conflicted with mandatory-deny
	// (e.g. $HOME, whose deny shadows would fail bwrap) and were narrowed or
	// dropped during manifest synthesis. Empty when nothing was narrowed.
	NarrowedReadPaths []string
}

// Profile runs the script in permissive-network and permissive-write mode:
// every outbound host:port is allowed AND recorded, and the script's directory
// plus /tmp are bound writable so realistic "fetch and save" scripts complete
// instead of crashing on Read-only-file-system errors. Other isolation
// (mandatory-deny, exec, limits) stays in place.
func Profile(ctx context.Context, m *Manifest, opts ...Option) (*ProfileResult, error) {
	obs := &observations{counts: make(map[obsKey]int)}
	cb := func(req GrantRequest) GrantDecision {
		obs.record(req.Host, req.Port)
		return GrantAllow
	}

	var fsOpens []FSOpen
	fsCB := func(opens []FSOpen) { fsOpens = opens }

	var connects []ConnectAttempt
	connectCB := func(c []ConnectAttempt) { connects = c }

	// Non-nil but empty Network routes every connect through the grant callback.
	profile := *m
	profile.Network = &spec.NetworkPerm{Rules: nil}
	// Permissive writes during profile: the script's directory and /tmp.
	// Mandatory-deny still shadows credentials and shell rc files.
	profile.Write = append([]string{}, m.Write...)
	if scriptDir := filepath.Dir(m.Script); scriptDir != "" && scriptDir != "/" {
		profile.Write = appendUnique(profile.Write, scriptDir)
	}
	if _, err := os.Stat("/tmp"); err == nil {
		profile.Write = appendUnique(profile.Write, "/tmp")
	}

	runOpts := append([]Option{
		WithGrantCallback(cb),
		WithFilesystemObserver(fsCB),
		WithConnectObserver(connectCB),
	}, opts...)
	code, err := Run(ctx, &profile, runOpts...)

	fsRead, fsWrite, tmpfs, denied, blocked := partitionFSObservations(fsOpens, m)
	suggested, narrowed := synthesizeSuggestedWithNotes(m, obs.list(), fsRead, fsWrite, blocked)
	// Surface connect() calls the libproxychains shim couldn't see (compiled
	// binaries that bypass libc/proxychains). The grant callback already saw
	// every host:port the shim DID intercept; anything else is either a denied
	// raw TCP from a Go/Rust/etc. binary, or a localhost connect to our own
	// proxy. Filter out the latter — the proxy addrs are what made the
	// observation pipeline work in the first place.
	blockedConnects := filterUnshimmedConnects(connects, obs.list())
	result := &ProfileResult{
		ExitCode:          code,
		Observations:      obs.list(),
		FSObservations:    fsRead,
		FSWrites:          fsWrite,
		TmpfsWrites:       tmpfs,
		DeniedAttempts:    denied,
		BlockedReads:      blocked,
		BlockedConnects:   blockedConnects,
		SuggestedManifest: suggested,
		NarrowedReadPaths: narrowed,
	}
	return result, err
}

// broadWriteParents lists directories that are too widely shared to grant
// blanket write access to. If a script wrote `/tmp/out.json`, narrowing to
// `/tmp` would give the script write access to every other tenant on /tmp.
// For these parents we keep the leaf file path; everywhere else we collapse
// siblings to the parent directory (typical workspace pattern).
func isBroadWriteParent(dir string) bool {
	switch dir {
	case "/", "/tmp", "/var/tmp", "/var", "/etc", "/opt", "/srv", "/mnt", "/media", "/run", "/usr", "/home":
		return true
	}
	if home, _ := os.UserHomeDir(); home != "" && dir == home {
		return true
	}
	return false
}

// narrowWritePaths picks the smallest declaration that still covers the
// observed writes: leaf paths when the parent is broad (avoids over-granting
// /tmp), parent dirs otherwise (scripts often rewrite siblings).
func narrowWritePaths(writes []string) []string {
	set := make(map[string]struct{})
	for _, p := range writes {
		dir := filepath.Dir(p)
		if isBroadWriteParent(dir) {
			set[p] = struct{}{}
		} else {
			set[dir] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// filterUnshimmedConnects drops connect() observations that the libproxychains
// shim already covered (those re-emerge as Observations with the real hostname)
// and those targeting localhost — the proxy itself lives on 127.0.0.1, and a
// script connecting there is bento's own indirection, not a user-meaningful
// destination. Anything left is a direct outbound the shim couldn't see,
// typically a statically-linked binary that Landlock TCP denied.
func filterUnshimmedConnects(connects []ConnectAttempt, shimmed []NetworkObservation) []ConnectAttempt {
	if len(connects) == 0 {
		return nil
	}
	shimmedPorts := make(map[int]bool, len(shimmed))
	for _, o := range shimmed {
		shimmedPorts[o.Port] = true
	}
	var out []ConnectAttempt
	for _, c := range connects {
		if isLoopbackIP(c.IP) {
			continue
		}
		// If the proxy already captured this port through libproxychains, the
		// successful kernel-level connect for the same port is bento's own
		// upstream socat hop, not the user's. Skip to avoid double-reporting.
		if c.OK && shimmedPorts[c.Port] {
			continue
		}
		out = append(out, c)
	}
	return out
}

func isLoopbackIP(ip string) bool {
	switch {
	case ip == "":
		return false
	case strings.HasPrefix(ip, "127."):
		return true
	case ip == "::1":
		return true
	}
	return false
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// partitionFSObservations splits the runner's open list into:
//   - read: successful read opens worth suggesting (not covered, not dangerous,
//     not the script, and not interpreter library / locale / loader noise that
//     bento auto-binds)
//   - write: successful write opens worth suggesting (same filters)
//   - denied: paths the script tried to open but bento's mandatory-deny list
//     blocks (regardless of success — even a "successful" open of a /dev/null
//     shadow is signal that the script tried to read a sensitive file)
func partitionFSObservations(opens []FSOpen, m *Manifest) (read, write, tmpfs, denied, blockedReads []string) {
	if len(opens) == 0 {
		return nil, nil, nil, nil, nil
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
			// Failed opens outside the deny list: usually noise (interpreter
			// probes, locale lookups, /proc misses), but sometimes the script
			// genuinely tried to read a host path that isn't bind-mounted
			// (e.g. /etc/shells from a bash script). After the same noise
			// filters used for successful opens, surface what remains as
			// "blocked reads" so the user can opt in to declaring them.
			if e.Path == m.Script {
				continue
			}
			if e.Write {
				continue // tmpfs/EROFS noise; we already report tmpfs writes
			}
			if isInterpreterDep(e.Path, interpRoot) {
				continue
			}
			if isUserToolNoise(e.Path) {
				continue
			}
			if isSandboxTmpfsPath(e.Path) {
				continue
			}
			if isSandboxToolingProbe(e.Path) {
				continue
			}
			blockedReads = append(blockedReads, e.Path)
			continue
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
		// /sandbox/* paths are inside the sandbox tmpfs (the script's cwd is
		// /sandbox). A write there has no host destination and can't go into a
		// suggested manifest as-is — the path would dangle. Surface it
		// separately so the user can see what was lost and pick a real target.
		if e.Write && isSandboxTmpfsPath(e.Path) {
			tmpfs = append(tmpfs, e.Path)
			continue
		}
		if e.Write {
			write = append(write, e.Path)
			continue
		}
		// Keep paths covered by the user's read grants: profile uses these
		// to tighten broad grants (e.g. `read: [./data]`) into the specific
		// files that were actually opened, so the generated manifest doesn't
		// over-grant.
		read = append(read, e.Path)
	}
	blockedReads = dropPathSearchNoise(blockedReads)
	return read, write, tmpfs, denied, blockedReads
}

// isSandboxToolingProbe reports whether a failed-open path is a lookup for
// one of bento's own host tools (bwrap, bento-launcher, the fsshim, socat,
// proxychains). These probes come from bento's own startup walking the host
// $PATH; they're never something a user script intentionally tried to read.
func isSandboxToolingProbe(p string) bool {
	switch filepath.Base(p) {
	case "bwrap", "bento-launcher", "fsshim.so", "socat", "proxychains4", "libproxychains.so.4":
		return true
	}
	return false
}

// dropPathSearchNoise removes the characteristic noise of a shell's PATH
// lookup for a command that isn't on the host: the same basename probed
// across several `/.../bin/` directories, all failing. These reads are the
// shell's, not the script's; keeping them clutters the manifest with paths
// the user never intended to declare. Heuristic: if a basename appears under
// >= 2 different `*/bin/` parents, every probe of that basename is noise.
func dropPathSearchNoise(paths []string) []string {
	binParents := make(map[string]map[string]struct{}) // basename -> set of bin dirs
	for _, p := range paths {
		dir := filepath.Dir(p)
		if filepath.Base(dir) != "bin" {
			continue
		}
		base := filepath.Base(p)
		set := binParents[base]
		if set == nil {
			set = make(map[string]struct{})
			binParents[base] = set
		}
		set[dir] = struct{}{}
	}
	drop := make(map[string]struct{})
	for base, dirs := range binParents {
		if len(dirs) >= 2 {
			drop[base] = struct{}{}
		}
	}
	if len(drop) == 0 {
		return paths
	}
	out := paths[:0]
	for _, p := range paths {
		if _, skip := drop[filepath.Base(p)]; skip && filepath.Base(filepath.Dir(p)) == "bin" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// isSandboxTmpfsPath reports whether a path is a user-visible write under
// /sandbox/. These can't appear in a host manifest — /sandbox is the in-sandbox
// cwd, not a host directory — so we strip them from the suggested manifest and
// surface them as "writes that landed on tmpfs" to the user.
func isSandboxTmpfsPath(p string) bool {
	if !strings.HasPrefix(p, spec.SandboxRoot+"/") {
		return false
	}
	switch p {
	case spec.SandboxScriptPath, spec.SandboxLauncherPath, spec.SandboxProxychainsConfPath:
		return false
	}
	rest := p[len(spec.SandboxRoot)+1:]
	if strings.HasPrefix(rest, ".bento-") {
		return false
	}
	return true
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

// isMandatoryDenyParent reports whether a path R is the direct parent
// directory of any mandatory-deny file. Emitting `read: R` in a manifest
// crashes at run time because the mandatory-deny shadow can't create a
// placeholder mount point under a read-only parent (bwrap: "Can't create
// file at ~/.bashrc"). Profile must narrow such paths before committing.
func isMandatoryDenyParent(r string) bool {
	home := homeDir()
	if home == "" {
		return false
	}
	clean := filepath.Clean(r)
	all := append(spec.ExpandDangerousPaths(home), spec.ExpandDangerousWritePaths(home)...)
	for _, d := range all {
		if filepath.Dir(d) == clean {
			return true
		}
	}
	return false
}

// narrowReadsAgainstMandatoryDeny replaces each read path that conflicts with
// mandatory-deny (e.g. $HOME, where mandatory-deny needs to shadow ~/.bashrc,
// ~/.ssh/id_rsa, etc.) with the deepest observed descendants. If no
// descendant is available, the path is dropped from reads and surfaced via
// the second return value so the caller can annotate the manifest header.
func narrowReadsAgainstMandatoryDeny(reads []string, descendantHints []string) (kept, dropped []string) {
	if len(reads) == 0 {
		return reads, nil
	}
	hintsByParent := func(parent string) []string {
		var out []string
		prefix := filepath.Clean(parent) + string(filepath.Separator)
		for _, h := range descendantHints {
			abs := filepath.Clean(h)
			if strings.HasPrefix(abs, prefix) {
				out = append(out, abs)
			}
		}
		return out
	}
	seen := make(map[string]bool)
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			kept = append(kept, p)
		}
	}
	for _, r := range reads {
		if !isMandatoryDenyParent(r) {
			add(r)
			continue
		}
		replacements := hintsByParent(r)
		if len(replacements) == 0 {
			dropped = append(dropped, r)
			continue
		}
		for _, p := range replacements {
			add(p)
		}
	}
	return kept, dropped
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
func synthesizeSuggested(original *Manifest, obs []NetworkObservation, fsReads, fsWrites, blockedReads []string) *Manifest {
	m, _ := synthesizeSuggestedWithNotes(original, obs, fsReads, fsWrites, blockedReads)
	return m
}

// synthesizeSuggestedWithNotes is synthesizeSuggested plus the list of read
// paths that were narrowed/dropped due to mandatory-deny conflicts. Callers
// that surface diagnostics use this; the original signature stays for
// backward-compatible callers (tests).
func synthesizeSuggestedWithNotes(original *Manifest, obs []NetworkObservation, fsReads, fsWrites, blockedReads []string) (*Manifest, []string) {
	var droppedNotes []string
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
	// Combine successful reads and blocked-read attempts: both belong in the
	// generated `read:` list. Without blockedReads here, scripts that touched
	// paths outside the script directory (e.g. /etc/shells from a bash script)
	// would silently fail on the first `bento run` because profile only
	// records successful opens. Auto-including blocked reads matches how
	// writes are handled — the user reviews and trims.
	merged := append([]string{}, fsReads...)
	for _, p := range blockedReads {
		merged = appendUnique(merged, p)
	}
	if len(merged) > 0 {
		sort.Strings(merged)
		// Narrow paths that would conflict with mandatory-deny at run time
		// (e.g. read: /home/jrose, where ~/.bashrc et al can't be shadowed
		// under a ro-bound parent). Use observed reads, writes, and args as
		// descendant hints — anything we have evidence the script actually
		// used inside the broad parent.
		hints := append([]string{}, fsReads...)
		hints = append(hints, fsWrites...)
		hints = append(hints, original.Args...)
		narrowed, dropped := narrowReadsAgainstMandatoryDeny(merged, hints)
		out.Read = narrowed
		droppedNotes = dropped
	}
	if len(fsWrites) > 0 {
		// Default: use the leaf file path. Suggesting the parent directory
		// makes the manifest brittle and, when the parent is broad (/tmp,
		// $HOME, /var/tmp), grants far more than the script actually used.
		// Group leaves by parent only when the parent is a clearly
		// workspace-local directory (not a broad system-shared path).
		out.Write = narrowWritePaths(fsWrites)
	}
	return &out, droppedNotes
}
