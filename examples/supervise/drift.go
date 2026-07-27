package main

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// warnManifestDrift warns when a script's committed manifest disagrees with the
// store's effective decisions, so the same script does not silently behave
// differently under `supervise` and plain `bento run`. It walks the store's own
// allow/deny opinions one-directionally and reports each that the manifest resolves
// the other way. A store-UNKNOWN item is never drift: under `bento run` the manifest
// applies, under supervise it prompts, and a prompt is not silent - warning on it
// would false-alarm every fresh store. Only fields both sides express are compared
// (read/write/network/exec); args, env, and limits are the store's blind spots.
func warnManifestDrift(w io.Writer, s *store, key, script string) {
	path := script + ".manifest.yaml"
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		fmt.Fprintf(w, "supervise: manifest %s present but unreadable: %v\n", path, err)
		return
	}
	defer f.Close()
	m, err := manifest.Load(f)
	if err != nil {
		fmt.Fprintf(w, "supervise: manifest %s present but will not parse: %v\n", path, err)
		return
	}
	// Compare what `bento run` would actually enforce: it anchors a relative grant to
	// the manifest's directory, while the store's paths are absolute. Without this a
	// relative grant matches nothing and every store allow reads as drift.
	if err := manifest.Resolve(m, path); err != nil {
		fmt.Fprintf(w, "supervise: manifest %s cannot be anchored to its directory: %v\n", path, err)
		return
	}

	var drift []string
	for _, kind := range []string{"read", "write"} {
		// A read is covered by a read OR a write grant (a write grant is read-write);
		// a write needs a write grant. Missing this hides the sharp case: a store
		// read-deny under a manifest write grant, which `bento run` can read while
		// supervise blocks.
		mPaths := m.Write
		if kind == "read" {
			mPaths = readGrants(m.Read, m.Write)
		}
		allows, denies := s.effectivePaths(key, kind)
		for _, p := range allows {
			if !pathCoveredBy(p, mPaths) {
				drift = append(drift, driftStoreAllows(kind, quotePath(p)))
			}
		}
		for _, p := range denies {
			if pathCoveredBy(p, mPaths) {
				drift = append(drift, driftManifestAllows(kind, quotePath(p)))
			}
		}
	}
	for _, k := range storeNetKeys(s, key) {
		host, port := splitNetKey(k)
		d, ok := s.decideNetwork(key, host, port)
		if !ok {
			continue
		}
		// policy.Allows matches the concrete host:port against the manifest's rules,
		// including its wildcards and port ranges, so a store host the manifest covers
		// via ".example" or "*" is not reported as phantom drift.
		mAllows := policy.Allows(m.Network, host, port)
		switch {
		case d == allow && !mAllows:
			drift = append(drift, driftStoreAllows("reach", quoteNetKey(k)))
		case d == deny && mAllows:
			drift = append(drift, driftManifestAllows("reach", quoteNetKey(k)))
		}
	}
	if d, ok := s.decideExec(key); ok {
		mExec := m.Exec == policy.ExecAll
		switch {
		case d == allow && !mExec:
			drift = append(drift, driftStoreAllows("exec", "run subprocesses"))
		case d == deny && mExec:
			drift = append(drift, driftManifestAllows("exec", "run subprocesses"))
		}
	}

	if len(drift) == 0 {
		return
	}
	fmt.Fprintf(w, "\nsupervise: the manifest %s disagrees with the store; the same script behaves differently under `bento run`:\n", path)
	for _, d := range drift {
		fmt.Fprintln(w, d)
	}
	fmt.Fprintln(w, "  reconcile with `perms export` / `perms import`, or clear the store entry with `perms forget`.")
}

func driftStoreAllows(kind, disp string) string {
	return fmt.Sprintf("  %-6s %s: the store allows it, the manifest does not (supervise permits, `bento run` blocks)", kind, disp)
}

func driftManifestAllows(kind, disp string) string {
	return fmt.Sprintf("  %-6s %s: the manifest allows it, the store denies it (`bento run` permits, supervise blocks)", kind, disp)
}

// pathCoveredBy reports whether any manifest grant covers path (a grant of a
// directory covers everything beneath it, the same containment bento enforces).
func pathCoveredBy(path string, grants []string) bool {
	for _, g := range grants {
		if underComponent(path, g) {
			return true
		}
	}
	return false
}

// storeNetKeys is the union of the app's and the global network keys, so drift is
// checked against every host the store has an opinion on.
func storeNetKeys(s *store, key string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(m map[string]decision) {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	add(s.Global.Network)
	if a := s.Apps[key]; a != nil {
		add(a.Network)
	}
	sort.Strings(out)
	return out
}
