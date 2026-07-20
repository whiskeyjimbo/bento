// Package audit cross-references bento's shield list against firejail's
// disable-common profile, so a path firejail shields but bento does not surfaces
// as a candidate rather than waiting for an adversarial review to find it.
//
// It is a dev-time completeness check, not part of the sandbox: the mapping from
// firejail's directives to bento's DenyAll/DenyWrite classes is a hint, and the
// final classification (per the credential-vs-exec rule in the denylist package)
// stays a human call. firejail's profile data is GPLv2; this reads it as a
// reference/diff input and never vendors it into the binary.
package audit

import (
	"path/filepath"
	"strings"

	"github.com/whiskeyjimbo/bento-v2/internal/denylist"
)

// Candidate is one firejail directive mapped into bento's terms.
type Candidate struct {
	// Path is the shielded path with firejail's variables expanded.
	Path string
	// Deny is the class the directive maps to: blacklist -> DenyAll, read-only ->
	// DenyWrite.
	Deny denylist.Deny
	// Glob reports that the source directive used a wildcard, which bento does not
	// express (it shields directories instead). A glob candidate needs a human to
	// decide the covering directory shield, so it is reported separately.
	Glob bool
	// Raw is the original firejail line, for the report.
	Raw string
}

// Gap is a firejail candidate bento does not fully cover.
type Gap struct {
	Candidate
	// Weaker is set when bento shields the path but only as DenyWrite while firejail
	// blacklists it (DenyAll) - the content is still readable, a possible
	// misclassification rather than a missing entry.
	Weaker bool
}

// ParseFirejail maps the blacklist/read-only directives of a firejail profile into
// candidates, expanding ${HOME} and ${RUNUSER} and keeping only home- and
// runtime-scoped paths - bento's shield scope. System paths (/etc, /sbin, /usr),
// ${PATH} entries, and the non-shield directives (noblacklist, read-write, include,
// mkdir, rmenv, whitelist) are dropped: those are outside bento's home/runtime
// threat model, which its empty-root default already covers.
func ParseFirejail(content, home, runUser string) []Candidate {
	var out []Candidate
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var deny denylist.Deny
		switch fields[0] {
		case "blacklist":
			deny = denylist.DenyAll
		case "read-only":
			deny = denylist.DenyWrite
		default:
			continue
		}
		raw := fields[1]
		path, ok := expand(raw, home, runUser)
		if !ok {
			continue
		}
		out = append(out, Candidate{Path: path, Deny: deny, Glob: strings.ContainsAny(raw, "*?"), Raw: line})
	}
	return out
}

// expand resolves the firejail variables bento cares about and reports whether the
// path is in scope. Only ${HOME}- and ${RUNUSER}-rooted paths are in scope; anything
// else (system paths, ${PATH}, ${CFG}, a bare absolute path) is out of scope.
func expand(raw, home, runUser string) (string, bool) {
	switch {
	case strings.HasPrefix(raw, "${HOME}/"):
		return filepath.Join(home, strings.TrimPrefix(raw, "${HOME}/")), true
	case raw == "${HOME}":
		return home, true
	case strings.HasPrefix(raw, "${RUNUSER}/"):
		return filepath.Join(runUser, strings.TrimPrefix(raw, "${RUNUSER}/")), true
	case raw == "${RUNUSER}":
		return runUser, true
	default:
		return "", false
	}
}

// Diff returns the candidates bento does not fully cover. A candidate is covered when
// a rule shields it exactly, or a directory rule encloses it (bento's dir shields
// cover unborn children, so firejail's per-file entries under a shielded dir are
// covered). A glob candidate is covered only when a directory rule encloses its
// parent, since bento cannot express the wildcard itself. A candidate bento shields
// as DenyWrite while firejail blacklists it is reported as Weaker, not missing.
func Diff(candidates []Candidate, rules []denylist.Rule) []Gap {
	var gaps []Gap
	for _, c := range candidates {
		covering, ok := cover(c.Path, rules)
		if !ok {
			gaps = append(gaps, Gap{Candidate: c})
			continue
		}
		if c.Deny == denylist.DenyAll && covering.Deny == denylist.DenyWrite {
			gaps = append(gaps, Gap{Candidate: c, Weaker: true})
		}
	}
	return gaps
}

// cover finds a rule that shields path, returning it and true. An exact match wins;
// otherwise a directory rule whose path encloses it covers it.
func cover(path string, rules []denylist.Rule) (denylist.Rule, bool) {
	var best denylist.Rule
	found := false
	for _, r := range rules {
		if r.Path == path || (r.Dir && under(path, r.Path)) {
			// Prefer the strictest covering rule, so a DenyAll dir shield is not
			// reported Weaker because a DenyWrite rule also matched.
			if !found || r.Deny < best.Deny {
				best, found = r, true
			}
		}
	}
	return best, found
}

// under reports whether path is strictly inside dir.
func under(path, dir string) bool {
	return strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}
