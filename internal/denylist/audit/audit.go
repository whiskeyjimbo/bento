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
	"sort"
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
	// Section is the firejail section-header comment the directive fell under, used
	// to separate bento's secret/exec threat model from firejail's broader privacy
	// and other-app scope.
	Section string
	// Raw is the original firejail line, for the report.
	Raw string
}

// inScopeSection reports whether a firejail section is within bento's host-exec /
// secret-read threat model - as opposed to firejail's broader privacy, other-app,
// and system-hardening scope, which bento's empty-root default already covers and
// deliberately does not enumerate. Matching is by substring on the distinctive words
// of the secret and exec sections; an unrecognised section is out of scope, so a
// firejail reorganization can only make the audit quieter, never silently in-scope.
func inScopeSection(section string) bool {
	s := strings.ToLower(section)
	for _, kw := range []string{
		// secret / credential sections
		"top secret", "cloud provider", "ssh-agent", "remote access", "pass utility",
		"mail directories", "dm-crypt", "luks", "veracrypt", "truecrypt", "zulucrypt",
		"intrusion detection", "history files",
		// host-exec sections (a plant that runs on the host later)
		"arbitrary command execution", "startup files", "autostart", "session manager",
		"systemd", "openrc", "desktop entries", "terminal emulator", "ipc socket",
	} {
		if strings.Contains(s, kw) && !negatedKeyword(s, kw) {
			return true
		}
	}
	return false
}

// negatedKeyword reports whether the section names kw only to exclude it. firejail has
// a header "Configuration files that do not allow arbitrary command execution but
// that..." which contains the exec keyword yet is deliberately out of the exec threat
// model, so a bare substring match on it is a false positive. Suppression is scoped to
// that keyword: a section that negates it while also matching another in-scope keyword
// still classifies in-scope.
func negatedKeyword(s, kw string) bool {
	return kw == "arbitrary command execution" && strings.Contains(s, "not allow "+kw)
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
	var section string
	headerCaptured := false
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			// A blank line opens a new block: the next header comment replaces the
			// section. The prior section is kept until then, so an intra-section blank
			// (firejail spaces related entries) does not orphan the entries after it.
			headerCaptured = false
			continue
		}
		if after, ok := strings.CutPrefix(line, "#"); ok {
			// The first comment of a block is its section header, with one monotonic
			// exception: a later in-scope header upgrades an out-of-scope note that
			// preceded it (firejail sometimes leads a section with a reference note like
			// "# see #3358" before "# X11 session autostart"). The reclassification only
			// ever moves a block out-of-scope -> in-scope, never the reverse, so it can
			// only reduce wrong-OUT (an in-scope entry silently left un-gated) - the
			// dangerous direction. That is why it does not reintroduce the last-comment-
			// wins bug, which was itself a wrong-OUT: a commented-out
			// "# blacklist ${HOME}/.xpra" pulling the X11-autostart entries out of scope.
			// A commented-out directive is skipped and is never in-scope, so it can never
			// win here.
			text := strings.TrimSpace(after)
			if !isCommentedDirective(text) && (!headerCaptured || (!inScopeSection(section) && inScopeSection(text))) {
				section = text
				headerCaptured = true
			}
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
		out = append(out, Candidate{Path: path, Deny: deny, Glob: strings.ContainsAny(raw, "*?"), Section: section, Raw: line})
	}
	return out
}

// firejailDirectives are the leading keywords of firejail profile directives. A
// comment whose first token is one of these is a directive firejail disabled by
// prefixing '#', not a section header: it must not become the section the entries
// below it are attributed to. A real header is prose ("Top secret", "History files"),
// so its first token is not a lowercase directive keyword.
var firejailDirectives = map[string]bool{
	"blacklist": true, "read-only": true, "read-write": true, "noblacklist": true,
	"whitelist": true, "nowhitelist": true, "include": true, "mkdir": true,
	"mkfile": true, "rmenv": true,
}

// isCommentedDirective reports whether a comment's body is a commented-out firejail
// directive rather than a section header.
func isCommentedDirective(comment string) bool {
	fields := strings.Fields(comment)
	// firejail gates a directive on a build condition with a leading "?COND:" token
	// (e.g. "?HAS_X11: blacklist ${HOME}/.ICEauthority"); look past it to the directive
	// keyword so a commented-out conditional is not mistaken for a section header.
	if len(fields) > 0 && strings.HasPrefix(fields[0], "?") && strings.HasSuffix(fields[0], ":") {
		fields = fields[1:]
	}
	return len(fields) > 0 && firejailDirectives[fields[0]]
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

// SplitByScope partitions gaps into the ones inside bento's secret/exec threat model
// (returned sorted by section, ready to list) and a count-by-section of the rest -
// firejail's privacy/other-app/system scope, which bento does not enumerate. The
// out-of-scope set is summarized rather than dropped so it stays accountable.
func SplitByScope(gaps []Gap) (inScope []Gap, outBySection map[string]int) {
	outBySection = map[string]int{}
	for _, g := range gaps {
		if inScopeSection(g.Section) {
			inScope = append(inScope, g)
		} else {
			outBySection[g.Section]++
		}
	}
	sort.SliceStable(inScope, func(i, j int) bool {
		if inScope[i].Section != inScope[j].Section {
			return inScope[i].Section < inScope[j].Section
		}
		return inScope[i].Path < inScope[j].Path
	})
	return inScope, outBySection
}

// IntentionalExclusions are firejail in-scope entries bento deliberately does NOT
// shield, keyed by their ${HOME}-relative path with the reason. The audit subtracts
// these so it flags only genuinely-new, unclassified entries; a human adds to it when
// classifying a flagged candidate as "correctly not shielded". It is bento's own
// artifact (path facts plus bento's reasoning), not a copy of firejail's profile.
//
// This seeds only the exclusions grounded in a recorded decision; it is expected to
// grow when the audit first runs against a real firejail profile and a human triages
// the remaining flags.
var IntentionalExclusions = map[string]string{
	".cert":             "often exists as a regular file, and a DenyAll tmpfs over a file aborts a broad-grant run; concrete credential files are shielded by name instead",
	".mail":             "same tmpfs-over-file abort risk as a bare mail dir; bento shields the concrete mail stores it enumerates",
	".Mail":             "same tmpfs-over-file abort risk as a bare mail dir",
	".history":          "a generic name bento does not shield; the concrete ~/.*_history credential-history files are shielded individually",
	".*_history":        "firejail's history glob, which bento cannot express; shielded as the named instances (.bash_history, .zsh_history, ...) instead",
	".local/state/nvim": "editor state, not auto-sourced code - no host-exec vector, and shielding it only breaks nvim's persistence",
	"_vimrc":            "a Windows-only vim rc name, dead on Linux where the real names (.vimrc, .gvimrc, .exrc) are shielded",
	"_gvimrc":           "a Windows-only gvim rc name, dead on Linux",
	"_exrc":             "a Windows-only ex rc name, dead on Linux",
}

// excluded reports whether path is an intentional exclusion at the given home.
func excluded(path, home string) bool {
	rel, ok := strings.CutPrefix(path, strings.TrimSuffix(home, "/")+"/")
	if !ok {
		return false
	}
	_, ok = IntentionalExclusions[rel]
	return ok
}

// Audit reads firejail profile contents, diffs them against bento's full shield list
// (Home + Runtime), and returns the in-scope gaps that are neither shielded nor an
// intentional exclusion - the entries a human must classify and either shield or
// exclude. outBySection summarizes the out-of-scope firejail sections bento does not
// enumerate, so they stay accountable rather than silently dropped. home and runUser
// expand firejail's ${HOME}/${RUNUSER}; the profile files are a dev-time diff input,
// never vendored into the binary.
func Audit(contents []string, home, runUser string) (unclassified []Gap, outBySection map[string]int) {
	var candidates []Candidate
	for _, c := range contents {
		candidates = append(candidates, ParseFirejail(c, home, runUser)...)
	}
	rules := append(denylist.Home(home), denylist.Runtime()...)
	inScope, outBySection := SplitByScope(Diff(candidates, rules))
	for _, g := range inScope {
		if !excluded(g.Path, home) {
			unclassified = append(unclassified, g)
		}
	}
	return unclassified, outBySection
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
