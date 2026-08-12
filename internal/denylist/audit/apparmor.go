package audit

import (
	"strings"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// ParseAppArmor maps the deny rules of an AppArmor abstraction into candidates. It is
// the second corpus behind the firejail parser, chosen because AppArmor's
// private-files/private-files-strict abstractions are deny-shaped (the same polarity
// bento's list has), single-file, and maintained by people with no connection to
// firejail - so a store one project overlooks is not automatically missed by the other.
//
// Three things differ from the firejail format and each is load-bearing:
//
//   - Scope comes from the file, not a section header. Both abstractions exist solely to
//     enumerate sensitive $HOME files, so every rule in them is in bento's model by
//     construction. That is why AppArmorSection is stamped on each candidate rather than
//     the enclosing comment: inScopeSection has nothing to key off here, and treating a
//     comment as a section would bin real entries by whatever prose happened to precede
//     them.
//   - The mode letters carry the deny class. "w" or "l" without "r" denies only writing
//     and linking, which is bento's DenyWrite; a rule including "r" (or the "m"/"k" that
//     accompany it) hides the content too, which is DenyAll. Reading every rule as
//     DenyAll would report bento's correct DenyWrite shields as Weaker - a wave of false
//     gaps on paths that are already right.
//   - Brace alternation is FINITE, so it expands to concrete paths rather than being a
//     glob. ".{,z}log{in,out}" is four real files, and treating it as a wildcard would
//     push four checkable paths into the review bucket that exists for the genuinely
//     inexpressible.
//
// The second return is the number of DENY RULES the parser could not turn into a
// candidate. A line that is not a deny rule at all (a comment, an allow rule) is not one:
// this counts the rules that were the parser's to read and were dropped anyway, including
// the create-guards isCreateGuard suppresses by design, whose doc already concedes the
// drop is a silent narrowing of the diff.
func ParseAppArmor(content, home, runUser string) ([]Candidate, int) {
	var out []Candidate
	dropped := 0
	seen := map[string]int{}
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		rule, ok := denyRule(line)
		if !ok {
			continue
		}
		path, modes, ok := splitRule(rule)
		if !ok {
			dropped++
			continue
		}
		deny := denylist.DenyWrite
		if strings.ContainsAny(modes, "rmk") {
			deny = denylist.DenyAll
		}
		// Variables first, alternation second: @{HOME} is itself brace-delimited, so
		// expanding alternation ahead of substitution consumes it as a one-branch group
		// and leaves "@HOME/..." - a path that matches no rule and silently drops the
		// entire corpus from the diff.
		rooted, ok := substituteVars(path, home, runUser)
		if !ok {
			// A system path is out of scope by design. An unresolved VARIABLE is not the
			// same thing: upstream introducing a spelling substituteVars does not know
			// moves home-relative rules out of the diff under the same "out of scope"
			// answer /etc gets.
			if strings.HasPrefix(path, "@{") {
				dropped++
			}
			continue
		}
		for _, expanded := range expandAlternation(rooted) {
			if isCreateGuard(expanded, modes) {
				dropped++
				continue
			}
			p, dir, ok := trimSubtreeSuffix(expanded, home, runUser)
			if !ok {
				dropped++
				continue
			}
			// One rule can expand to both branches of foo{,/**}, the file first, and
			// seen dedups across LINES as well, so the same path can arrive from two
			// profile entries with different modes. Taking the first would record
			// Dir=false and blind the diff's narrowing check, or record the weaker
			// Deny and hide a gap in the Weaker check - both are order-dependent
			// answers to "what does the reference profile shield here". Each field
			// takes the stronger claim independently, since the two branches of one
			// alternation carry the same modes and only cross-line duplicates can
			// disagree on Deny.
			if i, ok := seen[p]; ok {
				if dir {
					out[i].Dir = true
				}
				if deny < out[i].Deny {
					out[i].Deny = deny
				}
				continue
			}
			seen[p] = len(out)
			out = append(out, Candidate{
				Path:    p,
				Deny:    deny,
				Glob:    strings.ContainsAny(p, "*?"),
				Dir:     dir,
				Section: appArmorSection,
				Raw:     line,
			})
		}
	}
	return out, dropped
}

// appArmorSection is the section stamped on every AppArmor candidate. The abstractions
// carry no headers inScopeSection could read, and their whole purpose is sensitive-file
// enumeration, so scope is a property of the source rather than of the line.
const appArmorSection = "AppArmor private-files abstraction"

// denyRule returns the body of an AppArmor deny rule, dropping the "audit" and "owner"
// qualifiers that may precede or follow "deny". A rule without "deny" is an ALLOW rule:
// these abstractions carry none, but a caller pointed at an ordinary profile would
// otherwise read its permissions as shields, which is the polarity inversion that makes
// a confinement profile the wrong corpus for this diff.
func denyRule(line string) (string, bool) {
	fields := strings.Fields(line)
	i := 0
	// AppArmor's grammar takes either qualifier on either side of "deny", so both sides
	// skip both: matching "owner" only after it dropped a whole "owner deny @{HOME}/..."
	// rule with no diagnostic, and a rule that leaves the corpus reads downstream as a
	// path upstream does not shield.
	qualifier := func(f string) bool { return f == "audit" || f == "owner" }
	for i < len(fields) && qualifier(fields[i]) {
		i++
	}
	if i >= len(fields) || fields[i] != "deny" {
		return "", false
	}
	i++
	for i < len(fields) && qualifier(fields[i]) {
		i++
	}
	if i >= len(fields) {
		return "", false
	}
	return strings.Join(fields[i:], " "), true
}

// splitRule separates an AppArmor file rule's path from its mode letters. The rule ends
// in a comma and the modes are its last whitespace-separated token; a rule with no mode
// token is not a file rule (a capability or network rule) and is dropped.
func splitRule(rule string) (path, modes string, ok bool) {
	rule = strings.TrimSuffix(strings.TrimSpace(rule), ",")
	fields := strings.Fields(rule)
	if len(fields) < 2 {
		return "", "", false
	}
	modes = fields[len(fields)-1]
	// A mode token is only the permission letters. Anything else means the last field is
	// part of a path with spaces, and the rule carries no modes to classify by.
	if strings.Trim(modes, "rwaxmklPUCIicu") != "" {
		return "", "", false
	}
	return strings.Join(fields[:len(fields)-1], " "), modes, true
}

// expandAlternation turns AppArmor's brace alternation into the concrete set it stands
// for: "{,z}log{in,out}" is .login/.logout/.zlogin/.zlogout, four checkable paths rather
// than one unresolvable pattern. Nesting is handled by recursing on the remainder, and a
// rule whose braces do not balance is returned unexpanded rather than half-expanded into
// paths that were never written.
func expandAlternation(s string) []string {
	open := strings.IndexByte(s, '{')
	if open < 0 {
		return []string{s}
	}
	depth, close := 0, -1
	for i := open; i < len(s) && close < 0; i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				close = i
			}
		}
	}
	if close < 0 {
		return []string{s}
	}
	var out []string
	for _, alt := range splitTopLevel(s[open+1 : close]) {
		out = append(out, expandAlternation(s[:open]+alt+s[close+1:])...)
	}
	return out
}

// splitTopLevel splits an alternation body on the commas that separate its branches,
// ignoring commas nested in an inner brace group so "a,{b,c}" stays two branches.
func splitTopLevel(body string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, body[start:i])
				start = i + 1
			}
		}
	}
	return append(out, body[start:])
}

// isCreateGuard reports whether a rule denies creating entries directly in a directory
// rather than shielding the directory itself: a write-only mode on a path naming the
// directory ("@{HOME}/.config/ w"), with no subtree tail. AppArmor needs these so a
// child deny cannot be side-stepped by replacing the parent; bento needs no equivalent,
// because its shields are mounts rather than path rules.
//
// Dropping them is what keeps .config, .local, .local/share, .kde{,4} and their share/
// parents out of the diff. Left in, each reads as an unshielded credential directory,
// and the only ways to clear the gate would be to shield the whole of .config and
// .local - which would break every ordinary run - or to write off ten entries as
// exclusions, teaching the reader that entries here are noise. A rule that also carries
// a subtree branch is unaffected: "bin/{,**}" keeps its "bin/**" branch, so ~/bin is
// still audited.
//
// The drop is silent, which is a narrowing of the diff and so worth stating. Every rule
// it currently suppresses (.gnome2/, .config/, .kde{,4}/, .pki/) is a bare directory
// with no subtree branch, and each of those directories holds shielded children rather
// than being a store itself. Were upstream to rewrite an existing "foo/{,**}" as a bare
// "foo/ w", that entry would leave the comparison unannounced - the same silent-narrowing
// shape the fetch sentinels in cmd/denylist-audit exist to prevent. Re-check here if the
// abstraction's rule style changes.
func isCreateGuard(path, modes string) bool {
	return strings.HasSuffix(path, "/") && !strings.ContainsAny(modes, "rmk")
}

// substituteVars resolves the AppArmor variables bento's scope covers and reports
// whether the path is in it. @{HOME} and the runtime dir are in scope; a system path or
// an unresolved variable is not, matching what the firejail parser keeps.
func substituteVars(raw, home, runUser string) (string, bool) {
	switch {
	case strings.HasPrefix(raw, "@{HOME}"):
		return home + strings.TrimPrefix(raw, "@{HOME}"), true
	case strings.HasPrefix(raw, "@{run}/user/[0-9]*"):
		// The abstraction spells the runtime dir with a uid wildcard; bento's runtime
		// rules are rooted at the concrete dir, so substituting it makes the two
		// comparable instead of leaving a permanently-unmatchable pattern.
		return runUser + strings.TrimPrefix(raw, "@{run}/user/[0-9]*"), true
	default:
		return "", false
	}
}

// trimSubtreeSuffix collapses AppArmor's "and everything under it" tail to the directory
// itself, because a bento directory rule already covers its whole subtree. Without this
// every rule would carry a "**" and land in the review bucket that exists for genuinely
// inexpressible wildcards, rather than being diffed against the rule that covers it.
// It runs after alternation expansion, since "{,**}" only becomes a tail once expanded.
// A path that trims away to the home or runtime root itself says nothing and is dropped.
//
// dir reports that a tail was actually cut, which is what makes the directive
// directory-shaped: covering it takes a bento rule that shields the tree, not one on the
// path alone.
func trimSubtreeSuffix(path, home, runUser string) (trimmed string, dir, ok bool) {
	for _, suffix := range []string{"/**", "/*", "/"} {
		if cut, found := strings.CutSuffix(path, suffix); found {
			path, dir = cut, true
			break
		}
	}
	if path == "" || path == home || path == runUser {
		return "", false, false
	}
	return path, dir, true
}
