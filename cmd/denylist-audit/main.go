// Command denylist-audit reports the home/runtime paths an upstream sandbox project
// shields that bento does not, so known denylist gaps surface on a cycle instead of in a
// review. A clean run means parity with the corpora below, not a complete deny-list -
// see the audit package doc for what that does and does not rule out.
//
// It fetches firejail's disable-common.inc and disable-programs.inc (GPLv2) and
// AppArmor's private-files abstractions (GPLv2), reads them as diff input only and never
// vendors them, maps their deny directives to bento's shield classes, and prints the
// gaps. Classification of each gap - DenyAll vs
// DenyWrite - stays a human call. Exit status is 1 when any gap is found, so CI can gate
// on it; see the exit constants for the rest.
//
// Both profiles are fetched because they are classified by different halves of the audit
// package: disable-common.inc carries the section headers inScopeSection keys off, while
// disable-programs.inc is a flat header-less per-application list that only the
// credentialName classifier can pick credential stores out of. Fetching one left that
// classifier dead on this path.
package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/whiskeyjimbo/bento/internal/denylist/audit"
)

// firejailSources are the upstream profiles the audit diffs against, each with a
// sentinel directive it has carried for years. A 200 response is not proof the body is
// the profile - an upstream rename, a reformat to include-only files, or a CDN error
// page all return 200 with content that parses to zero candidates, which would read as
// "everything covered" and exit 0, a false pass on a CI safety gate.
//
// Each sentinel must identify ONE profile, so a URL serving another file's body is
// caught rather than accepted: the two would then be audited as one and the missing
// profile's entries would silently not be gaps. That is why these are whole directive
// LINES rather than bare paths, matched as such by isProfile - disable-common has a
// "read-only ${HOME}/.mozilla/firefox/profiles.ini" line, so a bare ${HOME}/.mozilla
// matches both files and would wave the mixup through, and AppArmor's private-files and
// its strict sibling differ only by an "audit " prefix on otherwise identical rules, so a
// substring sentinel of the one is satisfied by the other.
//
// minCandidates is the floor each profile's parse must clear. The fetch has a ceiling but
// nothing asserted a lower bound, so a complete-but-short body - a truncated CDN
// response, or an upstream that moved most of its rules behind an include directive
// neither format's parser follows - passed with the corpus tail simply absent from the
// diff, which reads as "no gaps there". The values sit below the current counts with
// headroom, so ordinary upstream churn does not trip them and a collapse does.
//
// The AppArmor abstractions are the second corpus, added because a single-source diff
// can only ever establish parity with that source. They are deny-shaped like firejail's
// (so the polarity matches bento's list), single-file, and maintained by an unrelated
// project, which is the property that matters: a store one of them overlooks is not
// automatically invisible to the other. Their parser is ParseAppArmor, not ParseFirejail
// - the formats share no syntax.
var upstreamSources = []struct {
	url           string
	sentinel      string
	minCandidates int
	parse         func(content, home, runUser string) []audit.Candidate
}{
	{"https://raw.githubusercontent.com/netblue30/firejail/master/etc/inc/disable-common.inc", "blacklist ${HOME}/.ssh", 250, audit.ParseFirejail},
	{"https://raw.githubusercontent.com/netblue30/firejail/master/etc/inc/disable-programs.inc", "blacklist ${HOME}/.mozilla", 1000, audit.ParseFirejail},
	{"https://gitlab.com/apparmor/apparmor/-/raw/master/profiles/apparmor.d/abstractions/private-files", "deny @{HOME}/.*history mrwkl,", 20, audit.ParseAppArmor},
	{"https://gitlab.com/apparmor/apparmor/-/raw/master/profiles/apparmor.d/abstractions/private-files-strict", "audit deny @{HOME}/.ssh/{,**} mrwkl,", 12, audit.ParseAppArmor},
}

// The paths the parser expands firejail's variables to; any absolute value works,
// it only has to match what denylist.Home/Runtime emit for the same home.
const (
	home    = "/home/u"
	runUser = "/run/user/1000"
)

// Exit statuses. scripts/denylist-audit.sh maps each to a CI verdict, so a fetch
// failure - an infrastructure condition it deliberately passes over - must not share a
// status with anything that means the deny-list or the corpus is wrong.
//
// 2 is deliberately unused: Go's runtime exits 2 on panic, so any status the wrapper
// treats as "skip, pass" would turn a crash inside the audit into a green gate. The
// wrapper's unexpected-failure arm catches 2 instead.
const (
	exitGap            = 1
	exitFetchFailed    = 3
	exitContentRefused = 4
)

// errRefuse marks a fetch failure that is a judgement about the RESPONSE rather than a
// transport condition, so it carries exitContentRefused and the wrapper fails on it. A
// 4xx says the URL is wrong or the file was renamed, which is permanent - left on the
// pass-over status it would print "offline?" and green the gate forever, the same lie the
// sentinel exists to prevent. So does a body past the size ceiling: that check is about
// what arrived, not whether it arrived. Only a transport error, a 5xx, and the two 4xx
// codes that do mean "try later" reach the pass-over arm.
var errRefuse = errors.New("the response is not the upstream profile")

func main() {
	sources, status := collect(fetch, os.Stderr)
	if status != 0 {
		os.Exit(status)
	}
	os.Exit(report(os.Stdout, sources, home, runUser))
}

// collect fetches every upstream profile and checks each is the file it claims to be,
// returning the sources to audit or the exit status to stop on. Every source must arrive
// intact: a partial set is refused rather than audited, because a missing profile
// silently narrows the diff - the entries it would have contributed simply are not gaps,
// and the gate reports a pass over a comparison it never made. That is the failure this
// command exists to prevent.
//
// The fetcher is a parameter so the two refusals - a source that did not arrive versus
// one that arrived and is not the profile - are asserted without the network. They carry
// different statuses because CI treats them differently.
func collect(fetch func(url string) (string, error), w io.Writer) ([]audit.Source, int) {
	var sources []audit.Source
	for _, src := range upstreamSources {
		content, err := fetch(src.url)
		if err != nil {
			fmt.Fprintf(w, "denylist-audit: fetching %s: %v\n", src.url, err)
			if errors.Is(err, errRefuse) {
				return nil, exitContentRefused
			}
			return nil, exitFetchFailed
		}
		if !isProfile(content, src.sentinel) {
			fmt.Fprintf(w, "denylist-audit: content fetched from %s does not carry %s, so it is not the expected upstream profile; refusing to report a pass\n", src.url, src.sentinel)
			return nil, exitContentRefused
		}
		// A body can carry the sentinel and still be most of a profile short: the
		// directive the sentinel names sits near the top of both formats, so a truncation
		// or an upstream that moved the bulk of its rules behind an include leaves the
		// check satisfied and the tail missing. Refusing on the count is the same
		// judgement as refusing on the sentinel - this is not the corpus - so it shares
		// the status.
		if n := len(src.parse(content, home, runUser)); n < src.minCandidates {
			fmt.Fprintf(w, "denylist-audit: %s parsed to %d in-scope directives, below the floor of %d; the body is not the whole profile, so refusing to report a pass\n", src.url, n, src.minCandidates)
			return nil, exitContentRefused
		}
		sources = append(sources, audit.Source{Content: content, Parse: src.parse})
	}
	return sources, 0
}

// isProfile reports whether content is plausibly the upstream profile that sentinel
// identifies - a directive line that file has carried for years. Absent it, the fetch did
// not return the profile and the audit cannot conclude anything, so a zero-gap diff over
// it must not be reported as a pass.
//
// The match is on a whole line, with the surrounding whitespace trimmed off (AppArmor
// indents its rules, firejail does not). A substring match would let one profile satisfy
// another's sentinel wherever one file's directive is a prefix or an extension of the
// other's, which is the ordinary case between siblings: private-files-strict writes the
// same rules as private-files with an "audit " prefix. Matching the line closes that
// without depending on how either project happens to indent today.
func isProfile(content, sentinel string) bool {
	for line := range strings.SplitSeq(content, "\n") {
		if strings.TrimSpace(line) == sentinel {
			return true
		}
	}
	return false
}

// report parses each upstream profile with its own parser, diffs the result it against bento's deny-list, writes the
// in-scope gaps (and an out-of-scope summary) to w, and returns the process exit code:
// exitGap when any in-scope gap remains, 0 when the list already covers them. It is separated
// from main's network fetch so the gate's decision - the part CI depends on - is testable
// without touching the network.
func report(w io.Writer, sources []audit.Source, home, runUser string) int {
	// One diff logic, two triggers: this CLI and the completeness test both go through
	// audit.Audit, so they cannot reach contradictory verdicts on the same profile.
	unclassified, globs, outOfScope := audit.Audit(sources, home, runUser)

	// Globs are reported for review (bento cannot express a wildcard; it covers the
	// class by shielding named instances) but do not fail the gate on their own.
	for _, g := range globs {
		fmt.Fprintf(w, "glob for review - verify bento's named instances cover it: %s [%s]\n", g.Path, g.Section)
	}

	if len(unclassified) == 0 {
		fmt.Fprintln(w, "no unclassified in-scope gaps: every secret/exec upstream shield is covered or excluded")
		reportOutOfScope(w, outOfScope)
		return 0
	}

	fmt.Fprintf(w, "%d in-scope upstream-shielded path(s) bento neither shields nor excludes:\n\n", len(unclassified))
	section := ""
	for _, g := range unclassified {
		if g.Section != section {
			section = g.Section
			fmt.Fprintf(w, "[%s]\n", section)
		}
		note := "missing"
		if g.Weaker {
			note = "present but DenyWrite; upstream denies reads too (candidate DenyAll)"
		}
		fmt.Fprintf(w, "  %-42s %s\n", g.Path, note)
	}
	reportOutOfScope(w, outOfScope)
	return exitGap
}

// reportOutOfScope lists the upstream entries bento deliberately does not cover
// (privacy, other-app, system hardening), grouped under their section, after the in-scope
// gaps so they do not bury them.
//
// It prints every path rather than a per-section count because the count is unreadable:
// the bulk of this bucket comes from disable-programs.inc, whose "section" is the file's
// own install-time header comment, so a newly-added credential store lands there and only
// moves one number by one - which two runs cannot be diffed to notice. The paths can be.
// The gaps arrive sorted, so the diff is the change and nothing else.
func reportOutOfScope(w io.Writer, gaps []audit.Gap) {
	if len(gaps) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%d out-of-scope gap(s) skipped (upstream's privacy/other-app/system scope), by section:\n", len(gaps))
	section := ""
	for _, g := range gaps {
		if g.Section != section {
			section = g.Section
			fmt.Fprintf(w, "\n[%s]\n", section)
		}
		fmt.Fprintf(w, "  %s\n", g.Path)
	}
}

// permanentStatus reports whether an HTTP status means the resource is not there to be
// had, as opposed to a server that is having a bad day. 408 and 429 are 4xx by number but
// both mean "try later", so they stay on the pass-over side with the 5xx codes.
func permanentStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	default:
		return code >= 400 && code < 500
	}
}

func fetch(url string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if permanentStatus(resp.StatusCode) {
			return "", fmt.Errorf("%w: unexpected status %s", errRefuse, resp.Status)
		}
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}
	// Read one byte past the cap so a body that hit it is detected rather than
	// silently truncated: a truncated profile would drop its tail sections from the
	// comparison and could hide gaps there. The real profile is ~20KB, so hitting 1MB
	// means the content is not what we expect.
	const maxBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxBytes {
		return "", fmt.Errorf("%w: it exceeds %d bytes, so the body is not the profile and auditing a truncated copy of it would hide the gaps in its tail", errRefuse, maxBytes)
	}
	return string(body), nil
}
