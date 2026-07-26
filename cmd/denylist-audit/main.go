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
// on it.
//
// Both profiles are fetched because they are classified by different halves of the audit
// package: disable-common.inc carries the section headers inScopeSection keys off, while
// disable-programs.inc is a flat header-less per-application list that only the
// credentialName classifier can pick credential stores out of. Fetching one left that
// classifier dead on this path.
package main

import (
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
// Each sentinel must identify ONE profile, so a URL serving the other file's body is
// caught rather than accepted: the two would then be audited as one and the missing
// profile's entries would silently not be gaps. That is why these carry the "blacklist "
// directive prefix and a trailing newline rather than a bare path - disable-common has a
// "read-only ${HOME}/.mozilla/firefox/profiles.ini" line, so a bare ${HOME}/.mozilla
// matches both files and would wave the mixup through.
//
// The AppArmor abstractions are the second corpus, added because a single-source diff
// can only ever establish parity with that source. They are deny-shaped like firejail's
// (so the polarity matches bento's list), single-file, and maintained by an unrelated
// project, which is the property that matters: a store one of them overlooks is not
// automatically invisible to the other. Their parser is ParseAppArmor, not ParseFirejail
// - the formats share no syntax.
var upstreamSources = []struct {
	url      string
	sentinel string
	parse    func(content, home, runUser string) []audit.Candidate
}{
	{"https://raw.githubusercontent.com/netblue30/firejail/master/etc/inc/disable-common.inc", "blacklist ${HOME}/.ssh\n", audit.ParseFirejail},
	{"https://raw.githubusercontent.com/netblue30/firejail/master/etc/inc/disable-programs.inc", "blacklist ${HOME}/.mozilla\n", audit.ParseFirejail},
	{"https://gitlab.com/apparmor/apparmor/-/raw/master/profiles/apparmor.d/abstractions/private-files", "deny @{HOME}/.*history mrwkl,", audit.ParseAppArmor},
	{"https://gitlab.com/apparmor/apparmor/-/raw/master/profiles/apparmor.d/abstractions/private-files-strict", "audit deny @{HOME}/.ssh/{,**} mrwkl,", audit.ParseAppArmor},
}

// The paths the parser expands firejail's variables to; any absolute value works,
// it only has to match what denylist.Home/Runtime emit for the same home.
const (
	home    = "/home/u"
	runUser = "/run/user/1000"
)

func main() {
	// Every source must arrive intact. A partial set is refused rather than audited,
	// because a missing profile silently narrows the diff: the entries it would have
	// contributed simply are not gaps, and the gate reports a pass over a comparison it
	// never made. That is the failure this command exists to prevent.
	var sources []audit.Source
	for _, src := range upstreamSources {
		content, err := fetch(src.url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "denylist-audit: fetching %s: %v\n", src.url, err)
			os.Exit(2)
		}
		if !isProfile(content, src.sentinel) {
			fmt.Fprintf(os.Stderr, "denylist-audit: content fetched from %s does not carry %s, so it is not the expected upstream profile; refusing to report a pass\n", src.url, src.sentinel)
			os.Exit(2)
		}
		sources = append(sources, audit.Source{Content: content, Parse: src.parse})
	}
	os.Exit(report(os.Stdout, sources, home, runUser))
}

// isProfile reports whether content is plausibly the firejail profile that sentinel
// identifies - a directive that file has carried for years. Absent it, the fetch did not
// return the profile and the audit cannot conclude anything, so a zero-gap diff over it
// must not be reported as a pass.
func isProfile(content, sentinel string) bool {
	return strings.Contains(content, sentinel)
}

// report parses each upstream profile with its own parser, diffs the result it against bento's deny-list, writes the
// in-scope gaps (and an out-of-scope summary) to w, and returns the process exit code:
// 1 when any in-scope gap remains, 0 when the list already covers them. It is separated
// from main's network fetch so the gate's decision - the part CI depends on - is testable
// without touching the network.
func report(w io.Writer, sources []audit.Source, home, runUser string) int {
	// One diff logic, two triggers: this CLI and the completeness test both go through
	// audit.Audit, so they cannot reach contradictory verdicts on the same profile.
	unclassified, globs, outBySection := audit.Audit(sources, home, runUser)

	// Globs are reported for review (bento cannot express a wildcard; it covers the
	// class by shielding named instances) but do not fail the gate on their own.
	for _, g := range globs {
		fmt.Fprintf(w, "glob for review - verify bento's named instances cover it: %s [%s]\n", g.Path, g.Section)
	}

	if len(unclassified) == 0 {
		fmt.Fprintln(w, "no unclassified in-scope gaps: every secret/exec upstream shield is covered or excluded")
		reportOutOfScope(w, outBySection)
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
	reportOutOfScope(w, outBySection)
	return 1
}

// reportOutOfScope summarizes the firejail sections bento deliberately does not
// cover (privacy, other-app, system hardening), so they are accounted for, not
// silently dropped, but do not bury the in-scope gaps.
func reportOutOfScope(w io.Writer, bySection map[string]int) {
	if len(bySection) == 0 {
		return
	}
	total := 0
	for _, n := range bySection {
		total += n
	}
	fmt.Fprintf(w, "\n%d out-of-scope gap(s) skipped (firejail's privacy/other-app/system scope), by section:\n", total)
	for s, n := range bySection {
		fmt.Fprintf(w, "  %3d  %s\n", n, s)
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
		return "", fmt.Errorf("firejail profile exceeds %d bytes, which is not expected; refusing to audit a truncated file", maxBytes)
	}
	return string(body), nil
}
