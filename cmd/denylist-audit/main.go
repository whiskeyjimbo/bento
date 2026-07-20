// Command denylist-audit reports the home/runtime paths firejail shields that
// bento does not, so denylist gaps surface on a cycle instead of in a review.
//
// It fetches firejail's disable-common.inc (GPLv2, read as a reference/diff input,
// never vendored), maps its blacklist/read-only directives to bento's shield
// classes, and prints the gaps. Classification of each gap - DenyAll vs DenyWrite -
// stays a human call. Exit status is 1 when any gap is found, so CI can gate on it.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/whiskeyjimbo/bento-v2/internal/denylist"
	"github.com/whiskeyjimbo/bento-v2/internal/denylist/audit"
)

const firejailURL = "https://raw.githubusercontent.com/netblue30/firejail/master/etc/inc/disable-common.inc"

// The paths the parser expands firejail's variables to; any absolute value works,
// it only has to match what denylist.Home/Runtime emit for the same home.
const (
	home    = "/home/u"
	runUser = "/run/user/1000"
)

func main() {
	content, err := fetch(firejailURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "denylist-audit: fetching firejail profile: %v\n", err)
		os.Exit(2)
	}
	os.Exit(report(os.Stdout, content, home, runUser))
}

// report parses the firejail profile, diffs it against bento's deny-list, writes the
// in-scope gaps (and an out-of-scope summary) to w, and returns the process exit code:
// 1 when any in-scope gap remains, 0 when the list already covers them. It is separated
// from main's network fetch so the gate's decision - the part CI depends on - is testable
// without touching the network.
func report(w io.Writer, content, home, runUser string) int {
	candidates := audit.ParseFirejail(content, home, runUser)
	rules := append(denylist.Home(home), denylist.Runtime()...)
	gaps := audit.Diff(candidates, rules)

	inScope, outBySection := audit.SplitByScope(gaps)
	if len(inScope) == 0 {
		fmt.Fprintln(w, "no in-scope gaps: every secret/exec firejail shield is covered")
		reportOutOfScope(w, outBySection)
		return 0
	}

	fmt.Fprintf(w, "%d in-scope firejail-shielded path(s) bento does not fully cover:\n\n", len(inScope))
	section := ""
	for _, g := range inScope {
		if g.Section != section {
			section = g.Section
			fmt.Fprintf(w, "[%s]\n", section)
		}
		note := "missing"
		if g.Weaker {
			note = "present but DenyWrite; firejail blacklists (candidate DenyAll)"
		}
		if g.Glob {
			note += "; glob - shield the covering directory"
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
