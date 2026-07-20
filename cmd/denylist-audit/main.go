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

	candidates := audit.ParseFirejail(content, home, runUser)
	rules := append(denylist.Home(home), denylist.Runtime()...)
	gaps := audit.Diff(candidates, rules)
	if len(gaps) == 0 {
		fmt.Println("no gaps: every scoped firejail shield is covered")
		return
	}

	fmt.Printf("%d firejail-shielded path(s) bento does not fully cover:\n\n", len(gaps))
	for _, g := range gaps {
		note := "missing"
		if g.Weaker {
			note = "present but DenyWrite; firejail blacklists (candidate DenyAll)"
		}
		if g.Glob {
			note += "; glob - shield the covering directory"
		}
		fmt.Printf("  %-40s %s\n      (%s)\n", g.Path, note, g.Raw)
	}
	os.Exit(1)
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
