package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist/audit"
)

// The gate's contract: exit 1 (and name the path) when an in-scope firejail shield is
// not covered by bento's deny-list. This is what CI keys off, so it is tested without
// the network by driving report() with fixture content.
func TestReportFlagsUncoveredInScopeShield(t *testing.T) {
	// A secret-section blacklist bento does not have.
	content := "# top secret\nblacklist ${HOME}/.some-new-secret-store\n"

	var b bytes.Buffer
	if code := report(&b, []audit.Source{{Content: content, Parse: audit.ParseFirejail}}, "/home/u", "/run/user/1000"); code != 1 {
		t.Fatalf("an uncovered in-scope shield must exit 1; got %d (%q)", code, b.String())
	}
	if !strings.Contains(b.String(), "/home/u/.some-new-secret-store") {
		t.Errorf("the missing path must be reported; got %q", b.String())
	}
}

// The complement: a shield bento already covers (~/.ssh is a DenyAll dir in
// denylist.Home) is not a gap, so the gate stays green.
func TestReportPassesWhenShieldCovered(t *testing.T) {
	content := "# top secret\nblacklist ${HOME}/.ssh\n"

	var b bytes.Buffer
	if code := report(&b, []audit.Source{{Content: content, Parse: audit.ParseFirejail}}, "/home/u", "/run/user/1000"); code != 0 {
		t.Fatalf("a covered shield must exit 0; got %d (%q)", code, b.String())
	}
}

// A 200 response whose body is not the firejail profile (an error page, an upstream
// rename or reformat) parses to zero candidates, which report() would read as
// "everything covered". The content check must reject it so the gate fails closed
// rather than reporting a false pass. The sentinel is per-source because the two
// profiles share no directive - checking disable-common's ${HOME}/.ssh against
// disable-programs would reject a good fetch.
func TestIsProfile(t *testing.T) {
	real := "# Home\nblacklist ${HOME}/.ssh\nblacklist ${HOME}/.gnupg\n"
	if !isProfile(real, "${HOME}/.ssh") {
		t.Error("the real profile must be recognized")
	}
	for name, content := range map[string]string{
		"empty":           "",
		"html error page": "<html><body>404 Not Found</body></html>",
		"include-only":    "# moved\ninclude disable-home.inc\n",
		"unrelated 200":   "just some other text file\n",
	} {
		if isProfile(content, "${HOME}/.ssh") {
			t.Errorf("%s: must not be accepted as the firejail profile", name)
		}
	}
}

// A sentinel must identify exactly ONE profile. A bare "${HOME}/.mozilla" looks
// distinct but is a substring of disable-common's "read-only
// ${HOME}/.mozilla/firefox/profiles.ini", so a URL mixup serving disable-common's body
// for disable-programs would pass the check, the two would be audited as one, and the
// ~1300 entries of the missing profile would silently not be gaps - the false pass the
// sentinel exists to prevent. Asserting mutual exclusion catches that; asserting the
// sentinels merely differ does not.
func TestFirejailSourceSentinelsIdentifyOneProfileEach(t *testing.T) {
	var firejail []int
	for i, src := range upstreamSources {
		if strings.Contains(src.url, "firejail") {
			firejail = append(firejail, i)
		}
	}
	if len(firejail) != 2 {
		t.Fatalf("expected the two firejail profiles, got %d", len(firejail))
	}
	dir := os.Getenv("FIREJAIL_DIR")
	if dir == "" {
		dir = "/etc/firejail"
	}
	bodies := make([]string, len(firejail))
	for i, si := range firejail {
		src := upstreamSources[si]
		name := src.url[strings.LastIndexByte(src.url, '/')+1:]
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Skipf("no local %s to check the sentinels against: %v", name, err)
		}
		bodies[i] = string(b)
	}
	for i, si := range firejail {
		src := upstreamSources[si]
		for j, body := range bodies {
			got := isProfile(body, src.sentinel)
			if want := i == j; got != want {
				t.Errorf("sentinel %q of source %d matched profile %d = %v, want %v; a sentinel that matches the other profile lets a URL mixup pass as a good fetch",
					src.sentinel, i, j, got, want)
			}
		}
	}
}

// An out-of-scope section (firejail's privacy/system scope, which bento's empty-root
// default already covers) is summarized, not treated as a gate failure.
func TestReportIgnoresOutOfScopeSection(t *testing.T) {
	content := "# KDE config\nblacklist ${HOME}/.config/some-kde-thing\n"

	var b bytes.Buffer
	if code := report(&b, []audit.Source{{Content: content, Parse: audit.ParseFirejail}}, "/home/u", "/run/user/1000"); code != 0 {
		t.Fatalf("an out-of-scope shield must not fail the gate; got %d (%q)", code, b.String())
	}
	if !strings.Contains(b.String(), "out-of-scope") {
		t.Errorf("the out-of-scope gap should be summarized, not dropped; got %q", b.String())
	}
}
