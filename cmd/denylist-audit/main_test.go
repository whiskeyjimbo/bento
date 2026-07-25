package main

import (
	"bytes"
	"strings"
	"testing"
)

// The gate's contract: exit 1 (and name the path) when an in-scope firejail shield is
// not covered by bento's deny-list. This is what CI keys off, so it is tested without
// the network by driving report() with fixture content.
func TestReportFlagsUncoveredInScopeShield(t *testing.T) {
	// A secret-section blacklist bento does not have.
	content := "# top secret\nblacklist ${HOME}/.some-new-secret-store\n"

	var b bytes.Buffer
	if code := report(&b, []string{content}, "/home/u", "/run/user/1000"); code != 1 {
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
	if code := report(&b, []string{content}, "/home/u", "/run/user/1000"); code != 0 {
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

// Each source must be checked against its OWN sentinel: a shared one would either
// reject a good fetch or, if weakened to something both files carry, stop catching the
// error page it exists to catch.
func TestFirejailSourceSentinelsAreDistinct(t *testing.T) {
	if len(firejailSources) != 2 {
		t.Fatalf("expected the two upstream profiles, got %d", len(firejailSources))
	}
	for _, src := range firejailSources {
		if src.sentinel == "" {
			t.Errorf("%s has no sentinel, so a 200 error page would pass as a profile", src.url)
		}
	}
	if firejailSources[0].sentinel == firejailSources[1].sentinel {
		t.Error("the two profiles share no directive, so a shared sentinel must reject one of them")
	}
}

// An out-of-scope section (firejail's privacy/system scope, which bento's empty-root
// default already covers) is summarized, not treated as a gate failure.
func TestReportIgnoresOutOfScopeSection(t *testing.T) {
	content := "# KDE config\nblacklist ${HOME}/.config/some-kde-thing\n"

	var b bytes.Buffer
	if code := report(&b, []string{content}, "/home/u", "/run/user/1000"); code != 0 {
		t.Fatalf("an out-of-scope shield must not fail the gate; got %d (%q)", code, b.String())
	}
	if !strings.Contains(b.String(), "out-of-scope") {
		t.Errorf("the out-of-scope gap should be summarized, not dropped; got %q", b.String())
	}
}
