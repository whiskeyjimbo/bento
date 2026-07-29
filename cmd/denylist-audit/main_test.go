package main

import (
	"bytes"
	"errors"
	"fmt"
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
	content := liveSections() + "# top secret\nblacklist ${HOME}/.ssh\n"

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
	if !isProfile(real, "blacklist ${HOME}/.ssh") {
		t.Error("the real profile must be recognized")
	}
	// AppArmor indents its rules; the sentinel is the directive, not the layout.
	if !isProfile("# vim:syntax=apparmor\n  deny @{HOME}/.*history mrwkl,\n", "deny @{HOME}/.*history mrwkl,") {
		t.Error("an indented rule must be recognized")
	}
	for name, content := range map[string]string{
		"empty":           "",
		"html error page": "<html><body>404 Not Found</body></html>",
		"include-only":    "# moved\ninclude disable-home.inc\n",
		"unrelated 200":   "just some other text file\n",
		// The sibling problem: private-files-strict writes private-files' rules with an
		// "audit " prefix, so a substring sentinel of the one is satisfied by the other and
		// the mixup that the sentinel exists to catch passes as a good fetch.
		"the sibling profile": "# strict\n  audit deny @{HOME}/.ssh mrwkl,\n",
		// The converse: a longer path must not satisfy a sentinel naming its parent.
		"a longer path": "blacklist ${HOME}/.ssh/authorized_keys\n",
	} {
		if isProfile(content, "blacklist ${HOME}/.ssh") || isProfile(content, "deny @{HOME}/.ssh mrwkl,") {
			t.Errorf("%s: must not be accepted as the profile", name)
		}
	}
}

// The two refusals must not share a status: the wrapper script passes over a fetch
// failure (network flakiness is not a deny-list regression) and fails on everything
// else, so a corpus that arrived and is not the profile has to be distinguishable. The
// statuses also have to stay off 2, which Go's runtime uses for a panic - the pass-over
// arm would otherwise report a crash inside the audit as a green gate.
func TestCollectRefusalStatuses(t *testing.T) {
	bodies := map[string]string{}
	for _, src := range upstreamSources {
		bodies[src.url] = fullBody(src.sentinel, src.minCandidates)
	}

	var b bytes.Buffer
	if _, code := collect(func(string) (string, error) { return "", errors.New("dial tcp: no route to host") }, &b); code != exitFetchFailed {
		t.Errorf("a fetch failure must exit %d; got %d", exitFetchFailed, code)
	}
	b.Reset()
	if _, code := collect(func(string) (string, error) { return "<html>404 Not Found</html>", nil }, &b); code != exitContentRefused {
		t.Errorf("a 200 whose body is not the profile must exit %d; got %d", exitContentRefused, code)
	}
	b.Reset()
	sources, code := collect(func(url string) (string, error) { return bodies[url], nil }, &b)
	if code != 0 {
		t.Errorf("every source arriving intact must not stop the run; got %d (%q)", code, b.String())
	}
	if len(sources) != len(upstreamSources) {
		t.Errorf("all %d sources must reach the audit; got %d", len(upstreamSources), len(sources))
	}
	for _, code := range []int{exitGap, exitFetchFailed, exitContentRefused} {
		if code == 2 {
			t.Error("no status may be 2: the wrapper must be able to tell a panic from a skip")
		}
	}
}

// Not every fetch error is an infrastructure condition. A 404 (the profile was renamed)
// and an oversize body are judgements about what came back, and on the pass-over status
// they would print "offline?" and green the gate permanently - the failure this whole
// group of fixes is about. A 5xx or a transport error is the flakiness the wrapper is
// meant to ride over, and stays there.
func TestCollectSeparatesPermanentFetchFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"renamed upstream", fmt.Errorf("%w: unexpected status 404 Not Found", errRefuse), exitContentRefused},
		{"oversize body", fmt.Errorf("%w: it exceeds 1048576 bytes", errRefuse), exitContentRefused},
		{"server error", errors.New("unexpected status 503 Service Unavailable"), exitFetchFailed},
		{"no route", errors.New("dial tcp: no route to host"), exitFetchFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if _, code := collect(func(string) (string, error) { return "", tc.err }, &b); code != tc.want {
				t.Errorf("%v must exit %d; got %d", tc.err, tc.want, code)
			}
		})
	}
	// The rate-limit and request-timeout codes are 4xx by number and transient in
	// meaning, so they must not fail the gate.
	for _, code := range []int{408, 429} {
		if permanentStatus(code) {
			t.Errorf("status %d means try later, not a wrong URL", code)
		}
	}
	for _, code := range []int{403, 404, 410} {
		if !permanentStatus(code) {
			t.Errorf("status %d will not fix itself; it must fail the gate, not skip it", code)
		}
	}
}

// fullBody synthesizes a profile that carries sentinel and parses to exactly n
// candidates, in the syntax of whichever format the sentinel comes from. The floor is
// about volume, so the fixtures need volume; the paths themselves are never diffed here.
func fullBody(sentinel string, n int) string {
	var b strings.Builder
	b.WriteString(sentinel)
	b.WriteString("\n")
	for i := range n - 1 {
		if strings.HasPrefix(sentinel, "blacklist") {
			fmt.Fprintf(&b, "blacklist ${HOME}/.fill%d\n", i)
		} else {
			fmt.Fprintf(&b, "  deny @{HOME}/.fill%d mrwkl,\n", i)
		}
	}
	return b.String()
}

// A body can carry the sentinel and still be a fraction of the profile - a truncated
// response, or an upstream that moved most of its rules behind an include. Nothing
// asserted a lower bound, so the corpus tail was simply absent from the diff and the gate
// read that as "no gaps there".
func TestCollectRefusesAShortProfile(t *testing.T) {
	var b bytes.Buffer
	_, code := collect(func(url string) (string, error) {
		for _, src := range upstreamSources {
			if src.url == url {
				return fullBody(src.sentinel, src.minCandidates-1), nil
			}
		}
		return "", nil
	}, &b)
	if code != exitContentRefused {
		t.Errorf("a profile below its floor must exit %d; got %d (%q)", exitContentRefused, code, b.String())
	}
}

// One source failing refuses the whole run rather than auditing a narrowed corpus: the
// entries the missing profile would have contributed simply would not be gaps, and the
// gate would pass over a comparison it never made.
func TestCollectRefusesAPartialSet(t *testing.T) {
	var b bytes.Buffer
	last := upstreamSources[len(upstreamSources)-1].url
	sources, code := collect(func(url string) (string, error) {
		if url == last {
			return "", errors.New("unexpected status 404 Not Found")
		}
		for _, src := range upstreamSources {
			if src.url == url {
				return fullBody(src.sentinel, src.minCandidates), nil
			}
		}
		return "", nil
	}, &b)
	if code == 0 || sources != nil {
		t.Errorf("a partial set must not be audited; got %d sources, code %d", len(sources), code)
	}
}

// A sentinel must identify exactly ONE profile. A bare "${HOME}/.mozilla" looks
// distinct but is a substring of disable-common's "read-only
// ${HOME}/.mozilla/firefox/profiles.ini", so a URL mixup serving disable-common's body
// for disable-programs would pass the check, the two would be audited as one, and the
// ~1300 entries of the missing profile would silently not be gaps - the false pass the
// sentinel exists to prevent. Asserting mutual exclusion catches that; asserting the
// sentinels merely differ does not.
//
// This runs over ALL FOUR sources, not just firejail's pair. AppArmor's two abstractions
// are the closer call of the two pairs: private-files-strict restates private-files' rules
// with an "audit " prefix, so any substring sentinel taken from the one is satisfied by
// the other, and the pair had no mutual-exclusion check at all.
func TestSourceSentinelsIdentifyOneProfileEach(t *testing.T) {
	// The local copy of each corpus, by the file name its URL ends in. A distro package
	// is not the upstream master these URLs serve, which is the point: a sentinel that
	// only holds for the exact revision in CI is not a sentinel.
	dirs := map[string]string{
		"firejail": envDir("FIREJAIL_DIR", "/etc/firejail"),
		"apparmor": envDir("APPARMOR_DIR", "/etc/apparmor.d/abstractions"),
	}
	bodies := make([]string, len(upstreamSources))
	for i, src := range upstreamSources {
		corpus := "apparmor"
		if strings.Contains(src.url, "firejail") {
			corpus = "firejail"
		}
		name := src.url[strings.LastIndexByte(src.url, '/')+1:]
		b, err := os.ReadFile(filepath.Join(dirs[corpus], name))
		if err != nil {
			skipMissingDep(t, "no local %s to check the sentinels against: %v", name, err)
		}
		bodies[i] = string(b)
	}
	for i, src := range upstreamSources {
		for j, body := range bodies {
			got := isProfile(body, src.sentinel)
			if want := i == j; got != want {
				t.Errorf("sentinel %q of source %d matched profile %d (%s) = %v, want %v; a sentinel that matches another profile lets a URL mixup pass as a good fetch",
					src.sentinel, i, j, upstreamSources[j].url, got, want)
			}
		}
	}
}

func envDir(name, fallback string) string {
	if dir := os.Getenv(name); dir != "" {
		return dir
	}
	return fallback
}

// skipMissingDep skips for a missing host dependency, or fails when
// BENTO_REQUIRE_TEST_DEPS is set. A gate that self-skips reports a pass having proved
// nothing, which is indistinguishable from a run that checked something; the variable is
// how a host that is supposed to have the dependency (CI, and `make test`) says so.
func skipMissingDep(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("BENTO_REQUIRE_TEST_DEPS") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// An out-of-scope section (firejail's privacy/system scope, which bento's empty-root
// default already covers) is summarized, not treated as a gate failure.
func TestReportIgnoresOutOfScopeSection(t *testing.T) {
	content := liveSections() + "# KDE config\nblacklist ${HOME}/.config/some-kde-thing\n"

	var b bytes.Buffer
	if code := report(&b, []audit.Source{{Content: content, Parse: audit.ParseFirejail}}, "/home/u", "/run/user/1000"); code != 0 {
		t.Fatalf("an out-of-scope shield must not fail the gate; got %d (%q)", code, b.String())
	}
	if !strings.Contains(b.String(), "out-of-scope") {
		t.Errorf("the out-of-scope gap should be summarized, not dropped; got %q", b.String())
	}
}

// liveSections is a synthetic firejail preamble carrying one section per non-dormant
// scope keyword, each with a home path bento already shields. report ratchets on the
// keywords still matching a section, so a corpus built to exercise the diff arm has to
// say that it is not also asserting an upstream retitle - see TestReportFailsOnStaleScopeKeyword.
func liveSections() string {
	var b strings.Builder
	for _, kw := range audit.ScopeKeywords {
		if _, dormant := audit.DormantKeywords[kw]; dormant {
			continue
		}
		fmt.Fprintf(&b, "# %s\nblacklist ${HOME}/.ssh\n\n", kw)
	}
	return b.String()
}

// A scope keyword that matches no upstream section means firejail retitled the block out
// from under the classifier: its entries stopped being compared, and the gap list stays
// empty because nothing reaches it. inScopeSection fails open, so without this the gate
// reports a clean pass over a comparison it never made.
func TestReportFailsOnStaleScopeKeyword(t *testing.T) {
	content := strings.Replace(liveSections(), "# top secret\n", "# Sensitive material\n", 1)

	var b bytes.Buffer
	if code := report(&b, []audit.Source{{Content: content, Parse: audit.ParseFirejail}}, "/home/u", "/run/user/1000"); code != 1 {
		t.Fatalf("a retitled section must fail the gate; got %d (%q)", code, b.String())
	}
	if !strings.Contains(b.String(), "top secret") {
		t.Errorf("the stale keyword must be named so it can be re-pointed; got %q", b.String())
	}
}
