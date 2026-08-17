package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
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

// fetch's job is to sort what came back into "try again later" and "this is not the
// profile", because the wrapper passes over the first and fails on the second. The
// discriminating bit is errRefuse, not the message, so that is what is asserted.
func TestFetchClassifiesTheResponse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		wantRefuse bool
	}{
		{"renamed upstream", http.StatusNotFound, true},
		{"forbidden", http.StatusForbidden, true},
		{"server having a bad day", http.StatusServiceUnavailable, false},
		{"rate limited", http.StatusTooManyRequests, false},
		{"request timeout", http.StatusRequestTimeout, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			_, err := fetch(srv.URL)
			if err == nil {
				t.Fatalf("status %d returned no error", tc.status)
			}
			if got := errors.Is(err, errRefuse); got != tc.wantRefuse {
				t.Errorf("status %d: refused = %v, want %v; the wrapper passes over a non-refusal and fails on a refusal", tc.status, got, tc.wantRefuse)
			}
		})
	}
}

// A transport error is the flakiness the pass-over status exists for, so it must not
// come back as a refusal - a refusal fails the gate.
func TestFetchTreatsATransportErrorAsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := fetch(url)
	if err == nil {
		t.Fatal("a dial to a closed server returned no error")
	}
	if errors.Is(err, errRefuse) {
		t.Errorf("a dial failure was refused (%v); it is an infrastructure condition, not a judgement about a response", err)
	}
}

// The size ceiling is read one byte past the cap so a body that hit it is detected
// rather than silently truncated - a truncated profile drops its tail sections from the
// comparison and could hide the gaps there. Both sides of the boundary, because an
// off-by-one here either refuses every real fetch or lets a truncated one through.
func TestFetchRefusesOnlyPastTheSizeCeiling(t *testing.T) {
	const maxBytes = 1 << 20
	for _, tc := range []struct {
		name       string
		size       int
		wantRefuse bool
	}{
		{"at the ceiling", maxBytes, false},
		{"one byte past", maxBytes + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write(bytes.Repeat([]byte("x"), tc.size)); err != nil {
					t.Errorf("serving the fixture body: %v", err)
				}
			}))
			defer srv.Close()

			body, err := fetch(srv.URL)
			if tc.wantRefuse {
				if !errors.Is(err, errRefuse) {
					t.Errorf("a %d-byte body was accepted (err %v); auditing a truncated copy hides the gaps in its tail", tc.size, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("a %d-byte body must be accepted whole: %v", tc.size, err)
			}
			if len(body) != tc.size {
				t.Errorf("body = %d bytes, want %d; a silently truncated profile drops its tail from the diff", len(body), tc.size)
			}
		})
	}
}

// The audit compares its own rule set against an upstream corpus, so that rule set has to
// be the same on every host: a relocation variable in the developer's shell adds a rule CI
// does not have, which can cover an upstream candidate and turn a real gap green. run
// clears them before building anything, and it must clear ALL of them - the list is
// assembled from the tables the rules read, so a variable added there is cleared here.
func TestRunClearsTheRelocationEnvironment(t *testing.T) {
	for _, v := range denylist.RelocationVars() {
		t.Setenv(v, "/srv/planted")
	}
	var b bytes.Buffer
	run(func(string) (string, error) { return "", errors.New("offline") }, &b, &b)
	for _, v := range denylist.RelocationVars() {
		if got := os.Getenv(v); got != "" {
			t.Errorf("$%s is still %q after run, so the audit's rule set is this host's", v, got)
		}
	}
}

// main's status is the CI wrapper's whole input, so run must hand each of collect's
// refusals up unchanged - collapsing the two would put a permanently wrong URL on the
// arm that prints "offline?" and passes. And a healthy fetch must reach the audit's own
// verdict rather than any refusal status, or the gate would report on a diff it skipped.
func TestRunReportsTheStatusTheWrapperSwitchesOn(t *testing.T) {
	var b bytes.Buffer
	if code := run(func(string) (string, error) { return "", errors.New("dial tcp: no route to host") }, &b, &b); code != exitFetchFailed {
		t.Errorf("run = %d over an unreachable upstream, want %d so the wrapper skips rather than reddens", code, exitFetchFailed)
	}
	b.Reset()
	// The same unreachable upstream on a run that was required to fetch. It cannot share
	// exitFetchFailed: that status is the one the wrapper passes over, so the scheduled
	// check would report the outage it exists to catch as a green skip.
	t.Setenv(requireFetchVar, "1")
	if code := run(func(string) (string, error) { return "", errors.New("dial tcp: no route to host") }, &b, &b); code != exitFetchRequired {
		t.Errorf("run = %d over an unreachable upstream with $%s set, want %d so the wrapper reddens", code, requireFetchVar, exitFetchRequired)
	}
	if !strings.Contains(b.String(), requireFetchVar) {
		t.Errorf("the banner must name why this run could not pass over the fetch; got %q", b.String())
	}
	os.Unsetenv(requireFetchVar)
	b.Reset()
	if code := run(func(string) (string, error) { return "<html>404</html>", nil }, &b, &b); code != exitContentRefused {
		t.Errorf("run = %d when a body is not the profile, want %d so the wrapper fails", code, exitContentRefused)
	}
	b.Reset()
	healthy := func(url string) (string, error) {
		for _, src := range upstreamSources {
			if src.url == url {
				return fullBody(src.sentinel, src.minCandidates), nil
			}
		}
		return "", fmt.Errorf("no fixture for %s", url)
	}
	if code := run(healthy, &b, &b); code == exitFetchFailed || code == exitContentRefused {
		t.Errorf("run = %d with every source intact; a refusal status here would report a fetch problem over an audit that ran", code)
	}
}

// The wrapper's case arms are the other half of that contract, and the mapping is where
// the original P0 lived - a real failure landing on the arm that prints "offline?" and
// passes. No Go test reaches scripts/denylist-audit.sh through make audit, so it is
// driven here: a fake `go` on PATH builds a stub that exits with the status under test,
// and the banner pins which arm ran rather than the exit code alone.
func TestWrapperMapsEachStatusToItsVerdict(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	fake := filepath.Join(t.TempDir(), "go")
	const shim = "#!/bin/sh\nout=\nwhile [ $# -gt 0 ]; do\n\tif [ \"$1\" = -o ]; then out=$2; fi\n\tshift\ndone\nprintf '#!/bin/sh\\nexit %s\\n' \"$STUB_STATUS\" >\"$out\"\nchmod +x \"$out\"\n"
	if err := os.WriteFile(fake, []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		stub   int    // what the audit binary exits with
		want   int    // what the wrapper must report to CI
		banner string // the arm that must have run; empty means the silent pass arm
	}{
		{0, 0, ""},
		{1, 1, "in-scope upstream shields are missing"},
		{3, 0, "skipping the check"},
		{4, 1, "proved nothing"},
		{5, 1, "could not clear a relocation variable"},
		{6, 1, "required the upstream corpora"},
		// A panic exits 2. It must not reach the pass-over arm, which is why that arm
		// is 3 and not 2.
		{2, 2, "unexpected failure (exit 2)"},
		{126, 126, "unexpected failure (exit 126)"},
	} {
		t.Run(fmt.Sprintf("status%d", tc.stub), func(t *testing.T) {
			cmd := exec.Command(filepath.Join(repo, "scripts", "denylist-audit.sh"))
			cmd.Dir = repo
			// The script is set -u, so it gets the real environment with only PATH
			// replaced - dropping the old entry rather than shadowing it, since which
			// of two PATH= entries a shell honours is not specified.
			env := slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "PATH=") })
			cmd.Env = append(env,
				"PATH="+filepath.Dir(fake)+string(os.PathListSeparator)+os.Getenv("PATH"),
				fmt.Sprintf("STUB_STATUS=%d", tc.stub))
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			got := 0
			if err := cmd.Run(); err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatalf("running the wrapper: %v", err)
				}
				got = exit.ExitCode()
			}
			if got != tc.want {
				t.Errorf("audit exited %d, wrapper reported %d, want %d\n%s", tc.stub, got, tc.want, out.String())
			}
			// The silent arm is asserted as silence, not as a substring: status 3 also
			// exits 0, so only the absence of its banner tells the two apart.
			if tc.banner == "" && out.Len() != 0 {
				t.Errorf("a clean audit must say nothing; got:\n%s", out.String())
			}
			if !strings.Contains(out.String(), tc.banner) {
				t.Errorf("wrapper on status %d must say %q; got:\n%s", tc.stub, tc.banner, out.String())
			}
		})
	}
}

// The count floor only catches a corpus that got SHORTER. One that moved its entries
// behind a syntax the parser does not read keeps its length and loses them from the diff,
// which reads as "no gaps there" just the same - so the share each parser could not
// understand has a ceiling of its own.
func TestCollectRefusesACorpusItCannotRead(t *testing.T) {
	var b bytes.Buffer
	_, code := collect(func(url string) (string, error) {
		for _, src := range upstreamSources {
			if src.url != url {
				continue
			}
			body := fullBody(src.sentinel, src.minCandidates)
			// An unclassified variable: the directives are all still there, and every one
			// of them is answered "out of scope" by a parser that has never seen the
			// spelling.
			for i := range src.minCandidates {
				if strings.HasPrefix(src.sentinel, "blacklist") {
					body += fmt.Sprintf("blacklist ${XDGDATA}/moved%d\n", i)
				} else {
					body += fmt.Sprintf("  deny @{XDG_DATA}/moved%d mrwkl,\n", i)
				}
			}
			return body, nil
		}
		return "", nil
	}, &b)
	if code != exitContentRefused {
		t.Errorf("a corpus the parser can no longer read must exit %d; got %d (%q)", exitContentRefused, code, b.String())
	}
	if !strings.Contains(b.String(), "unparsed") {
		t.Errorf("the refusal must say what share went unread; got %q", b.String())
	}
}

// The ratio ceiling in collect only fires on a collapse. A slice of a corpus going quiet
// moves the count long before it moves the ratio, so the report says per profile what the
// parser could not read - whether or not anything else about the run is interesting.
func TestReportNamesWhatTheParserCouldNotRead(t *testing.T) {
	content := liveSections() + "blacklist ${XDGDATA}/keyrings\n"

	var b bytes.Buffer
	if code := report(&b, []audit.Source{{Name: "disable-common.inc", Content: content, Parse: audit.ParseFirejail}}, "/home/u", "/run/user/1000"); code != 0 {
		t.Fatalf("an unread directive is a note, not a gate failure; got %d (%q)", code, b.String())
	}
	if !strings.Contains(b.String(), "disable-common.inc: 1 of ") {
		t.Errorf("the report must name the profile and the count; got %q", b.String())
	}
}

// A permanently moved upstream URL is the same condition as a 404 - the profile is not at
// the address the audit knows - but it arrives as a redirect the client would follow, and
// a chain past the hop limit arrives as a transport error rather than a status at all.
// Left on the pass-over status the wrapper prints "offline?" and greens the gate forever,
// so a gap opened after the move is never surfaced. Neither of these URLs redirects today,
// so a redirect IS the move.
func TestFetchRefusesARedirect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"moved permanently", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/moved", http.StatusMovedPermanently)
		}},
		{"found", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}},
		{"redirect loop past the hop limit", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/loop", http.StatusFound)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			_, err := fetch(srv.URL)
			if err == nil {
				t.Fatal("a redirected fetch returned no error")
			}
			if !errors.Is(err, errRefuse) {
				t.Errorf("a redirect was not refused (%v); the wrapper passes over a non-refusal, so a moved URL would green the gate forever", err)
			}
		})
	}
}
