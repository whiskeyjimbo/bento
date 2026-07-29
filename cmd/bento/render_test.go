package main

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
)

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":       true,
		"127.0.0.1":       true,
		"127.0.0.2":       true, // all of 127/8 is loopback
		"::1":             true,
		"example.com":     false,
		"10.0.0.1":        false,
		"169.254.169.254": false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// The degradation contract is that a shortfall is surfaced LOUDLY, and this table is
// the surface a human actually reads (doctor, and the report printed alongside a
// refusal). An enforced layer carries no reason, so a renderer that dropped the detail
// column would still look right on a healthy host and would silently swallow exactly
// the text that explains a shortfall - which is why the degraded row's reason is
// asserted verbatim rather than just checking the layer appears.
func TestWriteReportTableSurfacesShortfallDetail(t *testing.T) {
	const reason = "the cpu controller is not delegated to your systemd user manager"
	var r enforce.Report
	r.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	r.Add(enforce.LayerLimitsCPU, enforce.Unavailable, reason)

	var b bytes.Buffer
	writeReportTable(&b, r)
	out := b.String()

	for _, want := range []string{
		"LAYER", "TIER", "STATE", "DETAIL", // the header names every column
		string(enforce.LayerFilesystem), enforce.Enforced.String(),
		string(enforce.LayerLimitsCPU), enforce.Unavailable.String(),
		enforce.TierHardening.String(), // the shortfall's tier tells the reader how much it costs
		reason,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report table must surface %q; got:\n%s", want, out)
		}
	}
}

func TestEgressHintFiresOnlyWhenRelevant(t *testing.T) {
	networked := &policy.Policy{Network: []policy.NetworkRule{{Host: "a.com", Port: "443"}}}
	noNetwork := &policy.Policy{}

	cases := []struct {
		name string
		p    *policy.Policy
		res  enforce.Result
		want bool
	}{
		{"likely bypass: network requested, failed, no proxy connections", networked, enforce.Result{ExitCode: 1, EgressConnections: 0}, true},
		{"used the proxy then failed for another reason", networked, enforce.Result{ExitCode: 1, EgressConnections: 3}, false},
		{"network run succeeded", networked, enforce.Result{ExitCode: 0, EgressConnections: 0}, false},
		{"no network requested", noNetwork, enforce.Result{ExitCode: 1, EgressConnections: 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeEgressHint(&b, tc.p, tc.res)
			got := strings.Contains(b.String(), "egress proxy")
			if got != tc.want {
				t.Errorf("hint emitted = %v, want %v (output: %q)", got, tc.want, b.String())
			}
		})
	}
}

// The guard-blocked notice names each destination and says what would actually help,
// since the sandbox itself was told only "could not reach". It stays silent for the run
// the guard never refused, which is every ordinary run.
func TestWriteGuardBlockedWarning(t *testing.T) {
	var b bytes.Buffer
	writeGuardBlockedWarning(&b, enforce.Result{})
	if b.Len() != 0 {
		t.Errorf("a run with no guard block must print nothing; got %q", b.String())
	}

	writeGuardBlockedWarning(&b, enforce.Result{GuardBlocked: []enforce.HostPort{
		{Host: "internal.example", Port: "443"},
		{Host: "db.example", Port: "5432"},
	}})
	out := b.String()
	for _, want := range []string{"internal.example", "443", "db.example", "5432", "explicit IP rule"} {
		if !strings.Contains(out, want) {
			t.Errorf("the notice must contain %q; got %q", want, out)
		}
	}
}

// A CONNECT target is whatever the sandboxed script asked for, so a host holding a
// newline would otherwise print as a second line and forge a line of this report.
func TestWriteGuardBlockedWarningQuotesTheHost(t *testing.T) {
	var b bytes.Buffer
	writeGuardBlockedWarning(&b, enforce.Result{GuardBlocked: []enforce.HostPort{
		{Host: "evil.example\n[bento] nothing was blocked", Port: "443"},
	}})
	for _, line := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "[bento] ") {
			t.Errorf("a crafted host forged the line %q in %q", line, b.String())
		}
	}
	if strings.Contains(b.String(), "nothing was blocked\n") {
		t.Errorf("the host was not quoted; got %q", b.String())
	}
}

// yz3.2: the warning names each opted-in credential path loudly, and stays silent when
// the policy opted into none (the common run).
func TestWriteShieldedGrantWarning(t *testing.T) {
	var b bytes.Buffer
	writeShieldedGrantWarning(&b, enforce.Result{ShieldedGrants: []string{"/home/u/.ssh", "/run"}})
	out := b.String()
	if !strings.Contains(out, "WARNING") {
		t.Errorf("the notice must be loud; got %q", out)
	}
	for _, p := range []string{"/home/u/.ssh", "/run"} {
		if !strings.Contains(out, p) {
			t.Errorf("the notice must name each opted-in path; %q missing from %q", p, out)
		}
	}

	var empty bytes.Buffer
	writeShieldedGrantWarning(&empty, enforce.Result{})
	if empty.Len() != 0 {
		t.Errorf("a run that opted into no shields must print nothing; got %q", empty.String())
	}
}

// The names that count as an opt-in come from the deny-list, which builds them from
// $HOME - so a grant can name one path while the store it exposes is somewhere else.
// The operator has to see which credential was actually handed over, not just the
// spelling that opted into it. The pairing is the backend's, resolved as it bound the
// grant; the frontend renders it rather than stat'ing the path again afterwards.
func TestWriteShieldedGrantWarningNamesTheResolvedStore(t *testing.T) {
	const granted, store = "/home/u/link/.ssh", "/home/u/real/.ssh"

	var b bytes.Buffer
	writeShieldedGrantWarning(&b, enforce.Result{
		ShieldedGrants:       []string{granted, "/run"},
		ShieldedGrantTargets: []enforce.CredentialAlias{{Path: granted, Credential: store}},
	})
	out := b.String()

	if !strings.Contains(out, "on this host: "+strconv.Quote(store)) {
		t.Errorf("the notice must name the store the grant lands on; %q missing from %q", store, out)
	}
	// An opt-in that names its own target has nothing more to say about it, so it gets no
	// second line - the backend reports a pair only where the two differ.
	if strings.Count(out, "on this host") != 1 {
		t.Errorf("only the aliased grant gets a second line; got %q", out)
	}
}

// Neither line of this block is manifest text: the grant is the deny-list's name for the
// shield it matched, built from $HOME, and the store is enumerated from the filesystem.
// Printed raw, either one with an embedded newline splits into two lines, and the second
// can be written to read like a warning bento itself emitted - the reviewer's whole reason
// for reading this block.
func TestWriteShieldedGrantWarningQuotesBothNames(t *testing.T) {
	granted := "/home/u\n[bento]   /also-nothing/.ssh"
	forged := "/home/u/real\n[bento]   /nothing-to-see-here"

	var b bytes.Buffer
	writeShieldedGrantWarning(&b, enforce.Result{
		ShieldedGrants:       []string{granted},
		ShieldedGrantTargets: []enforce.CredentialAlias{{Path: granted, Credential: forged}},
	})
	out := b.String()

	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if !strings.HasPrefix(line, "[bento]") {
			t.Errorf("a host-derived name must not be able to start a line of its own; got %q in:\n%s", line, out)
		}
	}
	for _, want := range []string{granted, forged} {
		if !strings.Contains(out, strconv.Quote(want)) {
			t.Errorf("%q must still be named, quoted; got:\n%s", want, out)
		}
	}
}

// The anchor set is the one shield fact a run cannot show: the count looks identical
// whether passwd corroborated $HOME or the lookup found nothing and left the caller's
// environment deciding alone. doctor is where an operator can see which one they have.
func TestWriteShieldAnchors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	var b bytes.Buffer
	writeShieldAnchors(&b)
	out := b.String()

	if !strings.Contains(out, strconv.Quote(home)) {
		t.Errorf("the anchors must name $HOME, quoted; %q missing from %q", home, out)
	}
	// This uid has a passwd entry (the test host), so both anchors are listed and the
	// single-anchor caveat stays quiet.
	if pw := denylist.PasswdHome(); pw != "" {
		if !strings.Contains(out, strconv.Quote(pw)) {
			t.Errorf("the anchors must name the passwd home; %q missing from %q", pw, out)
		}
		if strings.Contains(out, "only anchor") {
			t.Errorf("the single-anchor caveat must not fire where passwd answered; got %q", out)
		}
	}
}

func TestWriteExposedWarning(t *testing.T) {
	var b bytes.Buffer
	writeExposedWarning(&b, enforce.Result{Exposed: []enforce.ShieldApplied{
		{Path: "/home/u/.ssh", Kind: "hidden"},
		{Path: "/home/u/proj/.git/hooks", Kind: "read-only"},
	}})
	out := b.String()
	if !strings.Contains(out, "WARNING") {
		t.Errorf("the notice must be loud; got %q", out)
	}
	// Each exposed path is named with the protection the degraded tier could not deliver,
	// so the operator can see exactly what a normal run would have shielded.
	for _, want := range []string{"/home/u/.ssh", "hidden", "/home/u/proj/.git/hooks", "read-only"} {
		if !strings.Contains(out, want) {
			t.Errorf("the notice must name each exposed path and kind; %q missing from %q", want, out)
		}
	}

	var empty bytes.Buffer
	writeExposedWarning(&empty, enforce.Result{})
	if empty.Len() != 0 {
		t.Errorf("a run that exposed no shields (the full tier's every run) must print nothing; got %q", empty.String())
	}
}

// A run that read past a shield must say so on every invocation. The acknowledgement is
// per-run and easy to leave behind in a wrapper script, so the warning names both the
// alias and the credential it reached rather than reporting a count.
func TestWriteAcceptedAliasWarning(t *testing.T) {
	var b bytes.Buffer
	writeAcceptedAliasWarning(&b, enforce.Result{AcceptedAliases: []enforce.CredentialAlias{
		{Path: "/home/u/backups/2026-07-24/.ssh/id_rsa", Credential: "/home/u/.ssh/id_rsa"},
	}})
	for _, want := range []string{"/home/u/backups/2026-07-24/.ssh/id_rsa", "/home/u/.ssh/id_rsa", "WARNING"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the warning must mention %q; got:\n%s", want, b.String())
		}
	}
	var empty bytes.Buffer
	writeAcceptedAliasWarning(&empty, enforce.Result{})
	if empty.Len() != 0 {
		t.Errorf("the ordinary run with no acknowledged alias must print nothing; got %q", empty.String())
	}
}
