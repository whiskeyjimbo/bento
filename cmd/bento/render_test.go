package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
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

// A detail too long for a cell has to leave the cell, or the alignment the table
// exists for is gone and the other rows go off screen with it. Relocating is not
// dropping: the text still has to appear in full, wrapped, below the table.
func TestWriteReportTableRelocatesAnOversizedDetail(t *testing.T) {
	long := "the degraded tier discloses a great deal " + strings.Repeat("and keeps going ", 40) + "to the end"
	var r enforce.Report
	r.Add(enforce.LayerFilesystem, enforce.Degraded, long)
	r.Add(enforce.LayerLimits, enforce.Enforced, "")

	var b bytes.Buffer
	writeReportTable(&b, r)
	out := b.String()

	header, rest, _ := strings.Cut(out, "\n")
	rows, notes, _ := strings.Cut(rest, "\n\n")
	for _, line := range strings.Split(header+"\n"+rows, "\n") {
		if len(line) > detailInline+len("filesystem  hardening  unavailable  ") {
			t.Errorf("table row is %d columns wide:\n%s", len(line), line)
		}
	}
	if !strings.Contains(rows, "see note below") {
		t.Errorf("the oversized row must point at its note; got:\n%s", rows)
	}
	if !strings.Contains(notes, string(enforce.LayerFilesystem)) {
		t.Errorf("the note must name its layer; got:\n%s", notes)
	}
	if flat := strings.Join(strings.Fields(notes), " "); !strings.Contains(flat, long) {
		t.Errorf("the note must carry the detail in full; got:\n%s", notes)
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

// 126 is what a shell returns when it could not execute a command, which is exactly how
// the exec block's EPERM surfaces - but only a manifest that blocks exec can have caused
// it, and only that code is evidence of it. Anything wider claims the manifest for a
// failure it had no part in.
func TestExecHintFiresOnlyWhenRelevant(t *testing.T) {
	blocked := &policy.Policy{Exec: policy.ExecNone}
	strict := &policy.Policy{Exec: policy.ExecNoneStrict}
	zero := &policy.Policy{}
	allowed := &policy.Policy{Exec: policy.ExecAll}

	enforced := func(code int) enforce.Result {
		var r enforce.Report
		r.Add(enforce.LayerExec, enforce.Enforced, "")
		return enforce.Result{ExitCode: code, Report: r}
	}
	unenforced := func(code int) enforce.Result {
		var r enforce.Report
		r.Add(enforce.LayerExec, enforce.Unavailable, "no seccomp on this platform")
		return enforce.Result{ExitCode: code, Report: r}
	}

	cases := []struct {
		name string
		p    *policy.Policy
		res  enforce.Result
		want string
	}{
		{"exec blocked, target could not exec", blocked, enforced(126), "exec: none"},
		{"exec blocked strictly", strict, enforced(126), "exec: none-strict"},
		{"the zero exec mode is none", zero, enforced(126), "exec: none"},
		{"subprocesses are allowed, so 126 is the script's own", allowed, enforced(126), ""},
		{"the block never landed, so it caused nothing", blocked, unenforced(126), ""},
		{"an ordinary failure under a blocking manifest", blocked, enforced(1), ""},
		{"a clean run", blocked, enforced(0), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			got := writeExecHint(&b, tc.p, tc.res)
			if got != (tc.want != "") {
				t.Errorf("hint emitted = %v, want %v (output: %q)", got, tc.want != "", b.String())
			}
			if tc.want != "" && !strings.Contains(b.String(), tc.want) {
				t.Errorf("hint does not name %q, the setting to change: %q", tc.want, b.String())
			}
		})
	}
}

// The legend is the only line that fires on a CLEAN run, so the case that matters is
// exit 0 under a blocking manifest - a script that continued past a refused write or
// exec, which every other hint reads as success.
func TestDenialLegendFiresOnACleanRun(t *testing.T) {
	// Both layers are named in every report a real run produces, and each line of the
	// legend answers for its own, so a case that omits one is not a case bento can be in.
	report := func(fs, exec enforce.State) enforce.Report {
		var r enforce.Report
		r.Add(enforce.LayerFilesystem, fs, "")
		r.Add(enforce.LayerExec, exec, "")
		return r
	}
	execEnforced := func() enforce.Report { return report(enforce.Enforced, enforce.Enforced) }
	execUnavailable := func() enforce.Report { return report(enforce.Enforced, enforce.Unavailable) }
	// The Landlock-only tier: no read-only remount behind it, so a refused write answers
	// EACCES and naming EROFS would map an error the script cannot emit.
	degradedFS := func() enforce.Report { return report(enforce.Degraded, enforce.Enforced) }

	cases := []struct {
		name      string
		p         *policy.Policy
		res       enforce.Result
		wantExec  string // the exec: line, or "" if it must not appear
		wantWrite bool   // the "Read-only file system" line
	}{
		{"a clean run under a blocking manifest still says so", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{ExitCode: 0, Report: execEnforced()}, "exec: none", true},
		{"the zero exec mode is none", &policy.Policy{}, enforce.Result{ExitCode: 0, Report: execEnforced()}, "exec: none", true},
		{"none-strict names itself", &policy.Policy{Exec: policy.ExecNoneStrict}, enforce.Result{ExitCode: 0, Report: execEnforced()}, "exec: none-strict", true},
		{"write grants alone are worth decoding", &policy.Policy{Exec: policy.ExecAll, Write: []string{"/tmp/out"}}, enforce.Result{Report: execEnforced()}, "", true},
		// No write grant leaves the whole tree read-only, so EROFS is not merely possible
		// there, it is certain for any write the script attempts.
		{"no write grant is the most restricted, not the least", &policy.Policy{Exec: policy.ExecAll}, enforce.Result{Report: execEnforced()}, "", true},
		{"a block that never landed names no exec field", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{Report: execUnavailable()}, "", true},
		// Each line answers for its own layer, so a tier that cannot produce EROFS drops
		// the write line and keeps the exec one.
		{"a tier without the remount does not promise EROFS", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{Report: degradedFS()}, "exec: none", false},
		{"neither layer in force says nothing at all", &policy.Policy{Exec: policy.ExecAll}, enforce.Result{Report: report(enforce.Degraded, enforce.Unavailable)}, "", false},
		// The hints that explain a failure have already spoken by here, and the legend's
		// own subject is the run that reported nothing.
		{"a failing run is somebody else's to explain", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{ExitCode: 1, Report: execEnforced()}, "", false},
		{"a signal death is not a clean exit", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{Signal: 9, Report: execEnforced()}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeDenialLegend(&b, tc.p, tc.res)
			out := b.String()
			if wantAny := tc.wantWrite || tc.wantExec != ""; (b.Len() > 0) != wantAny {
				t.Errorf("legend emitted = %v, want %v (output: %q)", b.Len() > 0, wantAny, out)
			}
			// The whole point is the mapping from the errno string the script printed to
			// the manifest field, so both halves have to survive a reword.
			if gotWrite := strings.Contains(out, "Read-only file system") && strings.Contains(out, "write:"); gotWrite != tc.wantWrite {
				t.Errorf("write errno mapped = %v, want %v: %q", gotWrite, tc.wantWrite, out)
			}
			if tc.wantExec == "" {
				if strings.Contains(out, "Operation not permitted") {
					t.Errorf("legend names an exec block that is not in force: %q", out)
				}
				return
			}
			if !strings.Contains(out, "Operation not permitted") || !strings.Contains(out, tc.wantExec) {
				t.Errorf("legend does not map the exec errno to %q: %q", tc.wantExec, out)
			}
		})
	}
}

// A cgroup kill is not a script failure, and the two shapes it arrives in - the
// wrapper signaled, or the kill relayed outward as 128+signal - must both be named as
// one. The relayed shape is the common one, and is hedged because a script can exit
// 137 itself; an ordinary failure must not be claimed as a signal at all.
func TestSignalNoticeNamesTheKill(t *testing.T) {
	limited := &policy.Policy{Limits: policy.Limits{Memory: "128M", PIDs: 32}}
	plain := &policy.Policy{}

	cases := []struct {
		name    string
		p       *policy.Policy
		res     enforce.Result
		want    []string
		notWant []string
		skip    bool
	}{
		{
			name: "the scope came down on the wrapper",
			p:    limited,
			res:  enforce.Result{ExitCode: 143, Signaled: true, Signal: 15},
			want: []string{"did not exit", "signal 15 (terminated)", "exit 143", "memory 128M, pids 32"},
		},
		{
			name: "the kill was relayed as an exit code",
			p:    limited,
			res:  enforce.Result{ExitCode: 137},
			want: []string{"exit 137", "signal 9 (killed)", "can also exit that code on its own", "memory 128M, pids 32"},
		},
		{
			name: "no limits declared: the signal is named, no cap is blamed",
			p:    plain,
			res:  enforce.Result{ExitCode: 139},
			want: []string{"signal 11 (segmentation fault)"},
		},
		{
			name:    "a segfault under declared limits is not a cap",
			p:       limited,
			res:     enforce.Result{ExitCode: 139},
			want:    []string{"signal 11 (segmentation fault)"},
			notWant: []string{"declares limits"},
		},
		{
			name:    "a broken pipe under declared limits is not a cap",
			p:       limited,
			res:     enforce.Result{ExitCode: 141},
			want:    []string{"signal 13 (broken pipe)"},
			notWant: []string{"declares limits"},
		},
		{
			// A scope torn down during setup arrives signaled with no script behind it, so
			// the notice must not attribute the death to one.
			name:    "the scope came down before the script started",
			p:       limited,
			res:     enforce.Result{ExitCode: 143, Signaled: true, Signal: 15, Setup: enforce.SetupSilent},
			want:    []string{"the run did not exit"},
			notWant: []string{"the script"},
		},
		{
			name: "SIGSYS names the filter that did it",
			p:    plain,
			res:  enforce.Result{ExitCode: 159, Signaled: true, Signal: 31},
			want: []string{"signal 31 (bad system call)", "seccomp filter", "foreign-architecture", "EPERM"},
		},
		{
			// The cap wording would read as an explanation of the SIGSYS, and a foreign-arch
			// kill has nothing to do with a declared limit.
			name:    "SIGSYS under declared limits is not a cap",
			p:       limited,
			res:     enforce.Result{ExitCode: 159, Signaled: true, Signal: 31},
			want:    []string{"foreign-architecture"},
			notWant: []string{"declares limits"},
		},
		{
			name:    "a cap kill is not blamed on seccomp",
			p:       limited,
			res:     enforce.Result{ExitCode: 137, Signaled: true, Signal: 9},
			notWant: []string{"seccomp filter"},
		},
		{name: "an ordinary failure", p: plain, res: enforce.Result{ExitCode: 1}, skip: true},
		{name: "a clean run", p: limited, res: enforce.Result{ExitCode: 0}, skip: true},
		{name: "bento's own could-not-run code", p: limited, res: enforce.Result{ExitCode: bentoFailed}, skip: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if got := writeSignalNotice(&b, tc.p, tc.res); got == tc.skip {
				t.Fatalf("notice emitted = %v, want %v (output: %q)", got, !tc.skip, b.String())
			}
			if tc.skip && b.Len() != 0 {
				t.Fatalf("a run that did not die on a signal must print nothing; got %q", b.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(b.String(), want) {
					t.Errorf("the notice must say %q; got:\n%s", want, b.String())
				}
			}
			for _, notWant := range tc.notWant {
				if strings.Contains(b.String(), notWant) {
					t.Errorf("the notice must not say %q for a signal no cap kill sends; got:\n%s", notWant, b.String())
				}
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
	for line := range strings.SplitSeq(strings.TrimRight(b.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "[bento] ") {
			t.Errorf("a crafted host forged the line %q in %q", line, b.String())
		}
	}
	if strings.Contains(b.String(), "nothing was blocked\n") {
		t.Errorf("the host was not quoted; got %q", b.String())
	}
}

// The denial notice is the only place the destination the script actually asked for is
// named - it met the refusal as a 403 inside its own traceback. It points at the
// profiling mode that forwards egress, since the default one reproduces the failure.
// Hosts are quoted for the same reason the guard-blocked notice quotes them.
func TestWriteDeniedWarning(t *testing.T) {
	var b bytes.Buffer
	if writeDeniedWarning(&b, &policy.Policy{Entrypoint: "./t.py"}, enforce.Result{}) || b.Len() != 0 {
		t.Errorf("a run the allowlist refused nothing on must print nothing; got %q", b.String())
	}

	if !writeDeniedWarning(&b, &policy.Policy{Entrypoint: "./t.py"}, enforce.Result{Denied: []enforce.HostPort{
		{Host: "api.github.com", Port: "443"},
		{Host: "evil.example\n[bento] nothing was denied", Port: "80"},
	}}) {
		t.Error("a denial must be reported")
	}
	out := b.String()
	for _, want := range []string{"api.github.com", "443", `bento profile "./t.py" --allow-network`} {
		if !strings.Contains(out, want) {
			t.Errorf("the notice must contain %q; got %q", want, out)
		}
	}
	for line := range strings.SplitSeq(strings.TrimRight(out, "\n"), "\n") {
		if !strings.HasPrefix(line, "[bento] ") {
			t.Errorf("a crafted host forged the line %q in %q", line, out)
		}
	}
}

// A read grant naming nothing grants nothing and the sandbox then denies that path
// silently, which is the failure hardest to trace back to the manifest. An approved
// manifest is never re-validated, so run is the last place to say it. Write grants are
// created by the backend, so their absence is not a miss.
func TestWriteMissingReadNotes(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "here")
	if err := os.WriteFile(present, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(dir, "gone")

	p := &policy.Policy{Read: []string{present}, Write: []string{filepath.Join(dir, "out")}}
	var b bytes.Buffer
	writeMissingReadNotes(&b, missingReadGrants(p.Read))
	if b.Len() != 0 {
		t.Errorf("a grant that exists and a write grant yet to be created must print nothing; got %q", b.String())
	}

	writeMissingReadNotes(&b, missingReadGrants([]string{present, gone}))
	out := b.String()
	if !strings.Contains(out, gone) {
		t.Errorf("the note must name the missing grant %q; got %q", gone, out)
	}
	if strings.Contains(out, present+"\"") {
		t.Errorf("the grant that exists must not be reported; got %q", out)
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

	for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
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

// The degraded filesystem tier skips the credential-alias scan entirely, which is the
// widest thing --allow-degraded gives up - and it was readable only from the help text of
// --accept-alias, the flag such a run did not pass. The disclosure keys on the probed
// filesystem state and not on the flag: --allow-degraded on a host where bwrap works
// still scans, so claiming otherwise there would be its own dishonesty.
func TestWriteDegradationsNamesTheSkippedAliasScan(t *testing.T) {
	var degraded enforce.Report
	degraded.Add(enforce.LayerFilesystem, enforce.Degraded, "no user namespaces")
	var b bytes.Buffer
	writeDegradations(&b, degraded)
	if !strings.Contains(b.String(), "never scans for credential aliases") {
		t.Errorf("a degraded filesystem run must disclose the skipped alias scan; got:\n%s", b.String())
	}

	var other enforce.Report
	other.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	other.Add(enforce.LayerExec, enforce.Unavailable, "no seccomp on this host")
	var full bytes.Buffer
	writeDegradations(&full, other)
	if strings.Contains(full.String(), "never scans for credential aliases") {
		t.Errorf("a run whose filesystem tier scanned must not claim it skipped the scan; got:\n%s", full.String())
	}
}

// run's only account of a guard refusal was writeGuardBlockedWarning, which fires after
// the connection was already refused. The manifest records what the profiling run met,
// so the rule can be marked before the script starts - and stays a note, since the
// record is provenance a hand-edited manifest can carry.
func TestWriteBlockedHostNotes(t *testing.T) {
	p := &policy.Policy{
		Entrypoint: "./x",
		Network: []policy.NetworkRule{
			{Host: ".internal", Port: "80"},
			{Host: "example.com", Port: "443"},
		},
	}

	var b bytes.Buffer
	writeBlockedHostNotes(&b, p, []string{"metadata.internal:80"})
	out := b.String()
	if !strings.Contains(out, `".internal" port "80"`) || !strings.Contains(out, "egress guard refused") {
		t.Errorf("the note must name the rule covering the refusal; got:\n%s", out)
	}
	if strings.Contains(out, "example.com") {
		t.Errorf("a rule covering no refusal must not be named; got:\n%s", out)
	}

	// The ordinary run: nothing was refused during profiling, so nothing is said.
	var quiet bytes.Buffer
	writeBlockedHostNotes(&quiet, p, nil)
	if quiet.Len() != 0 {
		t.Errorf("with no record the note must stay silent; got %q", quiet.String())
	}
}

// A read grant naming a credential shield exactly is the one grant that lifts a shield
// bento otherwise applies unconditionally, and the run-time warning for it only lands
// after the target has printed whatever it read. validate and approve raise it from
// this, so it has to match the backend's own opt-in test: the shield exactly, never a
// path inside one (which the run refuses outright) and never one containing one (which
// is an ordinary broad grant).
func TestExplicitShieldGrants(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")

	got, err := explicitShieldGrants([]string{sshDir, filepath.Join(sshDir, "id_rsa"), home, "/srv/app"})
	if err != nil {
		t.Fatalf("explicitShieldGrants: %v", err)
	}
	if !slices.Contains(got, sshDir) {
		t.Errorf("a grant naming the shield exactly must be reported; got %v", got)
	}
	for _, unwanted := range []string{filepath.Join(sshDir, "id_rsa"), home, "/srv/app"} {
		if slices.Contains(got, unwanted) {
			t.Errorf("%q is not an opt-in the run honors and must not be reported; got %v", unwanted, got)
		}
	}
	quiet, err := explicitShieldGrants([]string{home, "/srv/app"})
	if err != nil || len(quiet) != 0 {
		t.Errorf("a policy touching no shield must report nothing; got %v, %v", quiet, err)
	}
}

// The HOME remap is the headline gotcha, and the moment it costs someone is a run that
// failed on a path nobody wrote. Bento holds all three facts then - nonzero exit, a
// grant under the caller's home, HOME absent from env: - so the note validate prints
// while the grants are being reviewed has to fire here too. It stays quiet in the cases
// that look similar but are not: HOME passed through, a clean exit, and a grant that is
// nowhere near the home tree.
func TestSandboxHomeMissFiresOnlyWhenRelevant(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	granted := filepath.Join(home, "bento-journey-data")

	cases := []struct {
		name string
		p    *policy.Policy
		res  enforce.Result
		want bool
	}{
		{"failed run, grant under home, HOME not passed", &policy.Policy{Read: []string{granted}}, enforce.Result{ExitCode: 1}, true},
		{"the write grants are checked too", &policy.Policy{Write: []string{granted}}, enforce.Result{ExitCode: 1}, true},
		{"HOME is passed through, so ~ lands where the author meant", &policy.Policy{Read: []string{granted}, Env: []string{"HOME"}}, enforce.Result{ExitCode: 1}, false},
		{"the run succeeded", &policy.Policy{Read: []string{granted}}, enforce.Result{ExitCode: 0}, false},
		{"no grant is under the home tree", &policy.Policy{Read: []string{"/srv/app"}}, enforce.Result{ExitCode: 1}, false},
		{"a sibling of home is not under it", &policy.Policy{Read: []string{home + "-backup"}}, enforce.Result{ExitCode: 1}, false},
		{"a dotted name inside home has not escaped it", &policy.Policy{Read: []string{filepath.Join(home, "..cache")}}, enforce.Result{ExitCode: 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeSandboxHomeMiss(&b, tc.p, tc.res)
			got := strings.Contains(b.String(), "HOME is not passed through")
			if got != tc.want {
				t.Errorf("note emitted = %v, want %v (output: %q)", got, tc.want, b.String())
			}
		})
	}
}
