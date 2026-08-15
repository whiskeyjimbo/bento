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
	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
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

// A layer's consequences are the half of its disclosure a refusal deliberately does
// not print, so the two surfaces have to be held to opposite ends of that trade: the
// refusal leads with the remedy and says where the rest is, and doctor - the report
// the refusal sent the reader to - prints the rest in full. If either end slips, a
// disclosure has been dropped rather than relocated.
func TestConsequencesAreRelocatedNotDropped(t *testing.T) {
	const (
		reason       = "bwrap cannot make a user namespace here; install an AppArmor profile permitting it."
		consequences = "It confines filesystem read/write/exec, nothing more: no PID namespace, no network namespace"
	)
	short := enforce.LayerStatus{
		Layer: enforce.LayerFilesystem, State: enforce.Degraded,
		Reason: reason, Consequences: consequences,
	}

	var refusal bytes.Buffer
	writeRefusal(&refusal, "refusing to run", &enforce.Refusal{
		Reason: "a core guarantee cannot be fully enforced on this host",
		Short:  []enforce.LayerStatus{short},
	})
	// Whitespace-normalized: both surfaces wrap, so a line break inside the sentence is
	// not the failure this asserts.
	if !strings.Contains(strings.Join(strings.Fields(refusal.String()), " "), reason) {
		t.Errorf("the refusal dropped the diagnosis:\n%s", refusal.String())
	}
	if strings.Contains(refusal.String(), "no PID namespace") {
		t.Errorf("the refusal still buries its remedy under the tier consequences:\n%s", refusal.String())
	}
	if !strings.Contains(refusal.String(), "bento doctor") {
		t.Errorf("the refusal does not say where the rest of the disclosure is:\n%s", refusal.String())
	}

	// Every surface that describes the layer in full rather than pointing elsewhere: the
	// doctor table the refusal sent the reader to, the --allow-degraded path where the
	// operator is accepting these consequences, and the machine-readable report a harness
	// archives instead of the human output.
	var r enforce.Report
	r.AddStatus(short)
	var table, proceeded bytes.Buffer
	writeReportTable(&table, r)
	writeDegradations(&proceeded, r)
	for name, out := range map[string]string{"doctor": table.String(), "--allow-degraded": proceeded.String()} {
		// Normalized past both wrapping and the per-line "[bento] " prefix, neither of
		// which is the failure this asserts.
		flat := strings.Join(strings.Fields(strings.ReplaceAll(out, "[bento]", "")), " ")
		for _, want := range []string{reason, consequences} {
			if !strings.Contains(flat, want) {
				t.Errorf("%s must print %q; got:\n%s", name, want, out)
			}
		}
	}
	got := toReportJSON(r).Layers[0]
	if got.Detail != reason || got.Consequences != consequences {
		t.Errorf("--json dropped a half of the disclosure: %+v", got)
	}
}

// A refusal over a limit this host cannot apply is the one shortfall whose reader has
// nothing to go fix: the manifest asked for a cap and the host has no way to apply one,
// and on a container image without systemd neither end is theirs to change. So this
// refusal alone carries its ways out, and only where each really applies - the manifest
// edit wherever the shortfall is a limit, the flag only where it would admit the run.
// Under --strict it would not, since run refuses that flag alongside it, so strict is
// offered the edit without it rather than left with a diagnosis and no way past.
func TestLimitsRefusalNamesTheWayPast(t *testing.T) {
	limits := enforce.LayerStatus{
		Layer: enforce.LayerLimitsMemory, State: enforce.Unavailable,
		Reason: "systemd-run is not installed, so resource limits cannot be enforced unprivileged",
	}
	filesystem := enforce.LayerStatus{
		Layer: enforce.LayerFilesystem, State: enforce.Degraded,
		Reason: "bwrap cannot make a user namespace here",
	}
	for name, tc := range map[string]struct {
		refusal  *enforce.Refusal
		wantFlag bool
		wantEdit bool
	}{
		"waivable limits":     {&enforce.Refusal{Short: []enforce.LayerStatus{limits}, Waivable: true}, true, true},
		"strict limits":       {&enforce.Refusal{Short: []enforce.LayerStatus{limits}}, false, true},
		"waivable filesystem": {&enforce.Refusal{Short: []enforce.LayerStatus{filesystem}, Waivable: true}, false, false},
		"strict filesystem":   {&enforce.Refusal{Short: []enforce.LayerStatus{filesystem}}, false, false},
		// Strict refuses over every layer that fell short, so a reader told to drop
		// `limits:` here would be refused again by the filesystem tier they still have.
		"strict limits and filesystem": {&enforce.Refusal{Short: []enforce.LayerStatus{limits, filesystem}}, false, false},
	} {
		var b bytes.Buffer
		writeLimitsRemedy(&b, tc.refusal)
		flat := strings.Join(strings.Fields(b.String()), " ")
		if got := strings.Contains(flat, "--allow-degraded"); got != tc.wantFlag {
			t.Errorf("%s: offered the flag = %v, want %v; got:\n%s", name, got, tc.wantFlag, b.String())
		}
		if got := strings.Contains(flat, "`limits:`"); got != tc.wantEdit {
			t.Errorf("%s: offered the manifest edit = %v, want %v; got:\n%s", name, got, tc.wantEdit, b.String())
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
	r.Add(enforce.LayerLimitsMemory, enforce.Enforced, "")

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
	// A degraded filesystem layer: on the Landlock-only tier there is no read-only
	// remount behind it, so a refused write answers EACCES and naming EROFS would map an
	// error the script cannot emit. The same state also reaches a bwrap run whose Landlock
	// backstop failed, which the network: block is what separates.
	degradedFS := func() enforce.Report { return report(enforce.Degraded, enforce.Enforced) }

	cases := []struct {
		name     string
		p        *policy.Policy
		res      enforce.Result
		wantExec string // the exec: line, or "" if it must not appear
		wantFS   bool   // both filesystem lines, which share the mount namespace
		wantNet  bool   // the degraded tier's seccomp egress line
	}{
		{"a clean run under a blocking manifest still says so", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{ExitCode: 0, Report: execEnforced()}, "exec: none", true, false},
		{"the zero exec mode is none", &policy.Policy{}, enforce.Result{ExitCode: 0, Report: execEnforced()}, "exec: none", true, false},
		{"none-strict names itself", &policy.Policy{Exec: policy.ExecNoneStrict}, enforce.Result{ExitCode: 0, Report: execEnforced()}, "exec: none-strict", true, false},
		{"write grants alone are worth decoding", &policy.Policy{Exec: policy.ExecAll, Write: []string{"/tmp/out"}}, enforce.Result{Report: execEnforced()}, "", true, false},
		// No write grant leaves the whole tree read-only, so EROFS is not merely possible
		// there, it is certain for any write the script attempts.
		{"no write grant is the most restricted, not the least", &policy.Policy{Exec: policy.ExecAll}, enforce.Result{Report: execEnforced()}, "", true, false},
		{"a block that never landed names no exec field", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{Report: execUnavailable()}, "", true, false},
		// Each line answers for its own layer, so a tier that cannot produce EROFS drops
		// the write line and keeps the exec one.
		{"a tier without the remount does not promise EROFS", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{Report: degradedFS()}, "exec: none", false, true},
		// A manifest with network rules cannot be the Landlock-only tier - that tier has no
		// egress stack and the run refuses - so this is a bwrap run whose Landlock backstop
		// failed, where egress went through a proxy and the claim would contradict the
		// manifest the reader has open.
		{"network rules rule the seccomp egress line out", &policy.Policy{Exec: policy.ExecNone, Network: []policy.NetworkRule{{Host: "example.com"}}}, enforce.Result{Report: degradedFS()}, "exec: none", false, false},
		{"the degraded tier still fences egress, and says only that", &policy.Policy{Exec: policy.ExecAll}, enforce.Result{Report: report(enforce.Degraded, enforce.Unavailable)}, "", false, true},
		{"neither layer in force says nothing at all", &policy.Policy{Exec: policy.ExecAll}, enforce.Result{Report: report(enforce.Unavailable, enforce.Unavailable)}, "", false, false},
		// The hints that explain a failure have already spoken by here, and the legend's
		// own subject is the run that reported nothing.
		{"a failing run is somebody else's to explain", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{ExitCode: 1, Report: execEnforced()}, "", false, false},
		{"a signal death is not a clean exit", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{Signal: 9, Report: execEnforced()}, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeDenialLegend(&b, tc.p, tc.res, false)
			out := b.String()
			if wantAny := tc.wantFS || tc.wantExec != "" || tc.wantNet; (b.Len() > 0) != wantAny {
				t.Errorf("legend emitted = %v, want %v (output: %q)", b.Len() > 0, wantAny, out)
			}
			// The whole point is the mapping from the errno string the script printed to
			// the manifest field, so both halves have to survive a reword.
			if gotWrite := strings.Contains(out, "Read-only file system") && strings.Contains(out, "write:"); gotWrite != tc.wantFS {
				t.Errorf("write errno mapped = %v, want %v: %q", gotWrite, tc.wantFS, out)
			}
			// The read line shares the write line's layer, and must keep stating the
			// ambiguity: a cause here would blame the manifest for every absent file.
			if gotRead := strings.Contains(out, "No such file or directory"); gotRead != tc.wantFS {
				t.Errorf("read errno mapped = %v, want %v: %q", gotRead, tc.wantFS, out)
			}
			if tc.wantFS && !strings.Contains(out, "identical to truly absent") {
				t.Errorf("the read line must not read as a diagnosis: %q", out)
			}
			// Both EPERM lines share an errno string, so each is matched on the noun that
			// tells them apart - a command versus a socket.
			if gotNet := strings.Contains(out, "on a socket or connection"); gotNet != tc.wantNet {
				t.Errorf("seccomp egress errno mapped = %v, want %v: %q", gotNet, tc.wantNet, out)
			}
			if tc.wantExec == "" {
				if strings.Contains(out, "on a command") {
					t.Errorf("legend names an exec block that is not in force: %q", out)
				}
				return
			}
			if !strings.Contains(out, "on a command") || !strings.Contains(out, tc.wantExec) {
				t.Errorf("legend does not map the exec errno to %q: %q", tc.wantExec, out)
			}
		})
	}
}

// A zero-rule manifest is the one egress case with no reporter of its own: no proxy runs,
// so nothing observes the attempt and the reader is left holding an errno. The line is
// claimed off the filesystem layer, since a zero-rule run carries no network layer at all.
func TestDenialLegendNamesAnEmptyNetworkField(t *testing.T) {
	report := func(fs enforce.State) enforce.Report {
		var r enforce.Report
		r.Add(enforce.LayerFilesystem, fs, "")
		r.Add(enforce.LayerExec, enforce.Enforced, "")
		return r
	}
	const line = "no network: rules"

	var b bytes.Buffer
	writeDenialLegend(&b, &policy.Policy{}, enforce.Result{Report: report(enforce.Enforced)}, false)
	if !strings.Contains(b.String(), line) {
		t.Errorf("the field responsible for the failure is missing from the legend: %q", b.String())
	}

	// With rules there is a proxy, and its own hint names the destination it refused.
	b.Reset()
	writeDenialLegend(&b, &policy.Policy{Network: []policy.NetworkRule{{Host: "example.com", Port: "443"}}}, enforce.Result{Report: report(enforce.Enforced)}, false)
	if strings.Contains(b.String(), line) {
		t.Errorf("legend claims no rules over a manifest that has one: %q", b.String())
	}

	// The Landlock-only tier fences egress with a seccomp filter instead of a netns, so it
	// names the same field off a different errno - EPERM on socket(), not ENETUNREACH.
	b.Reset()
	writeDenialLegend(&b, &policy.Policy{Exec: policy.ExecNone}, enforce.Result{Report: report(enforce.Degraded)}, false)
	if strings.Contains(b.String(), "Network is unreachable") {
		t.Errorf("legend claims a shape no layer here produces: %q", b.String())
	}
	if !strings.Contains(b.String(), line) || !strings.Contains(b.String(), "on a socket or connection") {
		t.Errorf("the tier denies egress too, and the reader gets no mapping for it: %q", b.String())
	}
}

// The failing run is the one holding an errno string, and the generic hint tells it only
// that the sandbox denies silently - the mapping withheld. The two print together there,
// and the lead sentence stops claiming the exit code is unaffected, which that branch
// disproves.
func TestDenialLegendFollowsTheGenericHint(t *testing.T) {
	var r enforce.Report
	r.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	r.Add(enforce.LayerExec, enforce.Enforced, "")
	p := &policy.Policy{Exec: policy.ExecNone, Read: []string{"/data"}}
	res := enforce.Result{ExitCode: 1, Report: r}

	var b bytes.Buffer
	writeDenialLegend(&b, p, res, true)
	out := b.String()
	if !strings.Contains(out, "Read-only file system") || !strings.Contains(out, "exec: none") {
		t.Errorf("the branch that most needs the mapping must get it: %q", out)
	}
	if strings.Contains(out, "does not change its exit code") {
		t.Errorf("the run exited non-zero, so that lead is false here: %q", out)
	}

	// A signal death is explained by its own notice, which names the cap or the filter
	// that killed the run; the mapping under it offers four more causes to consider.
	b.Reset()
	writeDenialLegend(&b, p, enforce.Result{Signal: 9, Report: r}, false)
	if b.Len() > 0 {
		t.Errorf("a signal notice already explained this run: %q", b.String())
	}

	// The degraded tier is the thinnest legend there is - one line, no filesystem half -
	// so it is where the hint branch would most easily be left introducing nothing.
	var landlockOnly enforce.Report
	landlockOnly.Add(enforce.LayerFilesystem, enforce.Degraded, "")
	landlockOnly.Add(enforce.LayerExec, enforce.Unavailable, "")
	b.Reset()
	writeDenialLegend(&b, &policy.Policy{Exec: policy.ExecAll}, enforce.Result{ExitCode: 1, Report: landlockOnly}, true)
	if out := b.String(); !strings.Contains(out, "if that message was a denial") || !strings.Contains(out, "on a socket or connection") {
		t.Errorf("the one shape this tier produces must arrive with its lead: %q", out)
	}

	// The layer gate still decides whether there is a mapping at all, and it sits above
	// the lead: a tier that can produce none of these errnos must not print the sentence
	// that introduces them and then stop.
	var degraded enforce.Report
	degraded.Add(enforce.LayerFilesystem, enforce.Unavailable, "")
	degraded.Add(enforce.LayerExec, enforce.Unavailable, "")
	b.Reset()
	writeDenialLegend(&b, p, enforce.Result{ExitCode: 1, Report: degraded}, true)
	if b.Len() > 0 {
		t.Errorf("no layer can produce these errnos, so there is nothing to introduce: %q", b.String())
	}
}

// The two halves are wired through writeRunResult, so the order and the gating are
// asserted where a reader meets them rather than on the legend alone: the generic hint
// first, its shapes under it. The rule is the hint's own sentence, not the failure: where
// bento says the sandbox denies silently it says what a denial looks like, so a PATH miss
// - which names its cause and still gets the hint - gets the shapes too.
func TestFailingRunGetsTheHintThenTheShapes(t *testing.T) {
	var r enforce.Report
	r.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	r.Add(enforce.LayerExec, enforce.Enforced, "")

	var errOut bytes.Buffer
	p := &policy.Policy{Entrypoint: "/work/t.py", Read: []string{"/data"}}
	_ = writeRunResult(&errOut, false, p, nil, enforce.Result{ExitCode: 1, Report: r}, nil, nil, nil)
	got := errOut.String()
	hint := strings.Index(got, "denies silently")
	shapes := strings.Index(got, "Read-only file system")
	if hint < 0 || shapes < 0 {
		t.Fatalf("a failing run gets both the hint and the shapes; got:\n%s", got)
	}
	if shapes < hint {
		t.Errorf("the shapes explain the hint's own sentence, so they follow it; got:\n%s", got)
	}

	// 127 under a shell with no PATH grant: the miss note names the search path that lost
	// the command, the hint follows it anyway, and so the shapes must follow the hint -
	// the claim of silence and its mapping are never separated.
	errOut.Reset()
	shell := &policy.Policy{Entrypoint: "/work/t.sh", Interpreter: "/bin/sh", Read: []string{"/data"}}
	_ = writeRunResult(&errOut, false, shell, nil, enforce.Result{ExitCode: 127, Report: r}, nil, nil, nil)
	got = errOut.String()
	if !strings.Contains(got, "PATH is not passed through") {
		t.Fatalf("the PATH miss must still be explained; got:\n%s", got)
	}
	if strings.Contains(got, "denies silently") != strings.Contains(got, "Read-only file system") {
		t.Errorf("the claim of silence and its mapping must travel together; got:\n%s", got)
	}

	// A signal death is the branch that gets neither: its own notice names the cap or the
	// filter that killed the run, and the generic hint never speaks there.
	errOut.Reset()
	limited := &policy.Policy{Entrypoint: "/work/t.py", Read: []string{"/data"}, Limits: policy.Limits{Memory: "64M"}}
	_ = writeRunResult(&errOut, false, limited, nil, enforce.Result{ExitCode: 137, Signaled: true, Signal: 9, Report: r}, nil, nil, nil)
	got = errOut.String()
	if !strings.Contains(got, "killed by signal 9") {
		t.Fatalf("the kill must still be named; got:\n%s", got)
	}
	if strings.Contains(got, "denies silently") || strings.Contains(got, "Read-only file system") {
		t.Errorf("a signal notice explains this run alone; got:\n%s", got)
	}
}

// EPERM on an execve is bento's own verdict as much as EROFS is, so a summary that counts
// only paths leaves the reader hunting a field that is not the one that refused them.
func TestProfileHintNamesTheExecMode(t *testing.T) {
	report := func(exec enforce.State) enforce.Report {
		var r enforce.Report
		r.Add(enforce.LayerExec, exec, "")
		return r
	}
	cases := []struct {
		name string
		p    *policy.Policy
		res  enforce.Result
		want string
	}{
		{"a blocked exec is a grant withheld", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{ExitCode: 1, Report: report(enforce.Enforced)}, "exec: none"},
		{"the zero exec mode is none", &policy.Policy{}, enforce.Result{ExitCode: 1, Report: report(enforce.Enforced)}, "exec: none"},
		{"none-strict names itself", &policy.Policy{Exec: policy.ExecNoneStrict}, enforce.Result{ExitCode: 1, Report: report(enforce.Enforced)}, "exec: none-strict"},
		{"subprocesses are allowed, so nothing was withheld", &policy.Policy{Exec: policy.ExecAll}, enforce.Result{ExitCode: 1, Report: report(enforce.Enforced)}, ""},
		{"a block that never landed withheld nothing either", &policy.Policy{Exec: policy.ExecNone}, enforce.Result{ExitCode: 1, Report: report(enforce.Unavailable)}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if !writeProfileHint(&b, tc.p, tc.res) {
				t.Fatalf("a failing run gets the hint: %q", b.String())
			}
			out := b.String()
			if tc.want == "" {
				if strings.Contains(out, "exec:") {
					t.Errorf("hint names an exec block that withheld nothing: %q", out)
				}
				return
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("hint does not name %q, the field that refused a subprocess: %q", tc.want, out)
			}
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				if len(line) > textWidth {
					t.Errorf("line runs past the wrap column (%d): %q", len(line), line)
				}
			}
		})
	}
	var b bytes.Buffer
	if writeProfileHint(&b, &policy.Policy{}, enforce.Result{}) {
		t.Errorf("a clean run is not the hint's subject: %q", b.String())
	}
}

// A shield binds a read-only path inside a write grant, so EROFS arrives from a path the
// grant plainly covers. Naming only the grants there sends the reader to a manifest line
// that is correct, which is the misattribution the legend exists to avoid - and bento
// does observe this one, so it does not have to be guessed at.
func TestDenialLegendNamesAShieldInsideAWriteGrant(t *testing.T) {
	var r enforce.Report
	r.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	r.Add(enforce.LayerExec, enforce.Enforced, "")
	p := &policy.Policy{Exec: policy.ExecAll, Write: []string{"/tmp/out"}}

	readOnly := enforce.Result{Report: r, Shields: []enforce.ShieldApplied{{Path: "/tmp/out/.git/hooks", Kind: "read-only"}}}
	var b bytes.Buffer
	writeDenialLegend(&b, p, readOnly, false)
	if !strings.Contains(b.String(), "shielded path inside one") {
		t.Errorf("a read-only shield engaged, so the write line must admit it: %q", b.String())
	}

	// A hidden shield is unmounted, not read-only, so it cannot answer EROFS - widening
	// the line for it would hedge a cause that did not apply.
	hidden := enforce.Result{Report: r, Shields: []enforce.ShieldApplied{{Path: "/home/u/.ssh", Kind: "hidden"}}}
	b.Reset()
	writeDenialLegend(&b, p, hidden, false)
	if strings.Contains(b.String(), "shielded path inside one") {
		t.Errorf("no read-only shield engaged, so the grants stand alone: %q", b.String())
	}
	if !strings.Contains(b.String(), "Read-only file system") {
		t.Errorf("the write line must still appear: %q", b.String())
	}
}

// The errno lines are the whole legend only if every denial has an errno, and a hidden
// shield has none: the directory stats as an empty tmpfs, the file reads zero bytes. A
// reader who took the mapping as exhaustive would read that silence as access.
func TestDenialLegendNamesTheSilentShieldShapes(t *testing.T) {
	var r enforce.Report
	r.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	r.Add(enforce.LayerExec, enforce.Enforced, "")
	p := &policy.Policy{Exec: policy.ExecAll, Read: []string{"/home/u"}}
	const shapes = "reports no error either"

	hidden := enforce.Result{Report: r, Shields: []enforce.ShieldApplied{{Path: "/home/u/.ssh", Kind: "hidden"}}}
	var b bytes.Buffer
	writeDenialLegend(&b, p, hidden, false)
	out := b.String()
	if !strings.Contains(out, shapes) {
		t.Errorf("a hidden shield engaged, so its silence must be named: %q", out)
	}
	if !strings.Contains(out, "stats as empty") || !strings.Contains(out, "zero bytes") {
		t.Errorf("both shapes have to survive a reword - a shielded dir and a shielded file differ: %q", out)
	}

	// Naming a shape this run could not have produced is the misattribution the rest of
	// the legend is gated to avoid, so a run whose grants reached no hidden shield says
	// nothing about empty directories.
	readOnly := enforce.Result{Report: r, Shields: []enforce.ShieldApplied{{Path: "/tmp/out/.git/hooks", Kind: "read-only"}}}
	b.Reset()
	writeDenialLegend(&b, p, readOnly, false)
	if strings.Contains(b.String(), shapes) {
		t.Errorf("no hidden shield engaged, so the shapes did not apply: %q", b.String())
	}
	b.Reset()
	writeDenialLegend(&b, p, enforce.Result{Report: r}, false)
	if strings.Contains(b.String(), shapes) {
		t.Errorf("a run that shielded nothing must not name a shield: %q", b.String())
	}
}

// A discarded shield is the quietest of the three: the target's write to it SUCCEEDS and
// then vanishes with the run's scratch mount, so there is no errno for the legend's other
// lines to explain. A reader given only those lines concludes the write landed on the host.
func TestDenialLegendNamesADiscardedShield(t *testing.T) {
	var r enforce.Report
	r.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	r.Add(enforce.LayerExec, enforce.Enforced, "")
	p := &policy.Policy{Exec: policy.ExecAll, Write: []string{"/tmp/out"}}
	const vanished = "reached a scratch mount"

	discarded := enforce.Result{Report: r, Shields: []enforce.ShieldApplied{{Path: "/tmp/out/.git/hooks", Kind: "discarded"}}}
	var b bytes.Buffer
	writeDenialLegend(&b, p, discarded, false)
	if out := b.String(); !strings.Contains(out, vanished) {
		t.Errorf("a discarded shield engaged, so the write that vanishes must be named: %q", out)
	}

	// Gated like the other two: a run whose shields could not produce this shape must not
	// be told a write of its vanished.
	b.Reset()
	writeDenialLegend(&b, p, enforce.Result{Report: r, Shields: []enforce.ShieldApplied{{Path: "/home/u/.ssh", Kind: "hidden"}}}, false)
	if strings.Contains(b.String(), vanished) {
		t.Errorf("no discarded shield engaged, so nothing vanished: %q", b.String())
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

// A gate denial is the operator's own decision, so the notice must not tell them their
// manifest is missing the rule they just declined to add. It stays silent for the
// ungated run, which is every run with no gate installed.
func TestWriteGateDeniedWarning(t *testing.T) {
	var b bytes.Buffer
	if writeGateDeniedWarning(&b, enforce.Result{}) || b.Len() != 0 {
		t.Errorf("a run with no gate denial must print nothing; got %q", b.String())
	}

	if !writeGateDeniedWarning(&b, enforce.Result{GateDenied: []enforce.HostPort{
		{Host: "ads.example", Port: "443"},
	}}) {
		t.Error("a run with a gate denial must report that it said something")
	}
	out := b.String()
	for _, want := range []string{"ads.example", "443", "gate", "Nothing is wrong with the manifest"} {
		if !strings.Contains(out, want) {
			t.Errorf("the notice must contain %q; got %q", want, out)
		}
	}
}

// The request target is whatever the sandboxed script asked for, so it is quoted for the
// reason the guard-blocked notice quotes its own.
func TestWriteGateDeniedWarningQuotesTheHost(t *testing.T) {
	var b bytes.Buffer
	writeGateDeniedWarning(&b, enforce.Result{GateDenied: []enforce.HostPort{
		{Host: "evil.example\n[bento] the gate admitted everything", Port: "443"},
	}})
	for line := range strings.SplitSeq(strings.TrimRight(b.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "[bento] ") {
			t.Errorf("a crafted host forged the line %q in %q", line, b.String())
		}
	}
}

// The untunneled notice covers the one refusal a manifest edit cannot fix: validate and
// approve both report the network rule as granted, so the notice has to say the remedy is
// the client's, not the manifest's. It stays silent for the ordinary run.
func TestWriteUntunneledWarning(t *testing.T) {
	var b bytes.Buffer
	if writeUntunneledWarning(&b, enforce.Result{}) || b.Len() != 0 {
		t.Errorf("a run with nothing untunneled must print nothing; got %q", b.String())
	}

	if !writeUntunneledWarning(&b, enforce.Result{Untunneled: []enforce.HostPort{
		{Host: "example.com", Port: "80"},
	}}) {
		t.Error("a run with an untunneled destination must report that it said something")
	}
	out := b.String()
	for _, want := range []string{"example.com", "80", "CONNECT", "https", "will not change this"} {
		if !strings.Contains(out, want) {
			t.Errorf("the notice must contain %q; got %q", want, out)
		}
	}
}

// The request target is whatever the sandboxed script asked for, so it is quoted for the
// reason the guard-blocked notice quotes its own.
func TestWriteUntunneledWarningQuotesTheHost(t *testing.T) {
	var b bytes.Buffer
	writeUntunneledWarning(&b, enforce.Result{Untunneled: []enforce.HostPort{
		{Host: "evil.example\n[bento] everything was tunneled", Port: "80"},
	}})
	for line := range strings.SplitSeq(strings.TrimRight(b.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "[bento] ") {
			t.Errorf("a crafted host forged the line %q in %q", line, b.String())
		}
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
	writeMissingReadNotes(&b, gate.MissingReads(p.Read))
	if b.Len() != 0 {
		t.Errorf("a grant that exists and a write grant yet to be created must print nothing; got %q", b.String())
	}

	writeMissingReadNotes(&b, gate.MissingReads([]string{present, gone}))
	out := b.String()
	if !strings.Contains(out, gone) {
		t.Errorf("the note must name the missing grant %q; got %q", gone, out)
	}
	if strings.Contains(out, present+"\"") {
		t.Errorf("the grant that exists must not be reported; got %q", out)
	}
}

// A runtime directory outside every shield leaves the same two rules and the same count
// as a healthy host, so nothing in a run's own output distinguishes it. The note is what
// run and validate say instead - including for a RELATIVE value, where there is no
// resolved path to report and the degraded branch is reached without the variable being
// unset.
func TestWriteRuntimeDirNote(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var b bytes.Buffer
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	writeRuntimeDirNote(&b)
	if b.Len() != 0 {
		t.Errorf("a shieldable runtime dir must print nothing; got %q", b.String())
	}

	t.Setenv("XDG_RUNTIME_DIR", "run/user/1000")
	writeRuntimeDirNote(&b)
	if out := b.String(); !strings.Contains(out, "run/user/1000") || !strings.Contains(out, "XDG_RUNTIME_DIR") {
		t.Errorf("a relative runtime dir must be named in the note; got %q", out)
	}

	b.Reset()
	t.Setenv("XDG_RUNTIME_DIR", "")
	writeRuntimeDirNote(&b)
	if b.Len() != 0 {
		t.Errorf("an unset runtime dir shields nothing and must say nothing; got %q", b.String())
	}
}

// The warning names each opted-in credential path loudly, and stays silent when
// the policy opted into none (the common run).
func TestWriteShieldedGrantWarning(t *testing.T) {
	var b bytes.Buffer
	writeShieldedGrantWarning(&b, enforce.Result{ShieldedGrants: []enforce.ShieldedGrant{
		{Path: "/home/u/.ssh", Holds: "credentials"},
		{Path: "/run", Holds: "services"},
	}})
	out := b.String()
	if !strings.Contains(out, "WARNING") {
		t.Errorf("the notice must be loud; got %q", out)
	}
	for _, p := range []string{"/home/u/.ssh", "/run"} {
		if !strings.Contains(out, p) {
			t.Errorf("the notice must name each opted-in path; %q missing from %q", p, out)
		}
	}
	// Each path is named by what its shield held: an operator reading this after the fact
	// must not go looking for a key behind a service socket path, or the reverse.
	for _, noun := range []string{"credential store", "service socket path"} {
		if !strings.Contains(out, noun) {
			t.Errorf("the notice must say what each shield held; %q missing from %q", noun, out)
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
		ShieldedGrants: []enforce.ShieldedGrant{
			{Path: granted, OnHost: store, Holds: "credentials"},
			{Path: "/run", Holds: "services"},
		},
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
		ShieldedGrants: []enforce.ShieldedGrant{{Path: granted, OnHost: forged, Holds: "credentials"}},
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

// Runtime drops its shield when XDG_RUNTIME_DIR names a home or an ancestor of one,
// because the rule would hide the whole grant surface. It is dropped silently and the
// remaining rule set is byte-identical to an ordinary host's, so the operator has no way
// to tell that the directory holding their agent sockets and container auth.json is
// reachable under a broad grant. It stays a report rather than a refusal because
// XDG_RUNTIME_DIR=$HOME is ordinary on a minimal container.
func TestWriteShieldAnchorsReportsAnUnshieldableRuntimeDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", home)

	var b bytes.Buffer
	writeShieldAnchors(&b)
	if out := b.String(); !strings.Contains(out, "XDG_RUNTIME_DIR") || !strings.Contains(out, strconv.Quote(home)) {
		t.Errorf("an unshieldable runtime dir must be named; got %q", out)
	}

	// A runtime dir outside every anchor is shielded normally, and saying so on every
	// ordinary host would be the noise this report exists to stay clear of. Matched on the
	// caveat itself rather than on the variable's name: the relocation section below names
	// the same variable for a different and correct reason, that the shield moved off /run.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	b.Reset()
	writeShieldAnchors(&b)
	if out := b.String(); strings.Contains(out, "no shield can follow") {
		t.Errorf("a shieldable runtime dir must not draw the unshieldable caveat; got %q", out)
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

// The auto-executing files are the surfaces bento deliberately does not shield, so the
// notice is the whole of what keeps a change to one from being silent. A path a prior run
// chose is quoted for the reason the alias and grant blocks quote theirs: a filename
// holding a newline would otherwise print as a line of its own inside the block.
func TestWriteChangedAutoExecNoticeNamesAndQuotesEachFile(t *testing.T) {
	var b bytes.Buffer
	writeChangedAutoExecNotice(&b, enforce.Result{ChangedAutoExec: []string{
		"/repo/package.json",
		"/repo/.github/workflows/ci\nfake.yml",
	}})
	for _, want := range []string{"/repo/package.json", `"/repo/.github/workflows/ci\nfake.yml"`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the notice must mention %q; got:\n%s", want, b.String())
		}
	}
	// A WARNING is for a boundary that gave way. Editing a package.json is ordinary, and
	// crying wolf over it is what makes the real warnings above stop being read.
	if strings.Contains(b.String(), "WARNING") {
		t.Errorf("changing an auto-executing file is expected work, not a warning; got:\n%s", b.String())
	}

	var empty bytes.Buffer
	writeChangedAutoExecNotice(&empty, enforce.Result{})
	if empty.Len() != 0 {
		t.Errorf("a run that changed none of them must print nothing; got %q", empty.String())
	}
}

// A redirected hook directory is not a file the run changed, and printing it as one is
// wrong in both directions: the operator reviews an untouched directory of legitimate
// hooks and finds nothing, while the fact that actually matters - the run chose where the
// host's next commit executes from - reads as routine editing. The two notices are
// separate, and the redirection's says what the run did rather than what it wrote.
func TestWriteRedirectedHooksNoticeIsNotWordedAsAChangedFile(t *testing.T) {
	res := enforce.Result{
		ChangedAutoExec: []string{"/repo/package.json"},
		RedirectedHooks: []string{"/repo/other\nhooks"},
	}
	var b bytes.Buffer
	writeChangedAutoExecNotice(&b, res)
	writeRedirectedHooksNotice(&b, res)

	if !strings.Contains(b.String(), `"/repo/other\nhooks"`) {
		t.Errorf("the redirected directory must be named and quoted; got:\n%s", b.String())
	}
	// The changed-files notice asserts the run changed what it lists, which is false of a
	// directory the run only pointed at.
	changed, _, _ := strings.Cut(b.String(), "[bento] note: the run pointed")
	if strings.Contains(changed, "other") {
		t.Errorf("the redirected directory must not appear in the changed-files notice; got:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "/repo/package.json") {
		t.Errorf("the changed file is still reported; got:\n%s", b.String())
	}

	var empty bytes.Buffer
	writeRedirectedHooksNotice(&empty, enforce.Result{ChangedAutoExec: []string{"/repo/package.json"}})
	if empty.Len() != 0 {
		t.Errorf("a run that redirected no hooks must print nothing; got %q", empty.String())
	}
}

// The degraded tier runs the same credential-alias scan and makes the same refusal as
// the full tier, so the degradation block must not claim an alias exposure the run would
// never have performed. What that tier does expose - the shields it cannot apply - is
// writeExposedWarning's to report, from a Result this function does not have.
func TestWriteDegradationsClaimsNoAliasExposure(t *testing.T) {
	var degraded enforce.Report
	degraded.Add(enforce.LayerFilesystem, enforce.Degraded, "no user namespaces")
	var b bytes.Buffer
	writeDegradations(&b, degraded)
	if strings.Contains(b.String(), "alias") {
		t.Errorf("the degraded tier scans for aliases, so the block must make no claim about them; got:\n%s", b.String())
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

	grants, err := explicitShieldGrants([]string{sshDir, filepath.Join(sshDir, "id_rsa"), home, "/srv/app"})
	if err != nil {
		t.Fatalf("explicitShieldGrants: %v", err)
	}
	got := shieldGrantPaths(grants)
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
		env  map[string]string
		res  enforce.Result
		want bool
	}{
		{"failed run, grant under home, HOME not passed", &policy.Policy{Read: []string{granted}}, nil, enforce.Result{ExitCode: 1}, true},
		{"the write grants are checked too", &policy.Policy{Write: []string{granted}}, nil, enforce.Result{ExitCode: 1}, true},
		{"HOME is passed through, so ~ lands where the author meant", &policy.Policy{Read: []string{granted}, Env: []string{"HOME"}}, map[string]string{"HOME": home}, enforce.Result{ExitCode: 1}, false},
		{"allowlisted but unset on this host, so the box got its own HOME anyway", &policy.Policy{Read: []string{granted}, Env: []string{"HOME"}}, nil, enforce.Result{ExitCode: 1}, true},
		{"the run succeeded", &policy.Policy{Read: []string{granted}}, nil, enforce.Result{ExitCode: 0}, false},
		{"no grant is under the home tree", &policy.Policy{Read: []string{"/srv/app"}}, nil, enforce.Result{ExitCode: 1}, false},
		{"a sibling of home is not under it", &policy.Policy{Read: []string{home + "-backup"}}, nil, enforce.Result{ExitCode: 1}, false},
		{"a dotted name inside home has not escaped it", &policy.Policy{Read: []string{filepath.Join(home, "..cache")}}, nil, enforce.Result{ExitCode: 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeSandboxHomeMiss(&b, tc.p, tc.env, tc.res)
			got := strings.Contains(b.String(), "HOME is not passed through")
			if got != tc.want {
				t.Errorf("note emitted = %v, want %v (output: %q)", got, tc.want, b.String())
			}
		})
	}
}

// 127 is the other half of the environment the sandbox rewrites: the shell names the
// command it could not find and never the PATH it searched, so bento supplies it. The
// gate has to reach the common shape where the manifest sets no interpreter at all and
// the shebang names it, and stay quiet where 127 means something else - another
// language's chosen exit code, or a manifest that does pass PATH through.
func TestSandboxPathMissFiresOnlyWhenRelevant(t *testing.T) {
	dir := t.TempDir()
	script := func(name, shebang string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(shebang+"\nexit 127\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	shellScript := script("run.sh", "#!/bin/sh")
	envShellScript := script("env-run", "#!/usr/bin/env bash")
	pyScript := script("run.py", "#!/usr/bin/python3")
	binary := filepath.Join(dir, "app")
	if err := os.WriteFile(binary, []byte("\x7fELF\x02\x01\x01\x00"), 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		p    *policy.Policy
		env  map[string]string
		res  enforce.Result
		want bool
	}{
		{"exit 127 under a declared shell", &policy.Policy{Interpreter: "bash"}, nil, enforce.Result{ExitCode: 127}, true},
		{"the shebang names the shell when the manifest does not", &policy.Policy{Entrypoint: shellScript}, nil, enforce.Result{ExitCode: 127}, true},
		{"a shell reached through env is still a shell", &policy.Policy{Entrypoint: envShellScript}, nil, enforce.Result{ExitCode: 127}, true},
		{"a declared interpreter wins over the shebang", &policy.Policy{Interpreter: "python3", Entrypoint: shellScript}, nil, enforce.Result{ExitCode: 127}, false},
		{"PATH is passed through, so the box searched what the caller has", &policy.Policy{Interpreter: "bash", Env: []string{"PATH"}}, map[string]string{"PATH": "/opt/tools/bin"}, enforce.Result{ExitCode: 127}, false},
		{"allowlisted but unset on this host, so the box got its own PATH anyway", &policy.Policy{Interpreter: "bash", Env: []string{"PATH"}}, nil, enforce.Result{ExitCode: 127}, true},
		{"127 from a language that chose it for something else", &policy.Policy{Entrypoint: pyScript}, nil, enforce.Result{ExitCode: 127}, false},
		{"a compiled binary has no interpreter to read 127 for", &policy.Policy{Entrypoint: binary}, nil, enforce.Result{ExitCode: 127}, false},
		{"a different failure", &policy.Policy{Interpreter: "bash"}, nil, enforce.Result{ExitCode: 1}, false},
		{"the run succeeded", &policy.Policy{Interpreter: "bash"}, nil, enforce.Result{ExitCode: 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeSandboxPathMiss(&b, tc.p, tc.env, tc.res)
			got := strings.Contains(b.String(), enforce.SandboxPath)
			if got != tc.want {
				t.Errorf("note emitted = %v, want %v (output: %q)", got, tc.want, b.String())
			}
		})
	}
}

// fakeBaseImage returns a directory the shadow predicate treats as carried into the box,
// holding cmds. The real base image is the host's own /usr and /bin - and on Ubuntu /bin
// is a symlink to /usr/bin - so what it holds is neither stable nor a test's to arrange;
// this is what lets the collision be posed hermetically. Callers must put the returned
// directory on the PATH under test, since the box's search order is read from there.
func fakeBaseImage(t *testing.T, cmds ...string) string {
	t.Helper()
	base := filepath.Join(t.TempDir(), "usr", "bin")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range cmds {
		plantCommand(t, base, c)
	}
	orig := inBaseImage
	t.Cleanup(func() { inBaseImage = orig })
	inBaseImage = func(p string) bool { return p == base || orig(p) }
	return base
}

func plantCommand(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// The shadow note's whole point is a run that exits 0 with a different binary than the
// operator's, so the gate is what it fires on rather than what exit code it saw. The
// negative half matters as much: an ordinary PATH of system directories is ungranted on
// every run and must stay silent, or the note is noise by the second day.
//
// The tempdir-backed entries below stand in for the toolchains that shadow: what the
// predicate asks is whether the box carries the directory, and nothing outside
// enforce.BaseImageDirs is carried without a grant, wherever it sits.
//
// Every entry that must fire holds a command the fake base image also holds, because the
// shadow is that collision: a directory whose commands have no counterpart in the box
// resolves to nothing rather than to a different build.
func TestSandboxPathShadowFiresOnlyWhenRelevant(t *testing.T) {
	base := fakeBaseImage(t, "tool")
	home := t.TempDir()
	t.Setenv("HOME", home)
	profile := filepath.Join(home, ".nix-profile", "bin")
	if err := os.MkdirAll(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	// The greenboard shape: the PATH entry is under home, but resolves out of it, so a
	// grant naming either spelling covers it.
	store := filepath.Join(t.TempDir(), "nix-store-bin")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(home, ".mise", "shims")
	if err := os.MkdirAll(filepath.Dir(linked), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(store, linked); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(home, ".pyenv", "versions", "3.12")
	if err := os.MkdirAll(filepath.Join(runtime, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A multi-user nix install, the shape a home-gated predicate could not see: outside
	// the caller's home and outside the base image, shadowing exactly as a home profile
	// does.
	systemWide := filepath.Join(t.TempDir(), "nix", "var", "nix", "profiles", "default", "bin")
	if err := os.MkdirAll(systemWide, 0o755); err != nil {
		t.Fatal(err)
	}
	// A toolchain of its own, sharing no command name with the box.
	unshared := filepath.Join(t.TempDir(), "snap", "bin")
	if err := os.MkdirAll(unshared, 0o755); err != nil {
		t.Fatal(err)
	}
	plantCommand(t, unshared, "snap-only")
	// A candidate whose only entry sharing a base-image name is a directory.
	dirNamed := filepath.Join(t.TempDir(), "shims")
	if err := os.MkdirAll(filepath.Join(dirNamed, "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The fake base image goes on every PATH under test: it is what the box carries, so
	// without it on the search path there is nothing for a candidate to collide with.
	withPath := func(v string) map[string]string {
		return map[string]string{"PATH": v + string(os.PathListSeparator) + base}
	}
	for _, dir := range []string{profile, store, systemWide, filepath.Join(runtime, "bin")} {
		plantCommand(t, dir, "tool")
	}

	cases := []struct {
		name string
		p    *policy.Policy
		env  map[string]string
		want bool
	}{
		// A directory of its own tools with no counterpart in the box: the run gets an
		// exit 127 rather than a different build, which is writeSandboxPathMiss's note.
		// /snap/bin on a stock Ubuntu host is exactly this, and it fired here every run.
		{"an ungranted directory whose commands the box does not have", &policy.Policy{}, withPath(unshared), false},
		// A name the candidate holds as a DIRECTORY is not a command, so it collides with
		// nothing - the box cannot execute it, and nothing resolves in its place.
		{"a subdirectory sharing a command's name is not a collision", &policy.Policy{}, withPath(dirNamed), false},
		// No base-image entry on PATH at all: the box carries nothing to resolve a bare
		// name in, so the run gets an exit 127 rather than a silently different build.
		{"nothing the box carries is on PATH, so nothing can shadow", &policy.Policy{}, map[string]string{"PATH": profile}, false},
		{"a home toolchain directory no grant covers", &policy.Policy{}, withPath(profile + ":/usr/bin"), true},
		{"system directories alone are not a shadow", &policy.Policy{}, withPath("/usr/bin:/bin:/usr/local/bin"), false},
		{"the directory itself is granted", &policy.Policy{Read: []string{profile}}, withPath(profile), false},
		{"a parent grant covers it", &policy.Policy{Read: []string{home}}, withPath(profile), false},
		{"a write grant covers it too", &policy.Policy{Write: []string{profile}}, withPath(profile), false},
		{"a sibling grant does not cover it", &policy.Policy{Read: []string{profile + "-old"}}, withPath(profile), true},
		{"granted by where the entry resolves to", &policy.Policy{Read: []string{store}}, withPath(linked), false},
		{"a symlinked entry with no grant still shadows", &policy.Policy{}, withPath(linked), true},
		{"PATH is not passed through, so the box never searched it", &policy.Policy{}, nil, false},
		{"a relative entry names no directory at all", &policy.Policy{}, withPath("bin"), false},
		{"a system-wide toolchain outside home shadows the same way", &policy.Policy{}, withPath(systemWide + ":/usr/bin"), true},
		{"a system-wide toolchain the manifest granted does not", &policy.Policy{Read: []string{systemWide}}, withPath(systemWide), false},
		// Nothing resolved from it here, so nothing resolved differently in the box, and
		// the remedy the note names would be a grant that resolves to nothing.
		{"an entry the host does not have is not a shadow", &policy.Policy{}, withPath(filepath.Join(home, "gone", "bin")), false},
		// The interpreter's install prefix is bound on the interpreter's back, with
		// nothing in read: naming it, so warning about it tells the operator to grant a
		// directory the box already resolves.
		{"the interpreter's own bin directory arrives without a grant", &policy.Policy{Interpreter: filepath.Join(runtime, "bin", "python3")}, withPath(filepath.Join(runtime, "bin")), false},
		{"a sibling of the interpreter's prefix still shadows", &policy.Policy{Interpreter: filepath.Join(runtime, "bin", "python3")}, withPath(profile), true},
		{"a system interpreter carries no prefix at all", &policy.Policy{Interpreter: "/usr/bin/python3"}, withPath(profile), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeSandboxPathShadow(&b, tc.p, tc.env)
			got := strings.Contains(b.String(), "no grant covers them")
			if got != tc.want {
				t.Errorf("note emitted = %v, want %v (output: %q)", got, tc.want, b.String())
			}
		})
	}
}

func TestToReportJSONEmptyReportIsNotACleanPosture(t *testing.T) {
	// A refusal raised before anything was probed - a malformed run id, an invalid
	// policy - carries the zero Report. Reporting it as fully enforced would claim a
	// posture the run never had.
	got := toReportJSON(enforce.Report{})
	if got.FullyEnforced {
		t.Error("a report with no layers evaluated reads as fully enforced")
	}
	if got.Layers == nil {
		t.Error("layers must serialize as [] rather than null")
	}
}

// A relocation variable accepts any absolute path, so a shield can land on something the
// run needs and the failure surfaces as an ENOENT naming only the target. The summary is
// where an operator who just hit that reads why, so it must put the variable beside the
// path - and must stay a bare count where every shield sits at its default.
func TestShieldSummaryNamesTheRelocatingVariable(t *testing.T) {
	var b bytes.Buffer
	writeShieldSummary(&b, enforce.Result{Shields: []enforce.ShieldApplied{
		{Path: "/home/u/.ssh", Kind: "hidden"},
		{Path: "/usr/bin/python3", Kind: "hidden", Source: "HISTFILE"},
	}})
	out := b.String()
	for _, want := range []string{"HISTFILE", "/usr/bin/python3"} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary must name the variable and its target; %q missing from %q", want, out)
		}
	}
	if strings.Contains(out, "/home/u/.ssh") {
		t.Errorf("a shield at its default path needs no line of its own; got %q", out)
	}

	var quiet bytes.Buffer
	writeShieldSummary(&quiet, enforce.Result{Shields: []enforce.ShieldApplied{{Path: "/home/u/.ssh", Kind: "hidden"}}})
	if strings.Contains(quiet.String(), "environment variable") {
		t.Errorf("a run with no relocated shield must stay a count; got %q", quiet.String())
	}
}

// One variable can relocate a whole group - ZDOTDIR takes the entire zsh startup set - and
// a line per path would bury every other variable under it.
func TestShieldSummaryGroupsAGroupRelocation(t *testing.T) {
	var b bytes.Buffer
	writeShieldSummary(&b, enforce.Result{Shields: []enforce.ShieldApplied{
		{Path: "/z/.zshrc", Kind: "read-only", Source: "ZDOTDIR"},
		{Path: "/z/.zshenv", Kind: "read-only", Source: "ZDOTDIR"},
		{Path: "/z/.zprofile", Kind: "read-only", Source: "ZDOTDIR"},
	}})
	out := b.String()
	if !strings.Contains(out, "3 shields under") || !strings.Contains(out, `"/z"`) {
		t.Errorf("a group relocation must collapse to its common directory; got %q", out)
	}
	if strings.Contains(out, ".zshrc") {
		t.Errorf("the group must not be listed per path; got %q", out)
	}
}

// Doctor is where an operator can see a relocation BEFORE a run breaks on it. What earns a
// line is a variable that MOVED a shield, which is why an ordinary host is silent: a
// variable at its conventional value produces the default rule, carrying no source at all.
func TestDoctorNamesRelocatingVariablesButNotTheOrdinaryOnes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// HOME moves to a temp dir, so anything inherited from the real environment - an XDG
	// base, a GOBIN a version manager exports - points outside it and reads as a
	// relocation. Clear every variable the rule set reads to get the ordinary host back,
	// rather than the handful this developer's shell happened to carry.
	for _, env := range denylist.RelocationVars() {
		t.Setenv(env, "")
	}
	// The shape that is genuinely ordinary: Runtime leaves a runtime dir under /run to the
	// /run shield and stamps no source, so it is not a relocation and must not print.
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

	var quiet bytes.Buffer
	writeRelocatedShields(&quiet)
	if quiet.Len() != 0 {
		t.Errorf("a host with no relocation must produce no lines; got %q", quiet.String())
	}

	t.Setenv("HISTFILE", "/usr/bin/python3")
	var b bytes.Buffer
	writeRelocatedShields(&b)
	out := b.String()
	for _, want := range []string{"HISTFILE", strconv.Quote("/usr/bin/python3")} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor must name the variable and its target; %q missing from %q", want, out)
		}
	}
}

// A runtime dir parked outside /run - a session manager, a container - IS a relocation:
// the socket shield follows the variable there, so a value pointing at something the run
// needs blanks it. Doctor said nothing about that case while the run summary reported it,
// which left the two surfaces disagreeing about what counts as relocated.
func TestDoctorNamesARelocatedRuntimeDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ZDOTDIR", "")
	runtime := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtime)

	var b bytes.Buffer
	writeRelocatedShields(&b)
	out := b.String()
	if !strings.Contains(out, "XDG_RUNTIME_DIR") || !strings.Contains(out, strconv.Quote(runtime)) {
		t.Errorf("a runtime dir moved off /run must be named; got %q", out)
	}
}

// $HOME inside the passwd home, with the inner one a credential store, is shielded whole
// on purpose - the alternative unshields the credentials the rule exists to hide. What is
// missing without this is any way for the operator to tell an empty tmpfs from a bug, and
// only the anchor relationship explains it.
func TestDoctorNamesAnAnchorInsideAnotherAnchor(t *testing.T) {
	var b bytes.Buffer
	writeNestedAnchors(&b, []string{"/home/u/.aws", "/home/u"})
	out := b.String()
	for _, want := range []string{strconv.Quote("/home/u/.aws"), strconv.Quote("/home/u"), "tmpfs"} {
		if !strings.Contains(out, want) {
			t.Errorf("the nesting must be named with its consequence; %q missing from %q", want, out)
		}
	}

	// The ordinary shape - two unrelated anchors, or one - explains nothing and must not
	// print, or every host with a $HOME that disagrees with passwd carries this paragraph.
	for _, anchors := range [][]string{{"/home/u"}, {"/home/u", "/var/home/u"}} {
		var quiet bytes.Buffer
		writeNestedAnchors(&quiet, anchors)
		if quiet.Len() != 0 {
			t.Errorf("anchors %v are not nested and must produce no lines; got %q", anchors, quiet.String())
		}
	}
}

// The five states an exec record comes back in. Four of them are a record that is absent
// or partial, and each has to be distinguishable from the others: a reader who cannot
// tell "nothing was watching" from "nothing ran" learns the wrong thing about their run,
// and one who cannot tell a truncated record from a whole one believes a list that stops
// early.
func TestWriteExecRecordSeparatesItsFiveStates(t *testing.T) {
	render := func(rec *enforce.ExecRecord) string {
		var b bytes.Buffer
		writeExecRecord(&b, enforce.Result{ExecRecord: rec})
		return b.String()
	}

	// A run that did not ask is byte-for-byte the run it would otherwise be, output
	// included.
	if got := render(nil); got != "" {
		t.Errorf("a run that asked for no record must print nothing; got %q", got)
	}

	// The reason is the whole value of an unwatched record: it is what says whether to
	// drop --allow-degraded, change the manifest's exec mode, or lower yama's
	// ptrace_scope.
	unwatched := render(&enforce.ExecRecord{Reason: "yama ptrace_scope refused the attach"})
	if !strings.Contains(unwatched, "yama ptrace_scope refused the attach") {
		t.Errorf("an unwatched record must name why; got:\n%s", unwatched)
	}

	// The launcher seeds the target before the run starts, so a lone entry is a run that
	// spawned nothing - not an empty record - and it must not be counted among what the
	// run executed. Asserting on the target's own line as well, because a branch that
	// collapsed into silence would pass a check that only forbids wording.
	lone := render(&enforce.ExecRecord{Watched: true, Complete: true, Runs: []enforce.ExecRun{
		{Exe: "/bin/sh", Argv: []string{"sh", "./s.sh"}},
	}})
	if !strings.Contains(lone, "nothing beyond the target") || !strings.Contains(lone, `"/bin/sh"`) {
		t.Errorf("a run that spawned nothing must say so and still show the target; got:\n%s", lone)
	}

	// A record that lost even the seeded target entry is damaged, and the one thing it
	// must not do is read as the healthy run above.
	empty := render(&enforce.ExecRecord{Watched: true, Complete: true})
	if strings.Contains(empty, "nothing was watching") || strings.Contains(empty, "nothing beyond the target") {
		t.Errorf("a record missing even the target's entry is neither unwatched nor a clean run; got:\n%s", empty)
	}
	if empty == "" {
		t.Errorf("a damaged record must not print nothing, which is how a run that asked for none prints")
	}

	full := render(&enforce.ExecRecord{Watched: true, Complete: true, Runs: []enforce.ExecRun{
		{Exe: "/usr/bin/cc", Argv: []string{"cc", "-o", "a\nb"}, ArgvTruncated: true},
	}})
	// Argv is the target's own bytes, so an argument holding a newline must not become a
	// line of its own inside the block.
	if !strings.Contains(full, `"a\nb"`) {
		t.Errorf("the record must quote what the target ran; got:\n%s", full)
	}
	if !strings.Contains(full, "cut") {
		t.Errorf("a capped argv must say so, or the record lies about what ran; got:\n%s", full)
	}

	partial := render(&enforce.ExecRecord{Watched: true, Runs: []enforce.ExecRun{{Exe: "/bin/sh"}}})
	if !strings.Contains(partial, "ends") {
		t.Errorf("a record that never reached its end marker must say so; got:\n%s", partial)
	}
	if strings.Contains(full, "ends where it") {
		t.Errorf("a complete record must not claim it was cut short; got:\n%s", full)
	}
}

// A host whose $HOME cannot be resolved gets nil grants from resolvedGrants, and
// writePolicySummary prints the literal grants anyway - so this is asked for a host
// answer it does not have, over a manifest that does have grants.
func TestGrantTargetsWithoutAHostAnswer(t *testing.T) {
	if got := toGrantTargetsJSON([]string{"~/src", "/data"}, nil); got != nil {
		t.Errorf("no resolution for this host must yield no targets; got %v", got)
	}
}

// The memo is a cache over a DISK walk, so its lifetime is the whole of its correctness:
// it is honest for one render pass over one manifest and no longer, which is why profile's
// convergence loop drops it after each round has executed the target. Nothing exercised
// that, and a memo that never re-walks passes every test that only asks it twice.
//
// The mutation is a symlink inside a credential store pointing at a dotfile farm in the
// same home, which is what stow, chezmoi and home-manager leave: shield.Set expands it to
// a second rule at the target's own path. It moves the set with the environment untouched,
// which is the case that matters - the memo keys on the environment, so a test that
// relocated HOME between the two asks would re-walk for that reason and prove nothing.
func TestShieldSetMemoIsDroppedForTheNextRound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, d := range []string{".ssh", "farm"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "farm", "id_ed25519"), []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidateShieldSet()
	t.Cleanup(invalidateShieldSet)

	// Counted under the temp home alone. HomeAnchors also returns the passwd home, whose
	// stores are walked on every ask too - and this is a shared checkout, so a sibling
	// dropping a link into one of them between the two asks would move a whole-set count
	// for a reason that has nothing to do with the memo.
	underHome := func(set shield.Set) int {
		n := 0
		for _, r := range set.Rules() {
			if strings.HasPrefix(r.Path, home+string(filepath.Separator)) {
				n++
			}
		}
		return n
	}

	before, err := commandShieldSet()
	if err != nil {
		t.Fatal(err)
	}

	// A dotfile manager linking the key into its farm: the store's entry is a symlink, and
	// the target is shielded at its own path too or the store is reachable by naming where
	// it points.
	if err := os.Symlink(filepath.Join(home, "farm", "id_ed25519"), filepath.Join(home, ".ssh", "id_ed25519")); err != nil {
		t.Fatal(err)
	}

	if held, err := commandShieldSet(); err != nil {
		t.Fatal(err)
	} else if underHome(held) != underHome(before) {
		t.Fatalf("the memo must serve the same set within one render pass; %d rules became %d",
			underHome(before), underHome(held))
	}

	invalidateShieldSet()
	fresh, err := commandShieldSet()
	if err != nil {
		t.Fatal(err)
	}
	if underHome(fresh) != underHome(before)+1 {
		t.Errorf("a dropped memo must walk the stores again: %d rules before the link, %d after dropping it, want %d",
			underHome(before), underHome(fresh), underHome(before)+1)
	}
}

// The held flag, which is why the memo is not keyed on the environment alone: an empty
// environment is a legitimate key, and a cache comparing keys would hand a run in one back
// the zero Set forever - no rules, so no grant refused and no credential shielded.
func TestShieldSetMemoWalksForAnEmptyEnvironment(t *testing.T) {
	// The collision said directly, since an empty os.Environ() cannot be arranged from
	// inside a test: nothing is held, and the key the next ask computes is the one already
	// stored. A cache comparing keys alone answers that from an empty set.
	invalidateShieldSet()
	shieldSetCache.Lock()
	shieldSetCache.key = strings.Join(os.Environ(), "\x00")
	shieldSetCache.set = shield.Set{}
	shieldSetCache.Unlock()

	set, err := commandShieldSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Rules()) == 0 {
		t.Error("an ask that matches the zero key must still walk; a set with no rules shields nothing")
	}
	t.Cleanup(invalidateShieldSet)
}
