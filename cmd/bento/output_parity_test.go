package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// parityRow is one cell of docs/state-grid-output-parity.md: a fact a human writer prints,
// and either the --json key that carries the same fact or the reason it has none. A keyed
// row asserts both halves against one fixture rendered both ways, so a row whose writer
// stopped printing fails as loudly as one whose field stopped being filled.
type parityRow struct {
	writers []string
	fixture string
	marker  string
	key     string
	exempt  string
}

var parityRows = []parityRow{
	// run: the verdict event.
	{writers: []string{"writeShieldSummary"}, fixture: "verdict", marker: "sandbox engaged", key: "shields"},
	{writers: []string{"writeShieldSummary"}, fixture: "verdict", marker: "NOT shielded in this run", key: "unshieldable_relocations"},
	{writers: []string{"writeShieldedGrantWarning"}, fixture: "verdict", marker: "explicitly grants these paths", key: "shielded_grants"},
	{writers: []string{"writeAcceptedAliasWarning"}, fixture: "verdict", marker: "you acknowledged the tree", key: "accepted_aliases"},
	{writers: []string{"writeExposedWarning"}, fixture: "verdict", marker: "were left exposed", key: "exposed"},
	{writers: []string{"writeSandboxPathShadow"}, fixture: "verdict", marker: "the box does not carry", key: "shadowed_path_dirs"},
	{writers: []string{"writeDegradations"}, fixture: "verdict", marker: "does not enforce everything", key: "report.layers"},
	{writers: []string{"writeChangedAutoExecNotice"}, fixture: "verdict", marker: "the run changed these files", key: "changed_auto_exec"},
	{writers: []string{"writeRedirectedHooksNotice"}, fixture: "verdict", marker: "pointed this checkout's hooks", key: "redirected_hooks"},
	{writers: []string{"writeRedirectedHooksNotice"}, fixture: "verdict", marker: "could not read these grants whole", key: "unresolved_hooks"},
	{writers: []string{"writeGuardBlockedWarning"}, fixture: "verdict", marker: "egress guard refused to connect", key: "guard_blocked"},
	{writers: []string{"writeDeniedWarning"}, fixture: "verdict", marker: "egress allowlist refused", key: "egress_denied"},
	{writers: []string{"writeGateDeniedWarning"}, fixture: "verdict", marker: "network gate was asked", key: "gate_denied"},
	{writers: []string{"writeUntunneledWarning"}, fixture: "verdict", marker: "addressed without a CONNECT", key: "untunneled"},
	{writers: []string{"writeSignalNotice"}, fixture: "verdict", marker: "killed by signal", key: "signal"},
	{writers: []string{"writeExecRecord"}, fixture: "verdict", marker: "executed nothing beyond the target", key: "exec_record"},
	{writers: []string{"writeTargetUnreached"}, fixture: "unreached", marker: "never ran", key: "target_never_ran"},
	{writers: []string{"writeRefusal"}, fixture: "refusal", marker: "refusing to run", key: "reason"},
	{writers: []string{"writeLimitsRemedy"}, fixture: "refusal", marker: "pass --allow-degraded", key: "allow_degraded_would_admit"},
	{writers: []string{"writeSignalNotice"}, exempt: "R16: the hedged 128+n reading is withheld from signal on purpose; see the Signal field in writeRunResult"},
	{writers: []string{"writeEgressHint", "writeExecHint", "writeProfileHint", "writeSandboxHomeMiss", "writeSandboxPathMiss", "writeDenialLegend"},
		exempt: "R17/R18: remedies computed from exit_code, the policy and fields the verdict already carries"},
	{writers: []string{"writeFileishWriteNotes"}, exempt: "R26: stderr only on purpose; see writeFileishWriteNotes"},
	// The pre-run notes are written and their runNotesJSON fields filled side by side in
	// newRunCmd's RunE, which needs a backend before it reaches writeRunResult.
	{writers: []string{"writeMissingReadNotes", "writeBlockedHostNotes", "writeRuntimeDirNote"},
		exempt: "run pre-run notes: filled beside the write in newRunCmd, carried by runNotesJSON"},

	// validate.
	{writers: []string{"writePolicySummary"}, fixture: "validate", marker: "entrypoint:", key: "entrypoint"},
	{writers: []string{"writePolicySummary"}, fixture: "validate", marker: "bento shields on every run", key: "shielded_grants"},
	{writers: []string{"writePolicySummary"}, fixture: "validate", marker: "egress guard refused it", key: "network_blocked"},
	{writers: []string{"writePolicySummary"}, fixture: "validate", marker: "it was\n        hand-edited", key: "network_blocked_unreadable"},
	{writers: []string{"writePolicySummary"}, fixture: "validate", marker: "is a loopback address", key: "loopback_network_rules"},
	{writers: []string{"writePolicySummary"}, exempt: "V13: the exec notes are static text keyed on exec"},
	{writers: []string{"writeResolvedInterpreter"}, fixture: "validate", marker: "fakepython\"", key: "interpreter_on_host"},
	{writers: []string{"writeResolvedGrants"}, fixture: "validate", marker: "on this host:", key: "resolved_read"},
	{writers: []string{"writeBroadGrantNotes"}, fixture: "validate", marker: "is a whole home or top-level directory", key: "broad_read_grants"},
	{writers: []string{"writeGrantRefusals"}, fixture: "validate", marker: "REFUSED:", key: "refused_grants"},
	{writers: []string{"writeSandboxHome", "writeSandboxHomeNote"}, fixture: "validate", marker: "HOME is not passed through", key: "home_not_passed_through"},
	{writers: []string{"writeUnsetEnvNotes"}, fixture: "validate", marker: "BENTO_PARITY_UNSET is allowed by the manifest but not set", key: "unset_env"},
	// Field by field in TestEveryRunnabilityFieldReachesTheUser; these rows pin the command wiring.
	{writers: []string{"writeRunnability"}, fixture: "validate", marker: "runnable:", key: "runnable"},
	{writers: []string{"writeRunnability"}, fixture: "validate", marker: "names nothing on this host", key: "missing_read_grants"},
	{writers: []string{"writeRunnability"}, fixture: "validate", marker: "spelled like a file", key: "fileish_write_grants"},
	{writers: []string{"writeRunnability"}, fixture: "validate", marker: "XDG_RUNTIME_DIR is", key: "unshieldable_runtime_dir"},
	{writers: []string{"writeRelocatable"}, fixture: "validate", marker: "relocatable:  NO", key: "pinned_paths"},
	{writers: []string{"writeApprovalLine"}, fixture: "validate", marker: "approval:", key: "approval"},

	// doctor.
	{writers: []string{"writePlatform"}, fixture: "doctor", marker: "Platform:", key: "platform"},
	{writers: []string{"writeReportTable"}, fixture: "doctor", marker: "LAYER", key: "layers"},
	{writers: []string{"writeShieldAnchors"}, fixture: "doctor", marker: "Credential shields anchor on", key: "shield_anchor_homes"},
	{writers: []string{"writeShieldAnchors"}, fixture: "doctor", marker: "XDG_RUNTIME_DIR is", key: "unshieldable_runtime_dir"},
	{writers: []string{"writeShieldAnchors"}, exempt: "D8: no_usable_passwd_home needs a uid with no passwd home, which a test cannot construct"},
	{writers: []string{"writeNSSCaveat"}, fixture: "doctor", marker: "Built against libc NSS", key: "libc_nss_passwd_lookup"},
	{writers: []string{"writeDroppedRelocations"}, fixture: "doctor", marker: "move a store where the shields cannot reach", key: "unshieldable_relocations"},
	{writers: []string{"writeDegradedSummary"}, exempt: "D6: the refused/reported/host-only split is decided by layers[] tier and layer"},
	{writers: []string{"writeNestedAnchors"}, fixture: "doctor-relocated", marker: "sits inside", key: "nested_anchors"},
	{writers: []string{"writeRelocatedShields"}, fixture: "doctor-relocated", marker: "move a shield off its default path", key: "relocated_shields"},

	// profile.
	{writers: []string{"writeMergeNotice"}, fixture: "profile", marker: "kept from the existing manifest", key: "merged"},

	// approve has no --json: its callouts are validate's (Grid A), and the rest is the
	// interactive review that ends in a stamp.
	{writers: []string{"writeApprovalCallouts"}, exempt: "Grid A: approve has no --json; validate calls the same writer, and its --json carries each callout (unresolvable grants as an absent resolved_read)"},
	{writers: []string{"writeReapprovalNotice", "writeJournalDiff"}, exempt: "approve has no --json; validate --json carries the approval state and approval_note, but not the changed-field diff, which only this host's journal can produce"},

	// Trust warnings, shared across frontends.
	{writers: []string{"warnUntrusted"}, exempt: "run carries it as stamp_at_risk; approve has no --json; profile --json lacks it (bv2-uzlc2)"},
	{writers: []string{"warnStampAtRisk"}, exempt: "validate --json lacks it (bv2-ati60)"},

	{writers: []string{"writeJSON"}, exempt: "the encoder every --json path writes through, not a human writer"},
	{writers: []string{"writeRunResult"}, exempt: "the dispatcher that picks the human or --json rendering; its writers have rows of their own"},
	{writers: []string{"writeManifestAtomically", "writeApprovalRecord", "writeJournalEntry"}, exempt: "write files, not human output; their failures reach the user as errors"},
	{writers: []string{"writeUsageHint"}, exempt: "the hint under a command-line mistake, which the error above it already names"},
}

func TestEveryHumanFactReachesJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, env := range denylist.RelocationVars() {
		t.Setenv(env, "")
		os.Unsetenv(env)
	}
	t.Setenv("GNUPGHOME", home)
	t.Setenv("XDG_RUNTIME_DIR", "run/user/1000")
	pureLookup(t, false)

	fixtures := map[string]func(t *testing.T) (string, map[string]any){
		"verdict":   parityRunVerdict,
		"unreached": parityRunUnreached,
		"refusal":   parityRunRefusal,
		"validate":  parityValidate,
		"doctor":    parityDoctor,
		// Its HISTFILE stays set for the fixtures rendered after it; none of them reads it.
		"doctor-relocated": parityDoctorRelocated,
		"profile":          parityProfile,
	}
	type rendered struct {
		human   string
		machine map[string]any
	}
	cache := map[string]rendered{}
	for _, row := range parityRows {
		if row.exempt != "" {
			continue
		}
		r, ok := cache[row.fixture]
		if !ok {
			r.human, r.machine = fixtures[row.fixture](t)
			cache[row.fixture] = r
		}
		if !strings.Contains(r.human, row.marker) {
			t.Errorf("%v (%s): the human output no longer says %q, so this row guards nothing; fix the fixture or the row.\ngot:\n%s",
				row.writers, row.fixture, row.marker, r.human)
		}
		// Dotted keys reach inside an object whose own key is never empty, as the run
		// report's is, so the row checks the field that carries the fact.
		var v any = r.machine
		for _, part := range strings.Split(row.key, ".") {
			m, _ := v.(map[string]any)
			v = m[part]
		}
		if isZeroJSON(v) {
			t.Errorf("%v (%s): the human output says %q but --json carries no %q.\ngot: %v",
				row.writers, row.fixture, row.marker, row.key, r.machine)
		}
	}
}

// A human writer added with no parity decision is the gap this table exists to close, so
// the table has to know every writer by name.
func TestEveryHumanWriterHasAParityRow(t *testing.T) {
	for _, name := range unrowedWriters(t, ".") {
		t.Errorf("%s writes human output and has no row in parityRows: name the --json key that carries "+
			"its fact, or the reason it has none", name)
	}
}

// unrowedWriters names every write* or warn* function in dir's non-test files that no
// row names. The whole package rather than a list of files, because a list is a second
// place a new file has to be remembered, and the writer it forgets is the one it passes.
func unrowedWriters(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	rowed := map[string]bool{}
	for _, row := range parityRows {
		for _, w := range row.writers {
			rowed[w] = true
		}
	}
	var missing []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || rowed[fn.Name.Name] {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "write") || strings.HasPrefix(fn.Name.Name, "warn") {
				missing = append(missing, fn.Name.Name)
			}
		}
	}
	return missing
}

// The guard above is only as good as its file walk: a writer it cannot see is a writer
// it passes.
func TestUnrowedWritersSeesANewWriter(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"new.go":      "package main\n\nimport \"io\"\n\nfunc writeUnrowedFact(w io.Writer) {}\n\nfunc writeShieldSummary(w io.Writer) {}\n",
		"warn.go":     "package main\n\nimport \"io\"\n\nfunc warnUnrowedFact(w io.Writer) {}\n",
		"new_test.go": "package main\n\nimport \"io\"\n\nfunc writeTestHelper(w io.Writer) {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := unrowedWriters(t, dir)
	if !slices.Equal(got, []string{"writeUnrowedFact", "warnUnrowedFact"}) {
		t.Errorf("unrowedWriters = %v, want the write* and warn* writers with no row from every non-test file", got)
	}
}

func isZeroJSON(v any) bool {
	switch v := v.(type) {
	case nil:
		return true
	case bool:
		return !v
	case string:
		return v == ""
	case float64:
		return v == 0
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	}
	return false
}

func renderRun(t *testing.T, p *policy.Policy, env map[string]string, res enforce.Result, runErr error) (string, map[string]any) {
	t.Helper()
	var human bytes.Buffer
	_ = writeRunResult(&human, false, p, env, res, nil, nil, runErr)
	var stdout, stderr bytes.Buffer
	_ = writeRunResult(&stderr, true, p, env, res, nil, newEventStream(&stdout), runErr)
	var machine map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &machine); err != nil {
		t.Fatalf("run --json is not one JSON object (%v):\n%s", err, stdout.String())
	}
	return human.String(), machine
}

func parityRunVerdict(t *testing.T) (string, map[string]any) {
	base := fakeBaseImage(t, "tool")
	toolchain := t.TempDir()
	plantCommand(t, toolchain, "tool")
	env := map[string]string{"PATH": toolchain + string(os.PathListSeparator) + base}

	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	report.Add(enforce.LayerExecStrict, enforce.Degraded, "no seccomp here")
	hp := []enforce.HostPort{{Host: "example.com", Port: "443"}}
	res := enforce.Result{
		ExitCode: 137, Signal: 9, Report: report, EgressConnections: 1,
		Shields:         []enforce.ShieldApplied{{Path: "/home/u/.aws", Kind: "hidden"}},
		Exposed:         []enforce.ShieldApplied{{Path: "/home/u/.ssh", Kind: "hidden"}},
		ShieldedGrants:  []enforce.ShieldedGrant{{Path: "/home/u/.ssh", Holds: "credentials"}},
		AcceptedAliases: []enforce.CredentialAlias{{Path: "/backup/id_rsa", Credential: "/home/u/.ssh/id_rsa"}},
		ChangedAutoExec: []string{"/work/package.json"},
		RedirectedHooks: []string{"/work/hooks"},
		UnresolvedHooks: []string{"/work/other"},
		GuardBlocked:    hp, Denied: hp, GateDenied: hp, Untunneled: hp,
		ExecRecord: &enforce.ExecRecord{Watched: true, Complete: true, Runs: []enforce.ExecRun{{Pid: 1, Exe: "/x", Argv: []string{"x"}}}},
	}
	return renderRun(t, validPolicy(), env, res, nil)
}

func parityRunUnreached(t *testing.T) (string, map[string]any) {
	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	return renderRun(t, validPolicy(), nil, enforce.Result{ExitCode: 127, Setup: enforce.SetupTargetUnreached, Report: report}, nil)
}

func parityRunRefusal(t *testing.T) (string, map[string]any) {
	short := []enforce.LayerStatus{{Layer: enforce.LayerLimitsMemory, State: enforce.Unavailable, Reason: "no cgroup"}}
	refusal := &enforce.Refusal{Reason: "a limit cannot be applied", Short: short, Waivable: true}
	return renderRun(t, validPolicy(), nil, enforce.Result{}, refusal)
}

func parityValidate(t *testing.T) (string, map[string]any) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "fakepython"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	p := &policy.Policy{
		Entrypoint:  "./x",
		Interpreter: "fakepython",
		Read:        []string{"~/.ssh", "~", "/data/bento-parity-absent"},
		Write:       []string{"out/report.json", "/"},
		Env:         []string{"BENTO_PARITY_UNSET"},
		Network:     []policy.NetworkRule{{Host: "127.0.0.1", Port: "8080"}, {Host: ".internal", Port: "80"}},
	}
	path := writeManifest(t, p, manifest.Provenance{BlockedHosts: []string{"metadata.internal:80", "not-a-host-port"}})

	human, _ := runCapturingStdout(t, newValidateCmd(), "--relocatable", path)
	out, _ := runCapturingStdout(t, newValidateCmd(), "--json", "--relocatable", path)
	var machine map[string]any
	if err := json.Unmarshal([]byte(out), &machine); err != nil {
		t.Fatalf("validate --json is not JSON (%v):\n%s", err, out)
	}
	return human, machine
}

// parityDoctorRelocated is the host the ordinary doctor fixture cannot be: a $HOME inside
// the passwd home, which the test cannot arrange, is passed as anchors directly, and a
// variable moves a shield somewhere no home contains.
func parityDoctorRelocated(t *testing.T) (string, map[string]any) {
	t.Setenv("HISTFILE", "/usr/bin/python3")
	anchors := []string{"/home/u/.aws", "/home/u"}
	var human bytes.Buffer
	writeNestedAnchors(&human, anchors)
	writeRelocatedShields(&human)
	encoded, err := json.Marshal(toDoctorJSON(enforce.Report{}, anchors, nil))
	if err != nil {
		t.Fatal(err)
	}
	var machine map[string]any
	if err := json.Unmarshal(encoded, &machine); err != nil {
		t.Fatal(err)
	}
	return human.String(), machine
}

func parityProfile(t *testing.T) (string, map[string]any) {
	p := &policy.Policy{Entrypoint: "main.py", Exec: "none", Read: []string{"./old"}}
	merge := mergeOutcome{widened: true, keptRead: []string{"./old"}, policy: p}
	var human bytes.Buffer
	writeMergeNotice(&human, "m.yaml", merge)
	encoded, err := json.Marshal(profileResultJSON("m.yaml", p, p, manifest.Provenance{}, roundStatus{}, merge, ""))
	if err != nil {
		t.Fatal(err)
	}
	var machine map[string]any
	if err := json.Unmarshal(encoded, &machine); err != nil {
		t.Fatal(err)
	}
	return human.String(), machine
}

func parityDoctor(t *testing.T) (string, map[string]any) {
	anchors, err := denylist.HomeAnchors()
	if err != nil {
		t.Fatal(err)
	}
	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	var human bytes.Buffer
	writePlatform(&human)
	writeReportTable(&human, report)
	writeShieldAnchors(&human)
	encoded, err := json.Marshal(toDoctorJSON(report, anchors, nil))
	if err != nil {
		t.Fatal(err)
	}
	var machine map[string]any
	if err := json.Unmarshal(encoded, &machine); err != nil {
		t.Fatal(err)
	}
	return human.String(), machine
}
