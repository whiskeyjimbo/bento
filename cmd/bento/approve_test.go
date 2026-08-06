package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

func doc(approves string) *manifest.Document {
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	return &manifest.Document{Policy: p, Provenance: manifest.Provenance{Approves: approves}}
}

func TestCheckApproval(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	cases := map[string]struct {
		approves string
		want     approvalState
	}{
		"no approval":   {"", approvalUnstamped},
		"matching":      {p.Fingerprint(), approvalCurrent},
		"changed since": {"a-stale-fingerprint", approvalStale},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := checkApproval(doc(tc.approves)); got != tc.want {
				t.Errorf("checkApproval = %v, want %v", got, tc.want)
			}
		})
	}
}

// run refuses a manifest whose approval is not current by default, so a manifest
// edited after approval (drift) is caught at run time, not only by validate;
// --allow-unapproved opts out.
func TestRequireApproval(t *testing.T) {
	current := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	approved := &manifest.Document{Policy: current, Provenance: manifest.Provenance{Approves: current.Fingerprint()}}

	if err := requireApproval(approved, false); err != nil {
		t.Errorf("a current approval must run; got %v", err)
	}
	for name, d := range map[string]*manifest.Document{"stale": doc("old"), "unstamped": doc("")} {
		if err := requireApproval(d, false); err == nil {
			t.Errorf("%s approval must be refused without --allow-unapproved", name)
		}
		if err := requireApproval(d, true); err != nil {
			t.Errorf("%s approval must run under --allow-unapproved; got %v", name, err)
		}
	}
}

// The approval binding depends on the fingerprint being checked on the manifest AS
// WRITTEN, before manifest.Resolve rewrites its relative paths to absolute. This
// pins that ordering: resolution changes the fingerprint, so a check run after it
// would reject a validly-approved manifest - and a fingerprint stamped post-resolution
// would shift with the invocation directory. run.go checks approval first for exactly
// this reason.
func TestApprovalCheckedBeforePathResolution(t *testing.T) {
	p := &policy.Policy{Entrypoint: "run.py", Read: []string{"data"}} // relative on purpose
	stamped := p.Fingerprint()
	doc := &manifest.Document{Policy: p, Provenance: manifest.Provenance{Approves: stamped}}

	if got := checkApproval(doc); got != approvalCurrent {
		t.Fatalf("as-written approval = %v, want current", got)
	}
	if err := manifest.Resolve(p, "/work/proj/manifest.yaml"); err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint() == stamped {
		t.Fatal("manifest.Resolve must change the fingerprint, else the check ordering would not matter")
	}
	if got := checkApproval(doc); got != approvalStale {
		t.Fatalf("post-resolution approval = %v, want stale (so the check must precede resolution)", got)
	}
}

// --strict must fail on a stale or missing approval and pass on a current one;
// without --strict, none of them fail.
func TestReportApprovalStrictness(t *testing.T) {
	current := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}

	cases := map[string]struct {
		doc        *manifest.Document
		strictFail bool
	}{
		"stale":     {doc("old"), true},
		"unstamped": {doc(""), true},
		"current":   {&manifest.Document{Policy: current, Provenance: manifest.Provenance{Approves: current.Fingerprint()}}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := reportApproval(io.Discard, tc.doc, false); err != nil {
				t.Errorf("non-strict must never fail; got %v", err)
			}
			err := reportApproval(io.Discard, tc.doc, true)
			if tc.strictFail && err == nil {
				t.Error("--strict should have failed")
			}
			if !tc.strictFail && err != nil {
				t.Errorf("--strict should have passed; got %v", err)
			}
		})
	}
}

// approve rewrites the manifest others read, so a world-writable one gives away the
// only thing the stamp is worth: that the permissions cannot change without the
// approval going stale. It is written back with the shared write bits removed.
func TestApproveDropsSharedWriteBits(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0o022 != 0 {
		t.Errorf("mode = %#o, want the group/world write bits cleared", got)
	}
}

// A manifest kept in a dotfiles repo and symlinked into place is ordinary. Renaming
// onto the link would replace it with a regular file and detach it from its source, so
// approve writes at the resolved location and the link survives.
func TestApproveWritesThroughASymlink(t *testing.T) {
	target := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := runCapturingStdout(t, newApproveCmd(), link, "--yes"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink must survive approve; lstat = %v, %v", fi, err)
	}
	doc, _, err := loadDocument(target)
	if err != nil {
		t.Fatal(err)
	}
	if checkApproval(doc) != approvalCurrent {
		t.Error("the stamp must land on the link's target, not on a file replacing the link")
	}
}

// The location approve writes at is the one its trust check inspected, so repointing the
// symlink after the check cannot redirect the stamp. Standing in for the race: whoever can
// replace the link gets to do it at a moment of their choosing, and this is that moment.
func TestWriteManifestAtomicallyIgnoresARepointedSymlink(t *testing.T) {
	target := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	trust := trustOf(t, link)

	elsewhere := writeManifest(t, &policy.Policy{Entrypoint: "./elsewhere"}, manifest.Provenance{})
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	if err := writeManifestAtomically(trust, []byte("entrypoint: ./y\n"), io.Discard); err != nil {
		t.Fatalf("writeManifestAtomically: %v", err)
	}

	if data, err := os.ReadFile(target); err != nil || string(data) != "entrypoint: ./y\n" {
		t.Errorf("the inspected target must get the write; got %q, %v", data, err)
	}
	if data, err := os.ReadFile(elsewhere); err != nil || string(data) == "entrypoint: ./y\n" {
		t.Errorf("the repointed target must not be written; got %q, %v", data, err)
	}
}

// A manifest unlinked or renamed over between the open and the readlink leaves the kernel
// naming something the facts do not describe - "/w/m.yaml (deleted)". Concluding a location
// from that would send a rewrite somewhere unexamined, and the refusal has to say so in
// those terms rather than surfacing a stat error about a path the user never named.
func TestInspectManifestRefusesAManifestUnlinkedWhileOpen(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"unlinked": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
		"renamed over": func(t *testing.T, path string) {
			other := filepath.Join(filepath.Dir(path), "other.yaml")
			if err := os.WriteFile(other, []byte("entrypoint: ./y\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(other, path); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, disturb := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			disturb(t, path)

			_, err = inspectManifest(f, path)
			if err == nil {
				t.Fatal("a manifest with no location left to judge must fail")
			}
			if !strings.Contains(err.Error(), "moved while it was being read") {
				t.Errorf("the refusal must say the manifest moved; got %v", err)
			}
			if strings.Contains(err.Error(), "(deleted)") {
				t.Errorf("the refusal must not name the kernel's placeholder path; got %v", err)
			}
		})
	}
}

// A failed write must not leave a truncated manifest where a complete one was: the
// replacement goes through a temporary file and a rename, so the manifest is only ever
// the old bytes or the new ones - and no temp file is left behind.
func TestWriteManifestAtomicallyLeavesNoTempFiles(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	dir := filepath.Dir(path)
	if err := writeManifestAtomically(trustOf(t, path), []byte("entrypoint: ./y\n"), io.Discard); err != nil {
		t.Fatalf("writeManifestAtomically: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".bento-") {
			t.Errorf("left a temporary file behind: %s", e.Name())
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "entrypoint: ./y\n" {
		t.Errorf("manifest = %q, want the new bytes", data)
	}
}

// A stamp is current as long as the policy has not changed, and the mode is no part of
// the fingerprint - so chmod after an approve leaves the stamp reading as current over
// permissions nobody attested. Reporting that as already approved would vouch for what
// it never checked, so the clamp runs regardless of the stamp.
func TestApproveClampsAnAlreadyApprovedManifest(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	out, err := runCapturingStdout(t, newApproveCmd(), path, "--yes")
	if err != nil {
		t.Fatalf("second approve: %v", err)
	}
	// The clamp is the one way an unchanged policy reaches the review block twice, so it is
	// also the one way the drift notice can fire over permissions that never moved.
	if strings.Contains(out, "permissions have changed") {
		t.Errorf("the policy is the one that was stamped; only the mode moved:\n%s", out)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0o022 != 0 {
		t.Errorf("mode = %#o, want the group/world write bits cleared", got)
	}
}

// Profiling proposes what one run did rather than what a script should be allowed to do,
// and the four-step workflow makes typing the fourth command the path of least
// resistance. Approve has to show the entries it is about to hand over - each of these is
// something profiling proposes unprompted.
func TestApprovalCalloutsNameWhatDeservesReview(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "tool.py.manifest.yaml")

	callouts := func(p *policy.Policy) string {
		t.Helper()
		var buf strings.Builder
		writeApprovalCallouts(&buf, manifestPath, p, resolvedGrants(p, manifestPath), nil)
		return buf.String()
	}

	// A write over the directory holding the manifest is what profiling proposes for a
	// script that wrote anything beside itself.
	got := callouts(&policy.Policy{Entrypoint: "./tool.py", Write: []string{dir}, Exec: policy.ExecAll})
	for _, want := range []string{"covers the manifest itself", "exec: all"} {
		if !strings.Contains(got, want) {
			t.Errorf("callouts missing %q; got:\n%s", want, got)
		}
	}

	// A write reaching the entrypoint but not the manifest still lets the script rewrite
	// its own code after the approval attests it.
	sub := filepath.Join(dir, "src")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	got = callouts(&policy.Policy{Entrypoint: "./src/tool.py", Write: []string{sub}})
	if !strings.Contains(got, "covers the entrypoint") {
		t.Errorf("callouts missing the entrypoint warning; got:\n%s", got)
	}

	// A whole home is the other thing worth stopping on, and it is a read grant that
	// nothing else here would flag.
	home := t.TempDir()
	t.Setenv("HOME", home)
	got = callouts(&policy.Policy{Entrypoint: "./tool.py", Read: []string{"~"}})
	if !strings.Contains(got, "whole home or top-level directory") {
		t.Errorf("callouts missing the broad-grant warning; got:\n%s", got)
	}

	// A ~ entrypoint is legal and manifest.Resolve expands it against $HOME, so a second
	// implementation that only handles "absolute or relative-to-manifest" builds a path
	// that does not exist and CoversResolved silently answers no - the callout most worth
	// having, missing, in the review step that exists to give it.
	tildeHome := t.TempDir()
	t.Setenv("HOME", tildeHome)
	bin := filepath.Join(tildeHome, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	got = callouts(&policy.Policy{Entrypoint: "~/bin/tool.py", Write: []string{"~/bin"}})
	if !strings.Contains(got, "covers the entrypoint") {
		t.Errorf("a ~ entrypoint must resolve the same way the enforced run resolves it; got:\n%s", got)
	}

	// A host that cannot resolve the grants must say so rather than print a clean block:
	// resolution fails on a ~ it cannot expand, which is the likeliest whole-home grant.
	var buf strings.Builder
	writeApprovalCallouts(&buf, manifestPath, &policy.Policy{Entrypoint: "./tool.py", Read: []string{"~"}}, nil, nil)
	if !strings.Contains(buf.String(), "could not be resolved") {
		t.Errorf("unresolvable grants must be reported, not silently skipped; got:\n%s", buf.String())
	}

	// A narrow policy is the common case and must print nothing: a block that fires on
	// every manifest is a block nobody reads.
	if got := callouts(&policy.Policy{Entrypoint: "./tool.py", Read: []string{filepath.Join(dir, "data")}, Exec: policy.ExecNone}); got != "" {
		t.Errorf("a narrow policy must produce no callouts; got:\n%s", got)
	}
}

// approve's prompt is the review it exists to record, so the two ways past it must differ:
// --yes is a caller saying "stamp it unreviewed", and a stdin that is not a terminal is
// nobody there to ask at all. The second used to stamp too, which made a piped approve
// byte-identical in effect to a reviewed one - a pipeline reaching approve without --yes
// stamped whatever the manifest held. examples/supervise refuses the same condition.
func TestConfirmApprovalNeedsAnAnswerOrTheFlag(t *testing.T) {
	t.Run("--yes", func(t *testing.T) {
		var buf strings.Builder
		if err := confirmApproval(t.Context(), &buf, true); err != nil {
			t.Errorf("confirmApproval must proceed; got %v", err)
		}
		if buf.String() != "" {
			t.Errorf("--yes was the operator answering, so nothing is printed; got %q", buf.String())
		}
	})

	t.Run("stdin is not a terminal", func(t *testing.T) {
		// stdin is swapped for a pipe rather than trusting whatever the test binary
		// inherited: run from a terminal, this subtest otherwise takes the interactive
		// branch and asserts a refusal that never comes - or blocks on the developer's own
		// terminal waiting for an answer. A pipe is not a terminal anywhere.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		saved := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = saved }()

		var buf strings.Builder
		err = confirmApproval(t.Context(), &buf, false)
		if err == nil {
			t.Fatal("a stdin nobody can answer on must refuse rather than stamp")
		}
		if !strings.Contains(err.Error(), "not a terminal") || !strings.Contains(err.Error(), "--yes") {
			t.Errorf("the refusal must name the condition and the way past it; got %v", err)
		}
		if strings.Contains(buf.String(), "?") {
			t.Errorf("nothing may be asked when there is nobody to answer; got %q", buf.String())
		}
	})
}

// The fingerprint's job is catching permission creep, and `run` refuses a drifted manifest
// by sending the reader here - where the policy printed for a re-approval was identical to
// one printed for a first approval, so the grant that caused the refusal had to be spotted
// from memory. bento cannot mark it (the stamp is a hash, not a copy), but it must not let
// the two reads look the same.
func TestApproveSaysTheManifestWasApprovedForSomethingElse(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/etc/shadow"}}
	stale := writeManifest(t, p, manifest.Provenance{Approves: "0badc0de"})

	// --yes because `go test` has no terminal, and approve refuses one it cannot ask on.
	out, err := runCapturingStdout(t, newApproveCmd(), stale, "--yes")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !strings.Contains(out, "approved before and its permissions have changed") {
		t.Errorf("re-approving a drifted manifest must say the policy is not the one stamped:\n%s", out)
	}
	// And a first approval must not: a notice printed over every manifest says nothing.
	fresh := writeManifest(t, p, manifest.Provenance{})
	out, err = runCapturingStdout(t, newApproveCmd(), fresh, "--yes")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if strings.Contains(out, "permissions have changed") {
		t.Errorf("an unstamped manifest has no prior approval to differ from:\n%s", out)
	}
}

// A manifest lists a host the profiling run's egress guard refused exactly as
// it lists one that worked, so a reader following profile -> validate -> approve stamps
// egress bento itself would not permit. The record is provenance, so approve is the one
// command holding both it and the rule it describes.
func TestApproveCallsOutAHostTheProfilingRunWasRefused(t *testing.T) {
	p := &policy.Policy{
		Entrypoint: "./x",
		Network: []policy.NetworkRule{
			{Host: "metadata.internal", Port: "80"},
			{Host: "example.com", Port: "443"},
		},
	}
	prov := manifest.Provenance{GeneratedBy: "bento profile", BlockedHosts: []string{"metadata.internal:80"}}
	path := writeManifest(t, p, prov)

	out, err := runCapturingStdout(t, newApproveCmd(), path, "--yes")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !strings.Contains(out, `network: "metadata.internal"`) {
		t.Errorf("approve output must call out the refused host:\n%s", out)
	}
	if strings.Contains(out, `network: "example.com"`) {
		t.Errorf("a host the run actually reached must not be called out:\n%s", out)
	}

	// The stamp rewrites the whole provenance block, so without carrying the record
	// forward the callout would appear once and never again.
	doc, _, err := loadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(doc.Provenance.BlockedHosts, []string{"metadata.internal:80"}) {
		t.Errorf("blocked-hosts = %v, want it carried through the stamp", doc.Provenance.BlockedHosts)
	}
	if checkApproval(doc) != approvalCurrent {
		t.Error("the record is provenance, not permission: it must not shift the approval fingerprint")
	}
}

// The prompt is the last point at which lifting a credential shield can still be
// declined: the run-time warning for it prints after the target has already put whatever
// it read on stdout. It must fire on every path to the stamp, so it lives in the callouts
// rather than behind the TTY branch --yes and a piped stdin both skip.
func TestApprovalCalloutsNameAnExplicitShieldGrant(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	manifestPath := filepath.Join(t.TempDir(), "tool.py.manifest.yaml")

	p := &policy.Policy{Entrypoint: "./tool.py", Read: []string{"~/.ssh"}}
	var buf strings.Builder
	writeApprovalCallouts(&buf, manifestPath, p, resolvedGrants(p, manifestPath), nil)
	got := buf.String()
	for _, want := range []string{filepath.Join(home, ".ssh"), "lifts the shield"} {
		if !strings.Contains(got, want) {
			t.Errorf("callouts missing %q; got:\n%s", want, got)
		}
	}

	// A grant that merely contains shields is an ordinary broad read, called out as one.
	var broad strings.Builder
	q := &policy.Policy{Entrypoint: "./tool.py", Read: []string{"~"}}
	writeApprovalCallouts(&broad, manifestPath, q, resolvedGrants(q, manifestPath), nil)
	if strings.Contains(broad.String(), "lifts the shield") {
		t.Errorf("a grant containing shields does not lift one; got:\n%s", broad.String())
	}
}

// The whole point of an approval is that a human read the permissions, so a
// pipeline reaching approve without --yes must not have that decided for it by where
// stdin happens to point. Nothing may be stamped: the manifest is left as it was found.
func TestApproveRefusesANonTerminalStdinWithoutWritingAnything(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// `go test` has no terminal, so the plain invocation is the piped one.
	if _, err := runCapturingStdout(t, newApproveCmd(), path); err == nil {
		t.Fatal("approve must refuse a stdin nobody can answer on")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("a refused approval must leave the manifest untouched; got:\n%s", after)
	}
}

// A stamp over a grant the run refuses records a review of a permission that does not
// exist, and the stamp is what the CI gate then trusts. --yes does not soften it: in CI
// the flag answers every question, so the only place this can be caught is a refusal.
func TestApproveRefusesAGrantTheRunWillNotHonor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x", Write: []string{"~/.ssh"}}, manifest.Provenance{})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runCapturingStdout(t, newApproveCmd(), path, "--yes")
	if err == nil {
		t.Fatalf("approve must refuse a grant run refuses; got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("the refusal must carry run's own sentence; got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a refused approval must leave the manifest as it was found")
	}

	// A manifest carrying such a grant AND a matching stamp - what an earlier bento left
	// behind, and what the report of this bug started from - must not take the
	// already-approved shortcut and report as approved for a permission run refuses.
	stamped := &policy.Policy{Entrypoint: "./x", Write: []string{"~/.ssh"}}
	current := writeManifest(t, stamped, manifest.Provenance{Approves: stamped.Fingerprint()})
	out, err = runCapturingStdout(t, newApproveCmd(), current, "--yes")
	if err == nil {
		t.Errorf("an existing stamp must not excuse a grant run refuses; got:\n%s", out)
	}
}

// The stale refusal sends the reader back to re-review, and the next question is always
// "what changed?". The fingerprint is a one-way hash over the policy fields, so the
// manifest cannot answer it - and a message that does not say where the answer is reads as
// bento withholding one. Both refusals must point at approve, which holds the journal.
func TestStaleRefusalsSayWhereTheDiffIs(t *testing.T) {
	stale := doc("old")
	err := requireApproval(stale, false)
	if err == nil || !strings.Contains(err.Error(), noStampDiff) {
		t.Errorf("run's stale refusal must say the stamp cannot produce a diff; got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "bento approve") {
		t.Errorf("run's stale refusal must point at where the diff can be had; got %v", err)
	}

	var buf strings.Builder
	_ = reportApproval(&buf, stale, false)
	if !strings.Contains(buf.String(), "hash of the permissions, not a copy of them") {
		t.Errorf("validate's STALE report must say the same; got:\n%s", buf.String())
	}
}

// The one policy field that can change what program runs without naming a path or a
// host. It reads as configuration next to the grants around it, so approving it has to
// be a decision like every other callout.
func TestApprovalCalloutsNameInterpreterArgs(t *testing.T) {
	var buf strings.Builder
	p := &policy.Policy{Entrypoint: "./tool.py", Interpreter: "python3", InterpreterArgs: []string{"-c", "print(1)"}}
	writeApprovalCallouts(&buf, "m.yaml", p, p, nil)
	out := buf.String()
	if !strings.Contains(out, "interpreter_args") || !strings.Contains(out, strconv.Quote("print(1)")) {
		t.Errorf("approve did not call out the interpreter's own arguments:\n%s", out)
	}
	var plain strings.Builder
	q := &policy.Policy{Entrypoint: "./tool.py", Interpreter: "python3"}
	writeApprovalCallouts(&plain, "m.yaml", q, q, nil)
	if strings.Contains(plain.String(), "interpreter_args") {
		t.Errorf("a policy without interpreter_args must produce no callout:\n%s", plain.String())
	}
}
