package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
)

// filesystemLayer is the decision at the heart of the degraded tier: bwrap when
// userns works, Landlock-only Degraded when it does not but the kernel has Landlock
// and the reduced tier's seccomp fences are available, and Unavailable when the
// filesystem cannot be confined, when those fences cannot stand in for the missing
// namespaces, or when the probe never answered at all. It is a pure function so every
// branch is testable without a userns-blocked host.
func TestFilesystemLayerThreeStates(t *testing.T) {
	const nsReason = "userns blocked here"
	cases := []struct {
		name                  string
		ns                    namespaceProbe
		landlockAvail         bool
		truncateRestricted    bool
		ioctlDevRestricted    bool
		resolveUnixRestricted bool
		degradedFencesOK      bool
		want                  enforce.State
		reasonHas             string
	}{
		{"userns ok, landlock present", namespacesUsable, true, true, true, true, true, enforce.Enforced, "backstop"},
		{"userns ok, no landlock", namespacesUsable, false, true, true, true, true, enforce.Enforced, "bwrap alone"},
		{"userns blocked, landlock present, fences ok", namespacesBlocked, true, true, true, true, true, enforce.Degraded, "Landlock path rules"},
		{"userns blocked, landlock present, truncate unrestricted", namespacesBlocked, true, false, true, true, true, enforce.Degraded, "cannot restrict truncate"},
		{"userns blocked, landlock present, ioctl_dev unrestricted", namespacesBlocked, true, true, false, true, true, enforce.Degraded, "cannot restrict ioctl on device files"},
		{"userns blocked, landlock present, resolve_unix unrestricted", namespacesBlocked, true, true, true, false, true, enforce.Degraded, "cannot restrict connect(2) on pathname"},
		{"userns blocked, landlock present, no seccomp fences", namespacesBlocked, true, true, true, true, false, enforce.Unavailable, "reduced-confinement fallback needs a seccomp"},
		{"userns blocked, no landlock", namespacesBlocked, false, true, true, true, true, enforce.Unavailable, "no filesystem confinement"},
		// An unanswered probe must never select the weaker tier: the host may run bwrap
		// fine, and a degraded run decided from a measurement that was never taken is the
		// wrong sandbox under a wrong reason. Unknown fails closed even where Landlock -
		// and the fences the degraded tier needs - are present.
		{"userns unknown, landlock and fences present", namespacesUnknown, true, true, true, true, true, enforce.Unavailable, "userns blocked here"},
		{"userns unknown, no landlock", namespacesUnknown, false, true, true, true, true, enforce.Unavailable, "userns blocked here"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, reason := filesystemLayer(tc.ns, nsReason, tc.landlockAvail, tc.truncateRestricted, tc.ioctlDevRestricted, tc.resolveUnixRestricted, tc.degradedFencesOK)
			if state != tc.want {
				t.Errorf("state = %v, want %v", state, tc.want)
			}
			if !strings.Contains(reason, tc.reasonHas) {
				t.Errorf("reason %q does not mention %q", reason, tc.reasonHas)
			}
		})
	}
}

// The degraded tier is reached whenever bwrap cannot give a namespace, and a missing
// bwrap is one of those ways. Its detail has to lead with what the probe actually
// found: a hardcoded "user namespaces are blocked" sends a reader off to enable a
// namespace this host already permits, and the real cause used to sit ~1200
// characters downstream where nobody acts on it.
func TestFilesystemLayerDegradedLeadsWithProbeReason(t *testing.T) {
	const nsReason = "bubblewrap (bwrap) is not installed, so it cannot isolate anything"
	state, reason := filesystemLayer(namespacesBlocked, nsReason, true, true, true, true, true)
	if state != enforce.Degraded {
		t.Fatalf("state = %v, want Degraded", state)
	}
	if !strings.HasPrefix(reason, nsReason) {
		t.Errorf("reason does not lead with the probe reason: %q", reason)
	}
	if strings.Contains(reason, "unprivileged user namespaces are blocked") {
		t.Errorf("reason asserts a userns block the probe did not find: %q", reason)
	}
}

// classifyUnshare's sysctl diagnoses end with an instruction to the reader, so every
// branch that continues a probe reason has to join a full sentence to its own clause
// without leaving ".;" in the middle of the detail a user reads.
func TestFilesystemLayerJoinsASentenceReasonCleanly(t *testing.T) {
	const nsReason = "cannot create an unprivileged user namespace, so bubblewrap cannot isolate " +
		"anything: unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0). " +
		"Set it to 1 to allow them."
	for _, tc := range []struct {
		name          string
		landlockAvail bool
		fencesOK      bool
	}{
		{"degraded", true, true},
		{"no seccomp fences", true, false},
		{"no landlock", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, reason := filesystemLayer(namespacesBlocked, nsReason, tc.landlockAvail, true, true, true, tc.fencesOK)
			if strings.Contains(reason, ".;") {
				t.Errorf("reason runs a period into a semicolon: %q", reason)
			}
			if !strings.Contains(reason, "Set it to 1 to allow them") {
				t.Errorf("reason dropped the probe's instruction: %q", reason)
			}
		})
	}
}

// A limit is enforced by the systemd scope both tiers wrap their command in, so the
// report must hang on scope creation alone - and must never claim Enforced without a
// creatable scope, which would report a memory/pids/cpu cap that does not hold.
func TestLimitsLayersTrackScopeCreation(t *testing.T) {
	ok := limitsLayers(true, "", enforce.Degraded, "cpu controller not delegated")
	if len(ok) != 2 || ok[0].State != enforce.Enforced || ok[1].Layer != enforce.LayerLimitsCPU || ok[1].State != enforce.Degraded {
		t.Fatalf("scope: got %+v, want LayerLimits=Enforced + LayerLimitsCPU=Degraded", ok)
	}

	no := limitsLayers(false, "no scope here", enforce.Enforced, "")
	if len(no) != 1 || no[0].State != enforce.Unavailable || no[0].Reason != "no scope here" {
		t.Fatalf("no scope: got %+v, want LayerLimits=Unavailable carrying the scope reason", no)
	}
}

// exec-strict is the stricter of the two claims and needs the architecture filter on
// top of seccomp, so a host with seccomp but no strict filter must report exec
// Enforced and exec-strict Unavailable rather than letting the coarser layer's
// success speak for both.
func TestExecLayers(t *testing.T) {
	cases := []struct {
		name            string
		seccompOK       bool
		strictOK        bool
		wantExec        enforce.State
		wantStrict      enforce.State
		strictReasonHas string
	}{
		{"seccomp and strict filter", true, true, enforce.Enforced, enforce.Enforced, ""},
		{"seccomp, no strict filter", true, false, enforce.Enforced, enforce.Unavailable, "not implemented for this architecture"},
		{"no seccomp", false, true, enforce.Unavailable, enforce.Unavailable, "does not support seccomp BPF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := execLayers(tc.seccompOK, tc.strictOK)
			if len(got) != 2 || got[0].Layer != enforce.LayerExec || got[1].Layer != enforce.LayerExecStrict {
				t.Fatalf("got %+v, want LayerExec then LayerExecStrict", got)
			}
			if got[0].State != tc.wantExec {
				t.Errorf("exec = %v, want %v", got[0].State, tc.wantExec)
			}
			if got[1].State != tc.wantStrict {
				t.Errorf("exec-strict = %v, want %v", got[1].State, tc.wantStrict)
			}
			if !strings.Contains(got[1].Reason, tc.strictReasonHas) {
				t.Errorf("exec-strict reason %q does not mention %q", got[1].Reason, tc.strictReasonHas)
			}
		})
	}
}

// Probe must read the real capability checks, not assume the capabilities it was
// developed on. The decision functions above prove the decisions; this proves the
// wiring, which no host that HAS every capability can otherwise exercise: a Probe
// that hardcoded a layer Enforced would satisfy every test above and still report a
// guarantee this kernel cannot deliver.
func TestProbeReadsTheRealCapabilityChecks(t *testing.T) {
	cases := []struct {
		name string
		lose func(*testing.T)

		layer enforce.Layer
		// wantState after the loss. The filesystem layer stays Enforced without
		// Landlock on a userns-capable host - bwrap is the guarantee there and
		// Landlock only the backstop - so what must change is the disclosure, not
		// the verdict.
		wantState     enforce.State
		wantReasonHas string
	}{
		{
			"no landlock", func(t *testing.T) { swap(t, &landlockAvailable, false) },
			enforce.LayerFilesystem, enforce.Enforced, "bwrap alone",
		},
		{
			"no seccomp", func(t *testing.T) { swap(t, &seccompSupported, false) },
			enforce.LayerExec, enforce.Unavailable, "does not support seccomp BPF",
		},
		{
			"no strict exec filter", func(t *testing.T) { swap(t, &seccompStrictExecSupported, false) },
			enforce.LayerExecStrict, enforce.Unavailable, "not implemented for this architecture",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A positive control: this host must report the layer Enforced and NOT
			// already say what the loss should make it say, or the assertion below
			// would hold for a Probe that ignores the check entirely.
			before := layerStatus(t, tc.layer)
			if before.State != enforce.Enforced || strings.Contains(before.Reason, tc.wantReasonHas) {
				t.Skipf("this host already reports %v as %v (%q), so losing the capability proves nothing",
					tc.layer, before.State, before.Reason)
			}
			tc.lose(t)
			after := layerStatus(t, tc.layer)
			if after.State != tc.wantState || !strings.Contains(after.Reason, tc.wantReasonHas) {
				t.Errorf("with the capability absent %v = %v (%q), want %v mentioning %q - Probe is not reading the check",
					tc.layer, after.State, after.Reason, tc.wantState, tc.wantReasonHas)
			}
		})
	}
}

// The egress check reaches the filesystem layer only indirectly, through the
// degradedFencesOK term: the reduced tier stands in for the missing namespaces with
// a seccomp egress block, so without one there is no tier left to offer. Dropping
// that term from Probe would offer --allow-degraded on a host where the launcher can
// only refuse, which is the fail-open this layer exists to prevent.
//
// Emptying PATH is what makes the branch reachable: usableNamespaces looks bwrap up
// on PATH, so this drives Probe down the userns-blocked path on a host where userns
// works.
func TestProbeReadsTheEgressCheckForTheDegradedTier(t *testing.T) {
	t.Setenv("PATH", "")

	// A positive control: with the fences intact this host must still offer the
	// degraded tier, or the Unavailable below would just be the absent bwrap talking.
	if before := layerStatus(t, enforce.LayerFilesystem); before.State != enforce.Degraded {
		t.Skipf("without bwrap this host reports filesystem %v (%q), not the degraded tier, so losing the egress fence proves nothing",
			before.State, before.Reason)
	}

	swap(t, &seccompEgressSupported, false)
	after := layerStatus(t, enforce.LayerFilesystem)
	// The state check carries the teeth here: the Degraded reason this must NOT be
	// also mentions the seccomp egress block, so a reason-only assertion passes even
	// when Probe ignores the check entirely.
	if after.State != enforce.Unavailable || !strings.Contains(after.Reason, "seccomp") {
		t.Errorf("with the egress fence absent filesystem = %v (%q), want unavailable blaming the seccomp fences - Probe is not reading the check",
			after.State, after.Reason)
	}
}

func swap(t *testing.T, fn *func() bool, v bool) {
	t.Helper()
	orig := *fn
	t.Cleanup(func() { *fn = orig })
	*fn = func() bool { return v }
}

// The degraded tier's unix-socket disclosure has to track what the kernel can actually
// restrict, not repeat one fixed sentence. From ABI 9 the degraded ruleset handles
// resolve_unix and grants it only on the write set, so telling the operator a pathname
// socket to a host daemon is reachable would be false - and on a kernel below 9 it is
// true, and the residual has to say so. The two directions are asserted together because
// the failure that matters is the report contradicting itself.
func TestFilesystemLayerUnixSocketDisclosureTracksTheABI(t *testing.T) {
	const nsReason = "userns blocked here"
	_, restricted := filesystemLayer(namespacesBlocked, nsReason, true, true, true, true, true)
	if strings.Contains(restricted, "including an abstract-namespace one no grant is needed to reach") {
		t.Errorf("with resolve_unix restricted the reason still claims any unix socket is reachable: %q", restricted)
	}
	if !strings.Contains(restricted, "abstract-namespace unix socket") {
		t.Errorf("the abstract namespace stays reachable and must still be disclosed: %q", restricted)
	}
	// The one denial an operator cannot diagnose from the target's own behaviour, so the
	// report has to name it rather than leave it to "a pathname socket is denied".
	if !strings.Contains(restricted, "/dev/log") {
		t.Errorf("the silent syslog denial must be named: %q", restricted)
	}
	_, unrestricted := filesystemLayer(namespacesBlocked, nsReason, true, true, true, false, true)
	if !strings.Contains(unrestricted, "any host daemon socket its path names") {
		t.Errorf("below ABI 9 the pathname-socket residual must be disclosed: %q", unrestricted)
	}
}

func layerStatus(t *testing.T, layer enforce.Layer) enforce.LayerStatus {
	t.Helper()
	for _, ls := range New().Probe(t.Context()).Layers {
		if ls.Layer == layer {
			return ls
		}
	}
	t.Fatalf("Probe reported no %v layer", layer)
	return enforce.LayerStatus{}
}

// The degraded and unavailable reasons must carry the underlying namespace reason,
// so a user sees why bwrap could not run (and its remediation), not just that the
// filesystem tier changed.
func TestFilesystemLayerCarriesNamespaceReason(t *testing.T) {
	const nsReason = "AppArmor restricts unprivileged user namespaces"
	for _, landlock := range []bool{true, false} {
		state, reason := filesystemLayer(namespacesBlocked, nsReason, landlock, true, true, true, true)
		if !strings.Contains(reason, nsReason) {
			t.Errorf("landlock=%v: %v reason %q dropped the namespace reason", landlock, state, reason)
		}
	}
}

// The namespace probe's canary must be resolved on $PATH, not hardcoded to
// /bin/true. bwrap creates the namespaces first and execs last, so on a host with no
// /bin/true only the exec fails - and the probe would report userns blocked, refuse
// every network manifest, and silently downgrade the run to the Landlock-only tier.
// A host missing /bin/true cannot be constructed here, so this drives the property
// from the other side: with $PATH naming a `true` that exits non-zero, the probe must
// fail, which it can only do if the canary it ran was the resolved one.
func TestCanUnshareRunsTheResolvedCanary(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	canary := filepath.Join(dir, "true")
	if err := os.WriteFile(canary, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := canUnshare(context.Background(), "bwrap"); err == nil {
		t.Error("canUnshare passed while its canary exited 3; it ran a hardcoded /bin/true, not the resolved one")
	}
}

// The degraded tier's own system paths are raw literals, and several are commonly
// symlinks (/dev/urandom, the FHS lib dirs on a usrmerge host, /nix). go-landlock
// opens a path without O_NOFOLLOW, so the rule it installs lands on the resolved
// target either way - but bento's record of the read set feeds the exposure scan,
// which must name the paths that were actually granted, not the names they were
// granted under.
func TestDegradedSystemPathsResolveThroughTheSeam(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string {
		if p == "/dev/urandom" {
			return "/dev/hwrng"
		}
		return p
	}
	reads, writes := degradedSystemPaths(sb)
	if !slices.Contains(reads, "/dev/hwrng") {
		t.Errorf("reads = %v, want the symlinked /dev/urandom resolved to /dev/hwrng", reads)
	}
	if slices.Contains(reads, "/dev/urandom") {
		t.Errorf("reads = %v, want only the resolved name, not the symlink", reads)
	}
	if !slices.Contains(writes, "/dev/null") {
		t.Errorf("writes = %v, want /dev/null", writes)
	}
}

// Every failure of the namespace probe used to read as "userns blocked", which is a
// finding about the host. Only bwrap refusing the namespace is that finding; a probe
// that was killed by its own deadline, or that failed for a reason bwrap did not name,
// has measured nothing - and reporting it as blocked hands the user the Landlock-only
// tier plus AppArmor remediation on a host where bwrap works.
func TestClassifyUnshareSeparatesBlockedFromUnanswered(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		want        namespaceProbe
		reasonHas   string
		reasonLacks string
	}{
		{
			"bwrap refused the namespace",
			&usernsError{output: "bwrap: No permissions to create new user namespace", err: errors.New("exit status 1")},
			namespacesBlocked, "cannot create an unprivileged user namespace", "",
		},
		{
			"permission denied",
			&usernsError{output: "bwrap: Permission denied", err: errors.New("exit status 1")},
			namespacesBlocked, "cannot create an unprivileged user namespace", "",
		},
		{
			"probe timed out",
			&usernsError{output: "", err: errors.New("signal: killed"), ctxErr: context.DeadlineExceeded},
			namespacesUnknown, "did not finish", "",
		},
		{
			// A deadline that also produced bwrap output must still be unanswered: the
			// output is whatever the canary managed before the kill, not a verdict.
			"timed out with namespace-shaped output",
			&usernsError{output: "bwrap: No permissions to create new user namespace", err: errors.New("signal: killed"), ctxErr: context.Canceled},
			namespacesUnknown, "did not finish", "",
		},
		{
			// The host granted the namespace and refused the mount inside it, so the
			// reason must not claim the namespace was refused - and the verdict must not
			// be "unanswered" either, since this message names neither of the strings the
			// namespace match looks for.
			"procfs refused inside a granted namespace",
			&usernsError{output: "bwrap: Can't mount proc on /newroot/proc: Operation not permitted", err: errors.New("exit status 1")},
			namespacesBlocked, "systempaths=unconfined", "cannot create an unprivileged user namespace",
		},
		{
			// The other base mounts get the same reading and no remedy: bento has
			// established a cause for the procfs refusal and none for these, but a
			// "Permission denied" wording must still not be read as a userns refusal.
			"a base mount other than proc refused",
			&usernsError{output: "bwrap: Can't mount devpts on /newroot/dev/pts: Permission denied", err: errors.New("exit status 1")},
			namespacesBlocked, "cannot mount the pseudo-filesystems", "unprivileged user namespace",
		},
		{
			"canary reaped without a namespace error",
			&usernsError{output: "bwrap: execvp true: Cannot allocate memory", err: errors.New("exit status 1")},
			namespacesUnknown, "is unknown", "",
		},
		{
			"bwrap could not be run at all",
			errors.New("fork/exec /usr/bin/bwrap: resource temporarily unavailable"),
			namespacesUnknown, "is unknown", "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := classifyUnshare(tc.err)
			if got != tc.want {
				t.Errorf("verdict = %v, want %v (reason %q)", got, tc.want, reason)
			}
			if !strings.Contains(reason, tc.reasonHas) {
				t.Errorf("reason %q does not mention %q", reason, tc.reasonHas)
			}
			if tc.reasonLacks != "" && strings.Contains(reason, tc.reasonLacks) {
				t.Errorf("reason %q claims %q, which is not what this host refused", reason, tc.reasonLacks)
			}
		})
	}
}

// The probe is only as honest as the flags it shares with the run, and this drift has
// already happened once: --new-session sits in baseFlags rather than a shared list, so
// the canary never exercised it (see newsession_test.go). Mounting proc was the second
// instance and cost a host class a truthful doctor. So every base flag has to be
// accounted for - either it is in a list the canary appends, or it is a known exception
// with a test of its own behind it.
func TestBaseFlagsStayCoveredByTheProbedLists(t *testing.T) {
	covered := make(map[string]bool)
	for _, f := range append(append([]string{}, namespaceFlags...), pseudoFSFlags...) {
		covered[f] = true
	}
	// --die-with-parent is a parent-death signal, not a host capability, and
	// --new-session is asserted directly against a terminal in newsession_test.go.
	for _, f := range []string{"--die-with-parent", "--new-session"} {
		covered[f] = true
	}
	for _, f := range baseFlags() {
		if !covered[f] {
			t.Errorf("baseFlags has %q, which the pre-run probe never exercises: add it to namespaceFlags "+
				"or pseudoFSFlags, or record here why the probe cannot check it", f)
		}
	}
}

// The probe runs on the hot path of every Run, so it bounds itself like every sibling
// probe rather than trusting the caller's context - the CLI's is never cancelled, so a
// wedged bwrap would stall admission indefinitely. The bound is reported as a probe
// failure, not as a host that blocks namespaces.
func TestCanUnshareBoundsItselfAndReportsTheDeadline(t *testing.T) {
	slow := filepath.Join(t.TempDir(), "bwrap")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nsleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := canUnshare(context.Background(), slow)
	if err == nil {
		t.Fatal("a bwrap that never returns must fail the probe")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("the probe took %v; it must bound itself rather than wait on an uncancelled caller context", elapsed)
	}
	if got, reason := classifyUnshare(err); got != namespacesUnknown {
		t.Errorf("verdict = %v, want namespacesUnknown (reason %q)", got, reason)
	}
}
