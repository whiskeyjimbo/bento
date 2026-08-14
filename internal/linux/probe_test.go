//go:build linux

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
		scopedIPCRestricted   bool
		netTCPRestricted      bool
		degradedFencesOK      bool
		want                  enforce.State
		reasonHas             string
	}{
		{"userns ok, landlock present", namespacesUsable, true, true, true, true, true, true, true, enforce.Enforced, "backstop"},
		{"userns ok, no landlock", namespacesUsable, false, true, true, true, true, true, true, enforce.Enforced, "bwrap alone"},
		{"userns blocked, landlock present, fences ok", namespacesBlocked, true, true, true, true, true, true, true, enforce.Degraded, "Landlock path rules"},
		{"userns blocked, landlock present, truncate unrestricted", namespacesBlocked, true, false, true, true, true, true, true, enforce.Degraded, "cannot restrict truncate"},
		{"userns blocked, landlock present, ioctl_dev unrestricted", namespacesBlocked, true, true, false, true, true, true, true, enforce.Degraded, "cannot restrict ioctl on device files"},
		{"userns blocked, landlock present, resolve_unix unrestricted", namespacesBlocked, true, true, true, false, true, true, true, enforce.Degraded, "cannot restrict connect(2) on pathname"},
		{"userns blocked, landlock present, IPC scoping unavailable", namespacesBlocked, true, true, true, false, false, true, true, enforce.Degraded, "abstract-namespace one no grant is needed to reach"},
		{"userns blocked, landlock present, TCP fence unavailable", namespacesBlocked, true, true, true, true, true, false, true, enforce.Degraded, "cannot restrict TCP connect"},
		{"userns blocked, landlock present, no seccomp fences", namespacesBlocked, true, true, true, true, true, true, false, enforce.Unavailable, "reduced-confinement fallback needs a seccomp"},
		{"userns blocked, no landlock", namespacesBlocked, false, true, true, true, true, true, true, enforce.Unavailable, "no filesystem confinement"},
		// An unanswered probe must never select the weaker tier: the host may run bwrap
		// fine, and a degraded run decided from a measurement that was never taken is the
		// wrong sandbox under a wrong reason. Unknown fails closed even where Landlock -
		// and the fences the degraded tier needs - are present.
		{"userns unknown, landlock and fences present", namespacesUnknown, true, true, true, true, true, true, true, enforce.Unavailable, "userns blocked here"},
		{"userns unknown, no landlock", namespacesUnknown, false, true, true, true, true, true, true, enforce.Unavailable, "userns blocked here"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := filesystemLayer(tc.ns, nsReason, tc.landlockAvail, tc.truncateRestricted, tc.ioctlDevRestricted, tc.resolveUnixRestricted, tc.scopedIPCRestricted, tc.netTCPRestricted, tc.degradedFencesOK)
			state, reason := l.State, l.Disclosure()
			if state != tc.want {
				t.Errorf("state = %v, want %v", state, tc.want)
			}
			if !strings.Contains(reason, tc.reasonHas) {
				t.Errorf("reason %q does not mention %q", reason, tc.reasonHas)
			}
		})
	}
}

// The degraded tier's disclosure is split so a run refusal can lead with the remedy:
// the tier consequences are identical on every degraded host and used to bury the one
// host-specific line the reader can act on. The split is only sound if nothing is lost
// - every fact the one string carried has to still be in one half or the other.
func TestFilesystemLayerSplitsConsequencesFromTheRemedy(t *testing.T) {
	const nsReason = "userns blocked here. Set it to 1 to allow them."
	l := filesystemLayer(namespacesBlocked, nsReason, true, false, false, false, false, false, true)
	if l.State != enforce.Degraded {
		t.Fatalf("state = %v, want Degraded", l.State)
	}
	for _, buried := range []string{"no PID namespace", "netlink interface enumeration", "cannot restrict truncate"} {
		if strings.Contains(l.Reason, buried) {
			t.Errorf("reason still inlines the tier consequences (%q): %q", buried, l.Reason)
		}
		if !strings.Contains(l.Consequences, buried) {
			t.Errorf("consequences dropped %q: %q", buried, l.Consequences)
		}
	}
	// Every other state describes itself in one string; a stray consequences field there
	// is a fact no refusal prints and only doctor's note block would ever show.
	for _, other := range []enforce.LayerStatus{
		filesystemLayer(namespacesUsable, "", true, true, true, true, true, true, true),
		filesystemLayer(namespacesBlocked, nsReason, false, true, true, true, true, true, true),
		filesystemLayer(namespacesUnknown, nsReason, true, true, true, true, true, true, true),
	} {
		if other.Consequences != "" {
			t.Errorf("%v carries consequences no refusal points at: %q", other.State, other.Consequences)
		}
	}
}

// The degraded tier is reached whenever bwrap cannot give a namespace, and a missing
// bwrap is one of those ways. Its detail has to lead with what the probe actually
// found: a hardcoded "user namespaces are blocked" sends a reader off to enable a
// namespace this host already permits, and the real cause used to sit ~1200
// characters downstream where nobody acts on it.
func TestFilesystemLayerDegradedLeadsWithProbeReason(t *testing.T) {
	const nsReason = "bubblewrap (bwrap) is not installed, so it cannot isolate anything"
	l := filesystemLayer(namespacesBlocked, nsReason, true, true, true, true, true, true, true)
	state, reason := l.State, l.Reason
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

// A missing bwrap is the one probe finding the reader can fix outright, and the binary
// is not named after the package that carries it - so the reason has to say how to get
// it, not just that it is absent.
func TestMissingBwrapReasonNamesTheInstall(t *testing.T) {
	t.Setenv("PATH", "")
	state, reason := usableNamespaces(context.Background())
	if state != namespacesBlocked {
		t.Fatalf("state = %v, want namespacesBlocked", state)
	}
	if !strings.Contains(reason, "apt install bubblewrap") {
		t.Errorf("reason gives the user no way to install bwrap: %q", reason)
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
			reason := filesystemLayer(namespacesBlocked, nsReason, tc.landlockAvail, true, true, true, true, true, tc.fencesOK).Disclosure()
			if strings.Contains(reason, ".;") {
				t.Errorf("reason runs a period into a semicolon: %q", reason)
			}
			if !strings.Contains(reason, "Set it to 1 to allow them") {
				t.Errorf("reason dropped the probe's instruction: %q", reason)
			}
		})
	}
}

// A limit is enforced by the systemd scope both tiers wrap their command in, plus the
// controllers it needs delegated, so each layer must carry its own delegation state -
// and neither may claim Enforced without a creatable scope, which would report a
// memory/pids/cpu cap that does not hold.
func TestLimitsLayersTrackScopeCreation(t *testing.T) {
	ok := limitsLayers(true, "", enforce.Enforced, "", enforce.Degraded, "cpu controller not delegated")
	if len(ok) != 2 || ok[0].State != enforce.Enforced || ok[1].Layer != enforce.LayerLimitsCPU || ok[1].State != enforce.Degraded {
		t.Fatalf("scope: got %+v, want LayerLimits=Enforced + LayerLimitsCPU=Degraded", ok)
	}

	// Each layer states its own verdict: memory/pids undelegated must not drag the cpu
	// layer down, or a cpu-only manifest is refused over a controller it never asked for.
	memOnly := limitsLayers(true, "", enforce.Unavailable, "memory/pids not delegated", enforce.Enforced, "")
	if len(memOnly) != 2 || memOnly[0].State != enforce.Unavailable || memOnly[1].State != enforce.Enforced {
		t.Fatalf("memory undelegated: got %+v, want LayerLimits=Unavailable + LayerLimitsCPU=Enforced", memOnly)
	}

	// Both layers, not just LayerLimits: they are required per requested limit now, so a
	// cpu-only manifest missing the cpu line would reach admission with an empty
	// required report and run unbounded.
	no := limitsLayers(false, "no scope here", enforce.Enforced, "", enforce.Enforced, "")
	if len(no) != 2 {
		t.Fatalf("no scope: got %+v, want both limits layers", no)
	}
	for _, l := range no {
		if l.State != enforce.Unavailable || l.Reason != "no scope here" {
			t.Errorf("no scope: %s = %+v, want Unavailable carrying the scope reason", l.Layer, l)
		}
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
		{"no seccomp", false, true, enforce.Unavailable, enforce.Unavailable, "cannot install the exec-block filter"},
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

// The exec block is soft by construction on every host that has it: execveat is left
// open because the launcher execs the target through it. doctor is the one place that
// tells the whole truth about a host, so an Enforced exec-block row that says nothing
// leaves a reader who never runs validate believing exec is closed.
func TestEnforcedExecBlockDisclosesTheExecveatSeam(t *testing.T) {
	got := execLayers(true, true)
	if got[0].State != enforce.Enforced {
		t.Fatalf("exec = %v, want Enforced", got[0].State)
	}
	if !strings.Contains(got[0].Consequences, "execveat") {
		t.Errorf("enforced exec-block hides the seam: %q", got[0].Consequences)
	}
	// Reason stays empty on an Enforced layer, so the disclosure must not lead with the
	// space a bare join would leave.
	if d := got[0].Disclosure(); d != got[0].Consequences {
		t.Errorf("disclosure = %q, want the consequences alone", d)
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
			enforce.LayerExec, enforce.Unavailable, "cannot install the exec-block filter",
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

// Five Landlock rights the degraded tier discloses as residuals, each restricted only
// from a given ABI. The grid over them is finite, so every cell gets an assertion rather
// than one spot test per clause: the missing TCP-connect row is what let the report claim
// a fence Landlock does not have below ABI 4 on every kernel from 5.13 to 6.6.
//
// Each right is checked in both directions. Unrestricted, the Consequences must name the
// residual - silence there is the tier's disclosure failing at the only job it has.
// Restricted, they must not still describe it as open, and where the restricted case has
// a positive claim of its own that claim must not appear when the right is absent.
func TestDegradedConsequencesDiscloseEveryResidualRight(t *testing.T) {
	const nsReason = "userns blocked here"
	rights := []struct {
		name string
		// open is what the Consequences must say when the right is unrestricted, and must
		// not say when it is restricted.
		open string
		// closed is the claim only a kernel that restricts the right may make. Empty where
		// the restricted case simply drops the clause, or where the sentence is shared with
		// another right and cannot be read off this one alone (resolve_unix, whose clause
		// also turns on IPC scoping).
		closed string
	}{
		{"truncate", "cannot restrict truncate", ""},
		{"ioctl_dev", "cannot restrict ioctl on device files", ""},
		{"resolve_unix", "cannot restrict connect(2) on pathname", ""},
		{"scoped IPC", "see and signal same-user processes", "but not signal them"},
		{"net TCP", "cannot restrict TCP connect", "Landlock denies TCP connect"},
	}
	for cell := 0; cell < 1<<len(rights); cell++ {
		restricted := make([]bool, len(rights))
		var name []string
		for i := range rights {
			restricted[i] = cell&(1<<i) != 0
			if !restricted[i] {
				name = append(name, rights[i].name)
			}
		}
		unrestrictedIn := "none"
		if len(name) > 0 {
			unrestrictedIn = strings.Join(name, "+")
		}
		t.Run("unrestricted="+unrestrictedIn, func(t *testing.T) {
			l := filesystemLayer(namespacesBlocked, nsReason, true, restricted[0], restricted[1], restricted[2], restricted[3], restricted[4], true)
			if l.State != enforce.Degraded {
				t.Fatalf("state = %v, want Degraded", l.State)
			}
			for i, r := range rights {
				if restricted[i] {
					if strings.Contains(l.Consequences, r.open) {
						t.Errorf("%s is restricted on this kernel and the report still discloses it as open (%q): %q", r.name, r.open, l.Consequences)
					}
					if r.closed != "" && !strings.Contains(l.Consequences, r.closed) {
						t.Errorf("%s is restricted and the report does not say so (%q): %q", r.name, r.closed, l.Consequences)
					}
					continue
				}
				if !strings.Contains(l.Consequences, r.open) {
					t.Errorf("%s is unrestricted on this kernel and the report does not disclose the residual (%q): %q", r.name, r.open, l.Consequences)
				}
				if r.closed != "" && strings.Contains(l.Consequences, r.closed) {
					t.Errorf("%s is unrestricted and the report claims more than the ABI provides (%q): %q", r.name, r.closed, l.Consequences)
				}
			}
		})
	}
}

// The degraded tier's unix-socket disclosure has to track what the kernel can actually
// restrict, not repeat one fixed sentence. From ABI 6 the tier scopes the abstract
// namespace and from ABI 9 the ruleset handles resolve_unix, granting it only on the
// write set, so telling the operator either kind of socket is reachable would be false -
// and on a kernel below those it is true, and the residual has to say so. The directions
// are asserted together because the failure that matters is the report contradicting
// itself.
func TestFilesystemLayerUnixSocketDisclosureTracksTheABI(t *testing.T) {
	const nsReason = "userns blocked here"
	restricted := filesystemLayer(namespacesBlocked, nsReason, true, true, true, true, true, true, true).Disclosure()
	if strings.Contains(restricted, "including an abstract-namespace one no grant is needed to reach") {
		t.Errorf("with resolve_unix restricted the reason still claims any unix socket is reachable: %q", restricted)
	}
	if !strings.Contains(restricted, "an abstract-namespace one by Landlock's IPC scoping") {
		t.Errorf("with IPC scoping applied the reason must say the abstract namespace is denied: %q", restricted)
	}
	// The one denial an operator cannot diagnose from the target's own behaviour, so the
	// report has to name it rather than leave it to "a pathname socket is denied".
	if !strings.Contains(restricted, "/dev/log") {
		t.Errorf("the silent syslog denial must be named: %q", restricted)
	}
	unrestricted := filesystemLayer(namespacesBlocked, nsReason, true, true, true, false, true, true, true).Disclosure()
	if !strings.Contains(unrestricted, "any host daemon socket its path names") {
		t.Errorf("below ABI 9 the pathname-socket residual must be disclosed: %q", unrestricted)
	}
	// Below ABI 6 the abstract namespace is reachable whatever the file grants say, and it
	// is the residual no other layer covers, so the report must not go quiet about it.
	unscoped := filesystemLayer(namespacesBlocked, nsReason, true, true, true, false, false, true, true).Disclosure()
	if !strings.Contains(unscoped, "including an abstract-namespace one no grant is needed to reach") {
		t.Errorf("below ABI 6 the abstract-socket residual must be disclosed: %q", unscoped)
	}
	if strings.Contains(unscoped, "IPC scoping denies") {
		t.Errorf("below ABI 6 nothing scopes signals and the reason must not claim otherwise: %q", unscoped)
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
		l := filesystemLayer(namespacesBlocked, nsReason, landlock, true, true, true, true, true, true)
		state, reason := l.State, l.Reason
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

// On NixOS the interpreter and its whole library closure live in the Nix store, so
// whether the degraded tier's entire read set includes it is the difference between a
// working run and an interpreter that cannot load its stdlib. The question goes through
// the sandbox's host seam like every other one in the file, so the answer is testable on
// a host that has no /nix - which is every CI host this runs on.
func TestDegradedSystemPathsGrantTheNixStoreWhenPresent(t *testing.T) {
	sb := testSandbox()
	sb.exists = func(p string) bool { return p == "/nix" }
	sb.resolve = func(p string) string {
		if p == "/nix" {
			return "/mnt/nix"
		}
		return p
	}
	reads, _ := degradedSystemPaths(sb)
	if !slices.Contains(reads, "/mnt/nix") {
		t.Errorf("reads = %v, want the resolved Nix store", reads)
	}

	sb.exists = func(string) bool { return false }
	reads, _ = degradedSystemPaths(sb)
	if slices.Contains(reads, "/mnt/nix") {
		t.Errorf("reads = %v, want no Nix store on a host without one", reads)
	}
}

// The host remedy a userns refusal leads with is a sysctl, which a CI engineer running
// bento in a container cannot set - and inside docker the runtime's own seccomp and
// AppArmor profiles block the namespace anyway. Which of the three userns branches this
// host takes depends on its sysctls, so every one of them has to carry the container
// remedy for the diagnosis to be actionable wherever it lands.
//
// All three flags, not the two this refusal is about: lifting the seccomp and AppArmor
// ones grants the namespace and lands the reader on the proc-mask refusal instead, so a
// remedy naming only those costs a build-and-run cycle to discover the third.
func TestClassifyUnshareNamesTheContainerRemedy(t *testing.T) {
	for _, out := range []string{
		"bwrap: No permissions to create new user namespace",
		"bwrap: Creating new namespace failed: Permission denied",
		"bwrap: setting up uid map: Permission denied",
	} {
		state, reason := classifyUnshare(&usernsError{output: out, err: errors.New("exit status 1")})
		if state != namespacesBlocked {
			t.Fatalf("state = %v, want namespacesBlocked", state)
		}
		for _, want := range []string{"--security-opt seccomp=unconfined", "--security-opt apparmor=unconfined", "--security-opt systempaths=unconfined"} {
			if !strings.Contains(reason, want) {
				t.Errorf("reason %q does not name %q", reason, want)
			}
		}
		if strings.Contains(reason, ".;") || strings.Contains(reason, "..") {
			t.Errorf("reason runs its clauses together: %q", reason)
		}
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
			// bwrap's generic wording for the same refusal: unshare(2) returned EPERM and
			// the message names the namespace without qualifying it "user".
			"namespace creation refused",
			&usernsError{output: "bwrap: Creating new namespace failed: Permission denied", err: errors.New("exit status 1")},
			namespacesBlocked, "cannot create an unprivileged user namespace", "",
		},
		{
			// The namespace was created and the host refused the uid-map write, which
			// leaves the sandbox with no usable identity in it. Still a refusal, still
			// named, so still blocked - the errno is not what decides.
			"uid map refused",
			&usernsError{output: "bwrap: setting up uid map: Permission denied", err: errors.New("exit status 1")},
			namespacesBlocked, "cannot create an unprivileged user namespace", "",
		},
		{
			// bwrap words exhaustion with the same words it words a refusal, so a namespace
			// name alone cannot decide it. The host may grant the namespace on the next
			// attempt, and the AppArmor remedy the blocked branch prints is about a sysctl
			// that is not set here.
			"the namespace limit was exhausted",
			&usernsError{output: "bwrap: Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)", err: errors.New("exit status 1")},
			namespacesUnknown, "is unknown", "unprivileged user namespace",
		},
		{
			"the namespace failed under load",
			&usernsError{output: "bwrap: Creating new namespace failed: Resource temporarily unavailable", err: errors.New("exit status 1")},
			namespacesUnknown, "is unknown", "unprivileged user namespace",
		},
		{
			// The kernel has no user namespaces at all. bwrap says so with no errno
			// appended, so this shape is matched on its own wording.
			"the kernel supports no user namespaces",
			&usernsError{output: "bwrap: Creating new namespace failed, likely because the kernel does not support user namespaces.  bwrap must be installed setuid on such systems.", err: errors.New("exit status 1")},
			namespacesBlocked, "cannot create an unprivileged user namespace", "",
		},
		{
			// canUnshare execs its canary INSIDE the sandbox, so a noexec mount, mode 000
			// or an AppArmor exec denial produces this - a "Permission denied" that names
			// no namespace and says nothing about whether the host grants one. Reading it
			// as blocked selected the Landlock-only tier and the AppArmor remediation on a
			// host where bwrap works.
			"canary could not be exec'd",
			&usernsError{output: "bwrap: execvp true: Permission denied", err: errors.New("exit status 1")},
			namespacesUnknown, "is unknown", "unprivileged user namespace",
		},
		{
			// A bind refused inside a granted namespace belongs with the other mount
			// failures, not with the namespace refusals: bwrap words it "Can't bind
			// mount", which the base-mount prefix test has to spell separately.
			"a bind mount refused inside the namespace",
			&usernsError{output: "bwrap: Can't bind mount /oldroot/tmp on /newroot/tmp: Permission denied", err: errors.New("exit status 1")},
			namespacesBlocked, "cannot set up the mounts", "unprivileged user namespace",
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
			namespacesBlocked, "cannot set up the mounts", "unprivileged user namespace",
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

// A hardened CI runner sets user.max_user_namespaces to zero, and bwrap then dies with
// "nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)". That was read as
// an unclassified probe failure - the operator got "unknown" and no next action at all,
// on the one host condition with a one-line remedy. It is a namespace refusal: the kernel
// is declining to create one, permanently and for this user.
//
// The allowance is what makes the call, not the wording. bwrap words genuine exhaustion -
// nesting depth, or load - with the same sentence, and that measures nothing about the
// host, so it must keep falling through to unknown rather than costing a user the full
// sandbox on a machine that supports it.
func TestExhaustedAllowanceIsARefusalOnlyAtZero(t *testing.T) {
	const out = "bwrap: Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)"

	reason := exhaustedAllowanceReason(out, true)
	if reason == "" {
		t.Fatal("ENOSPC with the allowance at zero is the kernel refusing, not an unclassified failure")
	}
	for _, want := range []string{"user.max_user_namespaces", "sysctl -w"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not name %q; a CI engineer has to be able to tell their platform team what to change", reason, want)
		}
	}

	if got := exhaustedAllowanceReason(out, false); got != "" {
		t.Errorf("exhaustion under a nonzero allowance is transient and measures nothing about the host; got %q", got)
	}
	// A refusal shape that is not exhaustion at all must not be diverted into this branch
	// even on a host whose allowance happens to be zero: the AppArmor diagnosis below is
	// the one that names the cause there.
	if got := exhaustedAllowanceReason("bwrap: No permissions to create new user namespace", true); got != "" {
		t.Errorf("only the exhaustion wording belongs to this branch; got %q", got)
	}
}

// The systempaths remedy is the whole value of the procfs diagnosis to a CI engineer,
// and it is read at the head of a block that runs past twenty lines once the degraded
// tier's consequences follow it. Present is not enough at that length: a flag below
// that much prose is one nobody scanning the block reaches, so it has to stay ahead of
// the diagnosis it remedies, through both of the joins that build the block.
func TestProcMountRemedyLeadsTheReason(t *testing.T) {
	_, reason := classifyUnshare(&usernsError{
		output: "bwrap: Can't mount proc on /newroot/proc: Operation not permitted",
		err:    errors.New("exit status 1"),
	})
	remedy := strings.Index(reason, "--security-opt systempaths=unconfined")
	if remedy < 0 {
		t.Fatalf("reason %q drops the remedy entirely", reason)
	}
	diagnosis := strings.Index(reason, "the mount the sandbox's root filesystem needs was refused")
	if diagnosis < 0 {
		t.Fatalf("reason %q drops the diagnosis the remedy is meant to lead", reason)
	}
	if remedy > diagnosis {
		t.Errorf("remedy at %d trails the diagnosis at %d, so it reads as a footnote: %q", remedy, diagnosis, reason)
	}
	if !strings.Contains(reason[:remedy], "docker") {
		t.Errorf("nothing before the flag says which runtime it belongs to: %q", reason)
	}
	// Two joins sit between this reason and the block the reader actually sees:
	// joinReason appends the tier's clause after it, and Disclosure appends the
	// consequences after that. The flag leads only if both keep the reason in front.
	block := filesystemLayer(namespacesBlocked, reason, true, true, true, true, true, true, true).Disclosure()
	flag, tier := strings.Index(block, "--security-opt systempaths=unconfined"), strings.Index(block, "confinement falls back")
	if flag < 0 || tier < 0 {
		t.Fatalf("the degraded block dropped the flag or the tier clause: %q", block)
	}
	if flag > tier {
		t.Errorf("flag at %d trails the tier clause at %d, so it does not lead the block: %q", flag, tier, block)
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
