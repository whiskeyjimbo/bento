//go:build linux

package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/internal/seccomp"
)

// The tier differential. Every restriction the bwrap tier applies is a question about
// the degraded tier: does the degraded tier apply a counterpart, or is the restriction
// simply dropped? The grid in docs/state-grid-launcher-order.md walks that question
// cell by cell; this is its executable half, and it exists so a fence answers it by
// MEASUREMENT rather than by a code comment.
//
// The shape is one child binary, three arms, and a table of probes:
//
//   - unfenced   - no confinement at all. The positive control, and the row that makes
//     the other two mean something: without it "denied" is indistinguishable
//     from a probe whose subject was never set up.
//   - degraded   - the degraded tier's own fences, installed in RunDegraded's order.
//   - bwrap      - the bwrap tier's namespace and capability flags, no seccomp: those
//     three blocks are degraded-only by design (degraded.go:212-225).
//
// A new fence is a row here, not a new test. Add a probe to runTierProbes and a line
// to the table; the arms and the plumbing are already paid for.
const (
	sentinelTierArm = "BENTO_TEST_TIER_ARM"
	sentinelShmKey  = "BENTO_TEST_SHM_KEY"
	// sentinelUnderScript marks the inner run of the script(1) re-exec below, and is the
	// recursion guard: without it the inner run would re-exec itself forever.
	sentinelUnderScript = "BENTO_TEST_TIER_PTY"
	// sentinelHostNS prefixes one variable per namespace carrying the TEST PROCESS's
	// namespace identity, which is the host's. A child compares its own against it; the
	// ids are kernel inode numbers, so neither side can be hardcoded.
	sentinelHostNS = "BENTO_TEST_HOST_NS_"

	armUnfenced = "unfenced"
	armDegraded = "degraded"
	armBwrap    = "bwrap"

	// hostSegmentMarker is what the parent writes into the host's System V segment. A
	// child that prints it back read another process's memory.
	hostSegmentMarker = "HOST-SEGMENT-CONTENT"
)

// namespaceProbes are the namespaces whose identity a row compares against the host's.
// Each is a bwrap --unshare-<name> flag, and in every row the degraded tier shares the
// host's. Only ipc has a degraded counterpart at all, and it is a different KIND of fence:
// BlockProcessReach denies the System V calls rather than giving the target a namespace of
// its own, which is why the two ipc rows measure different things - identity here, reach in
// sysv-ipc.
var namespaceProbes = []string{"pid", "uts", "cgroup", "ipc"}

// tierProbe is one restriction, and what each tier is expected to give the target.
// unfenced is the control: a row whose unfenced value equals its degraded value is
// a row where the degraded tier applies nothing at all.
type tierProbe struct {
	name string
	// why records the grid cell or bead this row came from, so a row that starts
	// failing says what it was protecting.
	why      string
	unfenced string
	degraded string
	bwrap    string
	// hostFact, when set, names a host precondition. A row whose precondition the host
	// does not meet reports "n/a" from every arm and is not asserted.
	hostFact string
}

var tierProbes = []tierProbe{
	{
		name:     "sysv-ipc",
		why:      "bv2-xwz5v / grid row 11: --unshare-ipc hides the host's segments; BlockProcessReach is the degraded counterpart",
		unfenced: hostSegmentMarker,
		degraded: "denied",
		bwrap:    "denied",
	},
	{
		name: "cap-bounding-set",
		// The degraded cell equalling the unfenced one is the finding, not a hole in the
		// arm: PR_CAPBSET_DROP needs CAP_SETPCAP in a user namespace this tier could not
		// create, so the drop is attempted and fails. What the tier does instead - refuse
		// the run when the residual is live - is exercised by
		// TestRunDegradedRefusesWithoutTheRealFences/capability-bound, which no arm here
		// can reach without privilege.
		// The bwrap cell is "empty" on this arm whether or not --cap-drop ALL is passed:
		// bwrap applies that flag only when running privileged, and an unprivileged bwrap
		// empties the bounding set by default. So the row measures the SET, which is what
		// the differential is about, and not the flag that would empty it on a privileged
		// host - which nothing here can reach.
		why:      "bv2-7nv8y / grid row 10: the bwrap tier leaves it empty; the degraded tier attempts the drop, cannot make it, and refuses a privileged run instead",
		unfenced: "nonempty",
		degraded: "nonempty",
		bwrap:    "empty",
	},
	{
		name: "inet-socket",
		// bwrap reads "permitted" and that is not a scandal: --unshare-net is appended by
		// the network layer (internal/linux/args.go), not carried in the
		// namespaceFlags/sessionFlags set this arm models, so the real bwrap tier's
		// network fence is out of the arm's scope by construction. What
		// the row pins is the other side - that the degraded tier's substitute is live.
		why:      "grid row 2: the degraded tier has no netns, so BlockEgress is the whole IP-egress fence; socket(2) is its chokepoint",
		unfenced: "permitted",
		degraded: "denied",
		bwrap:    "permitted",
	},
	{
		name:     "pid-namespace",
		why:      "grid row 3: --unshare-pid gives the bwrap tier its own process table; the degraded tier shares the host's and substitutes BlockProcessReach, which the sysv-ipc row measures",
		unfenced: "shared",
		degraded: "shared",
		bwrap:    "separate",
	},
	{
		name: "ipc-namespace",
		// Redundant with sysv-ipc for pinning --unshare-ipc: both cells go red when the
		// flag is dropped (measured by ablation, not reasoned). Carried anyway because the
		// two measure different things - sysv-ipc measures REACH, which the degraded tier
		// denies with seccomp and the bwrap tier with a namespace, so it cannot say WHICH
		// mechanism answered. This row measures IDENTITY, so it stays red if the bwrap arm
		// ever grows a filter that denies reach without a namespace.
		why:      "grid rows 3 and 11: --unshare-ipc gives the bwrap tier its own System V namespace; the degraded tier shares the host's and substitutes BlockProcessReach, which the sysv-ipc row measures",
		unfenced: "shared",
		degraded: "shared",
		bwrap:    "separate",
	},
	{
		name: "process-vm-read",
		// The bwrap cell reading "permitted" is a fact about the TIER, not a gap in the arm,
		// and it is not inet-socket's shape: that cell is permitted because the arm omits
		// --unshare-net, a flag the real tier does pass. Here the real tier passes nothing
		// that would deny this. It does install seccomp - BlockIoUring and
		// installExecFilter, both in Run - but no filter of its own lists
		// process_vm_readv, and BlockProcessReach is degraded-only (degraded.go:109).
		// --unshare-pid only decides WHICH processes can be named, not whether the call is
		// reachable.
		//
		// This row produces no red the suite does not already have: dropping
		// process_vm_readv from the filter list reds
		// internal/seccomp/process_reach_linux_test.go, and dropping BlockProcessReach from
		// the degraded arm reds sysv-ipc as well. It is here so the table NAMES the
		// memory-read half of BlockProcessReach in the same place as the rest of the
		// differential, rather than leaving that fence represented only by the System V
		// calls - legibility, not a unique red.
		why:      "grid row 3, cross-process reach: BlockProcessReach is the degraded tier's whole substitute for the pid namespace it cannot create, and process_vm_readv is the memory-read half of it; sysv-ipc pins only the System V half",
		unfenced: "permitted",
		degraded: "denied",
		bwrap:    "permitted",
	},
	{
		name:     "uts-namespace",
		why:      "grid row 11: --unshare-uts is bwrap-only and has no degraded substitute at all",
		unfenced: "shared",
		degraded: "shared",
		bwrap:    "separate",
	},
	{
		name: "cgroup-namespace",
		// This row is also what makes --unshare-cgroup's presence in the arm load-bearing
		// (bv2-6m2dq): drop the flag and bwrap reads "shared" here.
		why:      "grid row 11: --unshare-cgroup is bwrap-only and has no degraded substitute at all",
		unfenced: "shared",
		degraded: "shared",
		bwrap:    "separate",
	},
	{
		name:     "controlling-terminal",
		why:      "bv2-lpuue / grid row 6: --new-session leaves none; the degraded substitute denies two ioctls and leaves the terminal attached",
		hostFact: "a controlling terminal",
		unfenced: "attached",
		degraded: "attached",
		bwrap:    "detached",
	},
	{
		name:     "tty-inject-ioctl",
		why:      "bv2-lpuue: what the degraded substitute DOES cover, pinned so a widening or a regression is visible; the bwrap cell is stated rather than measured (runTierProbes) because --new-session leaves no terminal to try the ioctl on",
		hostFact: "a controlling terminal",
		unfenced: "permitted",
		degraded: "denied",
		bwrap:    "permitted",
	},
}

// The grid's thirteen restrictions as data rather than as prose, so a fourteenth fence
// cannot be added without saying what covers it. Each entry resolves to probe rows in the
// table above or to a NAMED exemption, and TestEveryRestrictionIsAccountedFor is what
// makes that mandatory: an entry with neither fails, naming the restriction.
//
// Why data and not a comment: the launcher grid counts a code comment as a NON-channel and
// a comment-only residual as state D, the forbidden direction. Every sweep finding of the
// form "one tier has it, the sibling does not, nothing recorded the drop" has that shape,
// and a paragraph listing the restrictions is exactly what stops noticing when the list
// grows.
type exemption string

const (
	// The tiers apply the same thing, so a differential row would assert nothing.
	exemptIdentical exemption = "identical in both tiers"
	// Real in both tiers and different, but outside what the arms model. Widening the
	// arms is the price, and it costs the differential its property that each arm models
	// exactly one documented flag set.
	exemptOutOfArmScope exemption = "outside the arms' declared scope"
	// Not a property a probe running inside the child can ask about at all.
	exemptNotObservable exemption = "not observable from inside the child"
)

// The disclosure channels a restriction's exemption may cite, and the whole list of them:
// a channel is somewhere an OPERATOR reads what a run did, which a code comment is not.
// Checked against this set rather than accepted as free text, because "it is explained in
// a comment" is state D wearing the exemption's clothes.
type channel string

const (
	channelNone channel = ""
	// internal/launcher/applied.go, written before the target is reached.
	channelAppliedReport channel = "the applied-layer report"
	// internal/linux/degraded.go's degradedProbe, which rewrites LayerFilesystem and
	// LayerNetwork with the degraded tier's own consequences.
	channelDegradedProbe channel = "degradedProbe's LayerFilesystem/LayerNetwork rewrite"
	// Exposed and ShieldedGrants on the Result: what a bwrap run would have shielded and
	// this one did not.
	channelExposedShields channel = "Exposed/ShieldedGrants on the Result"
)

var realChannels = []channel{channelAppliedReport, channelDegradedProbe, channelExposedShields}

// restriction is one row of docs/state-grid-launcher-order.md's grid A.
type restriction struct {
	row  int
	name string
	// probes names the rows of tierProbes that measure this restriction. Non-empty means
	// the restriction is covered and no exemption is needed.
	probes []string
	// why the restriction has no probe row. Required when probes is empty.
	exempt exemption
	reason string
	// discloses names where an operator learns about the gap, when the exemption claims
	// one at all. It must be a real channel; see channel.
	discloses channel
}

var restrictions = []restriction{
	{
		row:    1,
		name:   "filesystem fence (mount ns + binds + deny-list vs Landlock path ruleset)",
		exempt: exemptIdentical,
		reason: "both tiers confine, by different mechanisms, and the degraded arm omits Landlock on purpose (see TestTierProbeHelper) because it would confine the probes' own reads - so any row would measure the arm's omission rather than the tier's",
		// The mount-namespace half IS dropped on the degraded tier, and that is recorded
		// rather than left to a comment, which is what keeps this an exemption and not a
		// silent drop.
		discloses: channelExposedShields,
	},
	{
		row:    2,
		name:   "network / egress fence (netns + bridge vs seccomp egress block)",
		probes: []string{"inet-socket"},
	},
	{
		row:    3,
		name:   "pid namespace / cross-process reach",
		probes: []string{"pid-namespace", "process-vm-read"},
	},
	{
		row:       4,
		name:      "exec-block seccomp filter",
		exempt:    exemptIdentical,
		reason:    "one shared installExecFilter, called by both tiers; the degraded arm omits it for the same reason as Landlock",
		discloses: channelAppliedReport,
	},
	{
		row:       5,
		name:      "Landlock",
		exempt:    exemptIdentical,
		reason:    "both tiers apply it and the degraded arm omits it because it would confine the probes' own reads; the asymmetry that remains is the allowed direction, bwrap warns and proceeds where degraded is fatal",
		discloses: channelAppliedReport,
	},
	{
		row:    6,
		name:   "terminal detach (--new-session vs TIOCSTI/TIOCLINUX block)",
		probes: []string{"controlling-terminal", "tty-inject-ioctl"},
	},
	{
		row:    7,
		name:   "pseudo-FS: /proc, /dev, /tmp",
		exempt: exemptOutOfArmScope,
		reason: "the bwrap arm is --dev-bind / / and models namespaceFlags+sessionFlags only; pseudoFSFlags is outside it. This is also why the arm sees the host's process table despite --unshare-pid, which is worth knowing before anyone writes a \"host process table\" row and misreads the result",
	},
	{
		row:    8,
		name:   "environment / HOME / TMPDIR / proxy vars",
		exempt: exemptNotObservable,
		reason: "both tiers build from the shared sandboxEnv and the child sees whatever the parent passed, so a row would measure this test's own env plumbing",
	},
	{
		row:    9,
		name:   "inherited FDs + stdio refusal + non-dumpable",
		exempt: exemptNotObservable,
		reason: "the FD drop and the stdio refusal both happen in the parent before exec. The non-dumpable half is set by both tiers (Run at launcher.go and RunDegraded at degraded.go), so mirroring it into the degraded arm alone would MANUFACTURE a difference production does not have; it is also a property of the launcher process rather than of the target, since execve resets dumpable",
	},
	{
		row:    10,
		name:   "capability bounding set",
		probes: []string{"cap-bounding-set"},
	},
	{
		row:    11,
		name:   "IPC / UTS / cgroup namespaces",
		probes: []string{"sysv-ipc", "ipc-namespace", "uts-namespace", "cgroup-namespace"},
	},
	{
		row:    12,
		name:   "limits (systemd scope) + teardown",
		exempt: exemptNotObservable,
		reason: "neither the scope limits nor the teardown is a property of the child",
	},
	{
		row:    13,
		name:   "in-sandbox self-verification",
		exempt: exemptNotObservable,
		reason: "it IS the verification, not a restriction a probe can ask about",
	},
}

// The enforcement half of the differential, and the reason the list above is data: today a
// fourteenth fence would be added to one tier, get no row and no exemption, and nothing
// would notice. This fails when that happens, and names the restriction.
//
// It checks both directions. An unclaimed tierProbe is the same drift read the other way -
// a row measuring something the grid no longer lists, which is how a probe outlives the
// restriction it was written for.
//
// The ceiling here is roughly 7 of 13 rather than 13 of 13, and that is the honest number:
// four restrictions are not comparable as the arms are built and four are not observable
// from inside the child at all. Raising it means growing the arms to carry Landlock and
// pseudoFSFlags, which costs the differential its property that each arm models exactly one
// documented flag set.
func TestEveryRestrictionIsAccountedFor(t *testing.T) {
	claimed := map[string]int{}
	for _, r := range restrictions {
		if len(r.probes) > 0 {
			if r.exempt != "" || r.reason != "" || r.discloses != channelNone {
				t.Errorf("row %d (%s) has probe rows AND an exemption; a covered restriction is not also exempt", r.row, r.name)
			}
			for _, name := range r.probes {
				if !slices.ContainsFunc(tierProbes, func(p tierProbe) bool { return p.name == name }) {
					t.Errorf("row %d (%s) names probe row %q, which is not in tierProbes: the restriction is recorded as covered by a row that does not exist", r.row, r.name, name)
				}
				claimed[name] = r.row
			}
			continue
		}
		// The whole of the bead: neither a row nor an exemption is the state the list
		// exists to make impossible.
		if r.exempt == "" {
			t.Errorf("row %d (%s) has no probe row and no exemption: add a row to tierProbes, or say which of the three categories it falls in and why", r.row, r.name)
			continue
		}
		if !slices.Contains([]exemption{exemptIdentical, exemptOutOfArmScope, exemptNotObservable}, r.exempt) {
			t.Errorf("row %d (%s) claims exemption %q, which is not one of the three categories", r.row, r.name, r.exempt)
		}
		if r.reason == "" {
			t.Errorf("row %d (%s) is exempt with no reason; the category alone is the claim this repo asks for a reason for", r.row, r.name)
		}
		if r.discloses != channelNone && !slices.Contains(realChannels, r.discloses) {
			t.Errorf("row %d (%s) cites %q as a disclosure channel, and that is not one: the grid counts a code comment as a non-channel and a comment-only residual as the forbidden direction", r.row, r.name, r.discloses)
		}
	}
	for _, p := range tierProbes {
		if _, ok := claimed[p.name]; !ok {
			t.Errorf("probe row %q is claimed by no restriction: either it outlived the restriction it measures, or the grid gained one the list does not carry", p.name)
		}
	}
}

func TestTierDifferential(t *testing.T) {
	if reexecUnderTerminal(t) {
		return
	}
	key, cleanup := hostSegment(t)
	defer cleanup()

	got := map[string]map[string]string{}
	for _, arm := range []string{armUnfenced, armDegraded, armBwrap} {
		got[arm] = runTierArm(t, arm, key)
	}

	for _, p := range tierProbes {
		t.Run(p.name, func(t *testing.T) {
			// Unreachable rather than skipped: reexecUnderTerminal has already given the
			// run a controlling terminal or refused to proceed, so an arm reporting n/a
			// here means the terminal the rows were promised went missing between the two
			// - which is the one outcome a skip would hide, and the whole of bv2-ciz11.
			if got[armUnfenced][p.name] == "n/a" {
				t.Fatalf("%s needs %s and this run was given one, yet the unfenced arm reported n/a: "+
					"the arm lost the terminal rather than measuring it", p.name, p.hostFact)
			}
			for arm, want := range map[string]string{
				armUnfenced: p.unfenced, armDegraded: p.degraded, armBwrap: p.bwrap,
			} {
				if g := got[arm][p.name]; g != want {
					t.Errorf("%s under the %s tier = %q, want %q\n%s", p.name, arm, g, want, p.why)
				}
			}
		})
	}
}

// reexecUnderTerminal makes sure the rows that measure the terminal fence have a terminal
// to measure, by re-running this one test under script(1) when the invocation had none. It
// reports whether it did so, in which case the caller has nothing left to do.
//
// Two rows compare what --new-session takes away against what the degraded tier's ioctl
// block leaves, and both need a real controlling terminal. `go test` gives none, so before
// this they skipped, and a CI table reported PASS having asserted nothing about the fence
// that landed with them. Giving the run a terminal is the fix rather than failing without
// one: a terminal is a property of how the test was invoked.
//
// script(1) is used rather than a pty allocated here: it forks, setsid()s and TIOCSCTTY's
// the slave itself, so this process gets a terminal it genuinely owns and bwrap's
// --new-session still genuinely detaches from it. A pty this process merely held open
// would have to be claimed by the child, and claiming it under the bwrap arm - already
// setsid'd, so a session leader with no terminal - would hand that arm the very thing the
// row exists to find absent.
//
// A missing script IS skipMissingDep's case, and that is not the fatality the bead
// forbids: script is util-linux, a package a host installs, where a controlling terminal
// is not. So make test (BENTO_REQUIRE_TEST_DEPS=1) fails loudly for it and a dev box skips.
func reexecUnderTerminal(t *testing.T) bool {
	t.Helper()
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		tty.Close()
		return false
	}
	if os.Getenv(sentinelUnderScript) != "" {
		t.Fatal("re-executed under script(1) and still have no controlling terminal; " +
			"the terminal rows cannot be measured and must not report a pass")
	}
	script, err := exec.LookPath("script")
	if err != nil {
		skipMissingDep(t, "this run has no controlling terminal and script(1) is not installed to give it one, "+
			"so the terminal rows would measure nothing: %v", err)
		return true
	}
	inner := shellQuote(os.Args[0]) + " -test.run '^TestTierDifferential$' -test.timeout=4m"
	if testing.Verbose() {
		inner += " -test.v"
	}
	cmd := exec.Command(script, "-q", "-e", "-c", inner, "/dev/null")
	cmd.Env = append(os.Environ(), sentinelUnderScript+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the differential re-run under script(1) failed with %v:\n%s", err, out)
	} else {
		t.Logf("ran under script(1), which supplied the controlling terminal this invocation lacked:\n%s", out)
	}
	return true
}

// shellQuote wraps s for the single command string script(1) hands to sh -c. The test
// binary's path is chosen by the toolchain, under a temporary directory this test does
// not pick, so it is not assumed to be free of shell metacharacters.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runTierArm runs the probe child under one arm and returns its probe results. A
// missing probe reads as the empty string, which no row expects, so a child that died
// partway through fails the rows it never reached rather than passing them.
func runTierArm(t *testing.T, arm, key string) map[string]string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^TestTierProbeHelper$")
	cmd.Env = append(os.Environ(), sentinelTierArm+"="+arm, sentinelShmKey+"="+key)
	for _, ns := range namespaceProbes {
		link, err := os.Readlink("/proc/self/ns/" + ns)
		if err != nil {
			t.Fatalf("reading the host's %s namespace identity: %v", ns, err)
		}
		cmd.Env = append(cmd.Env, sentinelHostNS+ns+"="+link)
	}
	// The probes read the child's own controlling terminal, which it inherits through
	// stdin. exec.Cmd leaves stdin at /dev/null otherwise, so every terminal row would
	// report "detached" on every arm and assert nothing.
	cmd.Stdin = os.Stdin
	if arm == armBwrap {
		bwrap, err := exec.LookPath("bwrap")
		if err != nil {
			skipMissingDep(t, "bwrap is not installed, so there is no bwrap tier to compare against: %v", err)
		}
		// The bwrap tier's own restriction set for the cells this table covers
		// (internal/linux/args.go namespaceFlags and sessionFlags), over a plain bind of
		// the host so the test binary and the Go toolchain's paths stay reachable. No
		// seccomp: the three blocks in RunDegraded are the degraded tier's substitutes,
		// not shared layers, so installing them here would erase the differential.
		//
		// The list is hand-copied because namespaceFlags is unexported in internal/linux
		// and this package cannot import it - the dependency runs the other way - so the
		// arm cannot be derived from it. Five of the seven flags are pinned by a row that
		// reads the unfenced value if the flag goes missing: --unshare-ipc by sysv-ipc and
		// ipc-namespace both, --unshare-pid, --unshare-uts and --unshare-cgroup by their
		// namespace rows, and --new-session by controlling-terminal. The other two cannot be pinned from an
		// unprivileged run and are carried for fidelity to namespaceFlags: bwrap creates a
		// user namespace without --unshare-user, and empties the bounding set without
		// --cap-drop ALL, which it applies only when privileged.
		cmd.Args = append([]string{
			bwrap, "--dev-bind", "/", "/",
			"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
			"--cap-drop", "ALL", "--new-session",
		}, cmd.Args...)
		cmd.Path = bwrap
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s arm exited with %v:\n%s", arm, err, out)
	}
	res := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if name, value, ok := strings.Cut(strings.TrimPrefix(line, "PROBE "), " "); ok && strings.HasPrefix(line, "PROBE ") {
			res[name] = value
		}
	}
	return res
}

func TestTierProbeHelper(t *testing.T) {
	arm := os.Getenv(sentinelTierArm)
	if arm == "" {
		t.Skip("child helper for TestTierDifferential")
	}
	if arm == armDegraded {
		// RunDegraded's order, minus the exec filter and Landlock: neither bears on the
		// rows here, and Landlock would confine the probes' own reads. The capability
		// fence below IS included, so the cap-bounding-set row measures the set after a
		// real drop attempt rather than one the arm never made.
		for _, f := range []struct {
			what string
			fn   func() error
		}{
			{"egress", seccomp.BlockEgress},
			{"process-reach", seccomp.BlockProcessReach},
			{"terminal", seccomp.BlockTerminalInjection},
			{"capability-bound", restrictCapabilityBound},
		} {
			if err := f.fn(); err != nil {
				fmt.Printf("FENCE-FAILED %s %v\n", f.what, err)
				os.Exit(3)
			}
		}
	}
	runTierProbes()
}

// runTierProbes measures each restriction from inside whatever confinement the arm
// installed and prints one PROBE line per row of the table.
func runTierProbes() {
	report := func(name, value string) { fmt.Printf("PROBE %s %s\n", name, value) }

	report("sysv-ipc", probeHostSegment(os.Getenv(sentinelShmKey)))

	// socket(AF_INET) rather than a connect: the egress filter is an allowlist on the
	// domain argument of socket(2) and filters creation, not I/O, so creation is where
	// the tiers differ - and the probe needs no network to answer.
	if _, _, errno := unix.Syscall(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 0); errno == unix.EPERM {
		report("inet-socket", "denied")
	} else {
		report("inet-socket", "permitted")
	}

	// Namespace identity is read from the kernel and compared against the host's, which
	// the parent passed in: the ids are inode numbers, so neither side can be a literal.
	// Read through the host's procfs, which the bwrap arm binds in whole - --proc is in
	// pseudoFSFlags, outside the set this arm models - and which still answers with the
	// READER's namespace for these links.
	for _, ns := range namespaceProbes {
		link, err := os.Readlink("/proc/self/ns/" + ns)
		switch {
		case err != nil:
			report(ns+"-namespace", "unreadable")
		case link == os.Getenv(sentinelHostNS+ns):
			report(ns+"-namespace", "shared")
		default:
			report(ns+"-namespace", "separate")
		}
	}

	report("process-vm-read", probeProcessVMRead())

	// The bounding set is read rather than inferred: it is the one fact that says
	// whether a capability could still be gained, and /proc/self/status carries it
	// verbatim on every arm.
	bnd, err := readCapBounding()
	switch {
	case err != nil:
		report("cap-bounding-set", "unreadable")
	case bnd == 0:
		report("cap-bounding-set", "empty")
	default:
		report("cap-bounding-set", "nonempty")
	}

	// /dev/tty is the controlling terminal by definition: it opens only for a process
	// that has one, which is exactly what --new-session takes away and the degraded
	// tier's ioctl block does not.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		report("controlling-terminal", "attached")
		report("tty-inject-ioctl", probeTIOCSTI(tty.Fd()))
		tty.Close()
		return
	}
	// With the terminal gone there is nothing left to measure the injection ioctl on, so
	// the bwrap arm's two cells are STATED consequences of --new-session rather than probe
	// results - the row that can go red for the bwrap arm is controlling-terminal, and
	// tty-inject-ioctl's teeth are all in its degraded cell. An arm that had no terminal to
	// begin with cannot tell "bwrap detached it" from "this host never had one", so it
	// reports n/a; reexecUnderTerminal makes that unreachable, and the table fails on it.
	if os.Getenv(sentinelTierArm) == armBwrap {
		report("controlling-terminal", "detached")
		report("tty-inject-ioctl", "permitted")
		return
	}
	report("controlling-terminal", "n/a")
	report("tty-inject-ioctl", "n/a")
}

// probeProcessVMRead reports whether process_vm_readv - the memory-read half of
// cross-process reach - is reachable at all.
//
// It reads this process's OWN memory, which is the only target that isolates the question.
// The parent was the obvious subject and does not work: a child reading its parent needs
// PTRACE_MODE_ATTACH, which yama ptrace_scope=1 refuses on every arm including the
// unfenced control, so the row would read "denied" everywhere and assert nothing. Under the
// bwrap arm it would fail a second way - the parent's host pid names no task in a separate
// pid namespace, so the cell would measure --unshare-pid rather than a memory fence. Self
// is subject to neither, and what the degraded tier's BlockProcessReach denies is the
// SYSCALL, not a particular target, so a denial here is that fence and nothing else.
func probeProcessVMRead() string {
	var (
		src = [1]byte{0x42}
		dst [1]byte
	)
	local := []unix.Iovec{{Base: &dst[0], Len: 1}}
	remote := []unix.RemoteIovec{{Base: uintptr(unsafe.Pointer(&src[0])), Len: 1}}
	switch _, err := unix.ProcessVMReadv(os.Getpid(), local, remote, 0); err {
	case nil:
		return "permitted"
	case unix.EPERM, unix.EACCES:
		return "denied"
	default:
		return "unreadable"
	}
}

// probeHostSegment attaches the parent's System V segment by key and returns what it
// found there. "denied" means the segment could not be reached at all, which is what
// both an IPC namespace and a seccomp denial produce - deliberately not distinguished,
// because the two tiers deny it with different errnos (ENOENT vs EPERM) and the
// invariant is about reach, not about which mechanism refused.
func probeHostSegment(key string) string {
	k, err := strconv.Atoi(key)
	if err != nil {
		return "no-key"
	}
	id, _, errno := unix.Syscall(unix.SYS_SHMGET, uintptr(k), uintptr(len(hostSegmentMarker)+1), 0)
	if errno != 0 {
		return "denied"
	}
	addr, _, errno := unix.Syscall(unix.SYS_SHMAT, id, 0, 0)
	if errno != 0 {
		return "denied"
	}
	// The attached segment is read through /proc/self/mem rather than through a Go
	// pointer built from the shmat return: a uintptr-to-pointer conversion is what
	// `go vet` calls a possible misuse, and it would be one - nothing keeps the
	// address alive. Reading one's OWN memory this way takes no ptrace check.
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return "unreadable"
	}
	defer mem.Close()
	buf := make([]byte, len(hostSegmentMarker))
	if _, err := mem.ReadAt(buf, int64(addr)); err != nil {
		return "unreadable"
	}
	return string(buf)
}

// probeTIOCSTI reports whether the terminal-injection ioctl the degraded tier's
// substitute denies is reachable. It pushes a byte the reader discards; EPERM is the
// answer either tier's fence gives, and anything else means the ioctl went through to
// the kernel.
func probeTIOCSTI(fd uintptr) string {
	b := byte(0)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(tiocsti), uintptr(unsafe.Pointer(&b))); errno == unix.EPERM {
		return "denied"
	}
	return "permitted"
}

// tiocsti mirrors internal/seccomp's own constant; the probe must name the request
// number the filter denies rather than ask the filter what it denies.
const tiocsti = 0x5412

// hostSegment creates the System V shared-memory segment the sysv-ipc row reaches for,
// writes the marker into it, and returns its key. It is the host state the whole row
// depends on: created by the test process, which is outside every arm's confinement,
// and removed afterwards so a failed run does not leak a segment into the host's IPC
// namespace.
func hostSegment(t *testing.T) (string, func()) {
	t.Helper()
	key := 0x62746f00 | (os.Getpid() & 0xff)
	id, _, errno := unix.Syscall(unix.SYS_SHMGET, uintptr(key), uintptr(len(hostSegmentMarker)+1),
		uintptr(unix.IPC_CREAT|unix.IPC_EXCL|0o600))
	if errno != 0 {
		t.Fatalf("creating the host System V segment: %v", errno)
	}
	addr, _, errno := unix.Syscall(unix.SYS_SHMAT, id, 0, 0)
	if errno != 0 {
		_, _, _ = unix.Syscall(unix.SYS_SHMCTL, id, uintptr(unix.IPC_RMID), 0)
		t.Fatalf("attaching the host System V segment: %v", errno)
	}
	mem, err := os.OpenFile("/proc/self/mem", os.O_WRONLY, 0)
	if err == nil {
		_, err = mem.WriteAt([]byte(hostSegmentMarker+"\x00"), int64(addr))
		mem.Close()
	}
	if err != nil {
		_, _, _ = unix.Syscall(unix.SYS_SHMDT, addr, 0, 0)
		_, _, _ = unix.Syscall(unix.SYS_SHMCTL, id, uintptr(unix.IPC_RMID), 0)
		t.Fatalf("writing the marker into the host System V segment: %v", err)
	}
	return strconv.Itoa(key), func() {
		_, _, _ = unix.Syscall(unix.SYS_SHMDT, addr, 0, 0)
		_, _, _ = unix.Syscall(unix.SYS_SHMCTL, id, uintptr(unix.IPC_RMID), 0)
	}
}
