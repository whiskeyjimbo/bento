package landlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock"
)

// The availability gate and the enforcement path must detect the same effective ABI.
// If they diverge, the gate can admit a degraded run that BestEffort then downgrades to
// a silent no-op, running the target with the whole host filesystem exposed.
func TestFlooredABI(t *testing.T) {
	if got := flooredABI(3, errors.New("ENOSYS")); got != 0 {
		t.Errorf("a syscall error must floor to 0 (unavailable); got %d", got)
	}
	floor := minRequiredABI()
	if got := flooredABI(floor+2, nil); got != floor+2 {
		t.Errorf("a version above the floor must pass through; got %d, want %d", got, floor+2)
	}
	if floor > 0 {
		if got := flooredABI(floor-1, nil); got != 0 {
			t.Errorf("a version below the floor must read as unavailable (fail-closed); got %d", got)
		}
	}
}

// Available must report exactly what effectiveABI (the value RestrictDegraded gates on)
// makes usable, so the two never disagree.
func TestAvailableMatchesEffectiveABI(t *testing.T) {
	if Available() != (effectiveABI() >= 1) {
		t.Errorf("Available()=%v but effectiveABI()=%d; the gate and enforcement detection disagree", Available(), effectiveABI())
	}
}

// The allowlist's read and write rights are a hand-written copy of go-landlock's
// helpers minus execute, because a rule's access set is unexported and cannot be asked
// for one right less. A copy drifts: a right added to those helpers would be inherited
// by every other rule this package builds and silently NOT by these, which narrows an
// allowlist run without failing anything.
//
// So the difference is pinned rather than the sets. FSRule.String names the rights it
// carries, which is the only handle the package exposes; comparing the two name sets
// asserts exactly one thing - that execute, and nothing else, is what the allowlist
// withholds.
func TestAllowlistRightsTrackTheHelpers(t *testing.T) {
	for _, c := range []struct {
		name    string
		helper  func(...string) ll.FSRule
		without func(...string) ll.FSRule
	}{
		{"RODirs", ll.RODirs, roDirsNoExec},
		{"ROFiles", ll.ROFiles, roFilesNoExec},
		{"RWDirs", ll.RWDirs, rwDirsNoExec},
		{"RWFiles", ll.RWFiles, rwFilesNoExec},
	} {
		t.Run(c.name, func(t *testing.T) {
			full := slices.DeleteFunc(rightNames(c.helper("/").String()), func(n string) bool { return n == "execute" })
			less := rightNames(c.without("/").String())
			slices.Sort(full)
			slices.Sort(less)
			if !slices.Equal(full, less) {
				t.Errorf("the allowlist's %s rights are no longer that helper's minus execute:\n helper minus execute: %v\n allowlist: %v", c.name, full, less)
			}
		})
	}
}

// A path that cannot be stat'd is not the same fact as a path that is absent. Dropping
// it builds a ruleset that denies a granted path, and the target then gets EACCES with
// nothing naming Landlock - so the errno has to reach the caller. ENOTDIR is the arm
// used here because it does not depend on the test's uid.
func TestClassifyRulesSeparatesMissingFromUnstattable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "regular")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	rules, err := classifyRules(nil, []string{filepath.Join(dir, "absent")}, ll.RODirs, ll.ROFiles)
	if err != nil {
		t.Errorf("a missing path must be skipped, not refused; got %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("a missing path must contribute no rule; got %d", len(rules))
	}

	under := filepath.Join(file, "child")
	if _, err := classifyRules(nil, []string{under}, ll.RWDirs, ll.RWFiles); err == nil {
		t.Errorf("a path under a regular file must be refused, not silently dropped")
	}
	if _, err := existing([]string{under}); err == nil {
		t.Errorf("an entrypoint that cannot be stat'd must be refused, not silently dropped")
	}
	if got, err := existing([]string{filepath.Join(dir, "absent"), file}); err != nil || len(got) != 1 {
		t.Errorf("existing must keep the paths that exist and skip the absent one; got %v, %v", got, err)
	}
}

// A Landlock rule's rights reach every file beneath the path, so an exec rule built from
// a directory grants execute on the whole tree under it - the blanket execAllowFiles
// refuses by name. degradedRules builds its exec rule from existing(), so the refusal has
// to be there too, or the degraded tier grants what the enforced tier will not.
func TestExistingRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := existing([]string{dir}); err == nil {
		t.Error("a directory in the exec set must be refused; Landlock would grant execute on everything beneath it")
	}
	if _, err := degradedRules(nil, nil, []string{dir}); err == nil {
		t.Error("degradedRules must refuse a directory in the exec set, not build a blanket execute rule from it")
	}
}

// The degraded tier's sole filesystem guarantee is Landlock, so it must refuse rather
// than run unconfined when the effective ABI is unavailable. Only the refusal branch is
// exercised here: applying a real ruleset would irreversibly Landlock the test process
// and poison every later test. The probe binary covers RestrictTo only, so the
// confinement half of RestrictDegraded is reached solely through the end-to-end
// degraded-tier runs, never from this package.
func TestRestrictDegradedRefusesWithoutABI(t *testing.T) {
	if effectiveABI() >= 1 {
		t.Skip("Landlock available; the refusal guard fires only when it is not")
	}
	if err := RestrictDegraded([]string{"/"}, nil, nil); !errors.Is(err, errUnavailableABI) {
		t.Errorf("RestrictDegraded must refuse with errUnavailableABI when ABI is unavailable; got %v", err)
	}
}

// The allowlist's two refusals, neither of which any other test reaches: a directory
// entry would grant execute on everything beneath it - Landlock rules apply to a whole
// subtree - which is the blanket the ruleset exists to withhold, and a missing entry
// would silently leave the ruleset narrower than the list it was built from. Both are
// refused where the path grants' own skip-if-absent contract would pass them, so this
// pins the difference rather than the shared helper.
func TestExecAllowlistRefusesADirectoryAndAMissingEntry(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tool")
	if err := os.WriteFile(file, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := execAllowlistRules([]string{"/"}, nil, []string{dir}); err == nil {
		t.Error("a directory allowlist entry must be refused; honoring it grants execute on every file under it")
	}
	if _, err := execAllowlistRules([]string{"/"}, nil, []string{filepath.Join(dir, "absent")}); err == nil {
		t.Error("a missing allowlist entry must be refused, not skipped: the ruleset would permit fewer binaries than the policy named")
	}
	if _, err := execAllowlistRules([]string{"/"}, nil, []string{file}); err != nil {
		t.Errorf("a regular file is the one shape an entry may take: %v", err)
	}
}

// exec: allowlist installs no exec-block filter, so this ruleset is the only thing
// bounding what the target spawns. A kernel that cannot apply it must refuse the run
// rather than fall through to unrestricted spawn under a report claiming an allowlist -
// the same stance RestrictDegraded takes, and for the same reason: in both cases
// Landlock is not a backstop behind something else, it IS the mechanism.
func TestRestrictExecAllowlistRefusesWithoutABI(t *testing.T) {
	if effectiveABI() >= 1 {
		t.Skip("Landlock available; the refusal guard fires only when it is not")
	}
	if err := RestrictExecAllowlist(nil, []string{"/opt/tool"}); !errors.Is(err, errAllowlistUnavailableABI) {
		t.Errorf("RestrictExecAllowlist must refuse with errAllowlistUnavailableABI when ABI is unavailable; got %v", err)
	}
}

// Landlock denies a handled right wherever no rule grants it, so a right this package
// declares it HANDLES but no rule of the tier grants is a blanket denial of that
// operation - inside the grants, with nothing in the errno naming the layer. That has now
// been the bug three times (ioctl_dev, resolve_unix, refer), each found by reading rather
// than by a test, so this asserts the general invariant instead of the next instance:
// every right a tier handles is granted by at least ONE of its rules.
//
// At least one, not all: read rules deliberately withhold resolve_unix and refer, and
// forcing every rule to carry every right would demand exactly the escalation those two
// wrappers exist to avoid.
//
// The rules are inspected rather than applied - applying would Landlock the test process
// irreversibly - so the handled sets are spelled as the bit ranges of the presets the
// package names, with the tripwire below to catch go-landlock growing a right past them.
func TestEveryHandledRightIsGrantedBySomeRule(t *testing.T) {
	// go-landlock names rights 0..16 today, so V8 is (1<<16)-1 and V9 (1<<17)-1. An
	// unnamed bit prints as "1<<n", so this fires when the library learns a 18th right -
	// at which point whoever raises handledFS or degradedFS revisits the masks below.
	if got := ll.AccessFSSet(1 << 17).String(); got != "{1<<17}" {
		t.Fatalf("go-landlock has grown an access right past resolve_unix (bit 17 prints as %s); recheck the handled masks here and in landlock_linux.go", got)
	}

	d := t.TempDir()
	f := filepath.Join(d, "regular")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{d, f}

	backstop, err := backstopRules(paths, paths)
	if err != nil {
		t.Fatal(err)
	}
	// Exec takes the regular file alone: the set is the entrypoint and its interpreter,
	// and a directory in it is refused (see TestExistingRefusesADirectory).
	degraded, err := degradedRules(paths, paths, []string{f})
	if err != nil {
		t.Fatal(err)
	}
	// The allowlist tier is the third hand-written builder over handledFS, and the one
	// whose rights are a copy of go-landlock's helpers rather than the helpers themselves.
	// It withholds execute from its read and write rules and grants it back only on the
	// allowlisted file, so it satisfies the invariant only when that entry is present -
	// which the caller is refused for omitting.
	allowlist, err := execAllowlistRules(paths, paths, []string{f})
	if err != nil {
		t.Fatal(err)
	}
	tiers := []struct {
		name    string
		handled ll.AccessFSSet
		rules   []ll.Rule
	}{
		{"bwrap backstop", ll.AccessFSSet(1<<16 - 1), backstop},  // handledFS = ll.V8
		{"degraded", ll.AccessFSSet(1<<17 - 1), degraded},        // degradedFS = ll.V9
		{"exec allowlist", ll.AccessFSSet(1<<16 - 1), allowlist}, // handledFS = ll.V8
	}

	for _, tier := range tiers {
		granted := map[string]bool{}
		for _, r := range tier.rules {
			for _, name := range rightNames(fmt.Sprintf("%v", r)) {
				granted[name] = true
			}
		}
		for _, name := range rightNames(tier.handled.String()) {
			// BestEffort strips refer from the handled set below ABI 2, and withRefer
			// stops asking for it there in step - so on those kernels it is neither
			// handled nor granted, and the invariant is not violated by its absence.
			if name == "refer" && !referSupported() {
				continue
			}
			if !granted[name] {
				t.Errorf("%s tier handles %q but no rule grants it, so the right is denied everywhere inside the grants", tier.name, name)
			}
		}
	}
}

// rightNames pulls the access-right names out of a go-landlock AccessFSSet or FSRule
// rendering, both of which spell the set as "{execute,read_file,...}". The fields are
// unexported, so the String form is the only view of them from outside the library.
func rightNames(s string) []string {
	open := strings.Index(s, "{")
	closed := strings.Index(s, "}")
	if open < 0 || closed < open {
		return nil
	}
	return strings.Split(s[open+1:closed], ",")
}

// Landlock denies a handled right wherever no rule grants it, so a right in the handled
// set that no rule carries is a blanket denial, not a no-op. ioctl_dev is in both handled
// sets from ABI 5 and none of go-landlock's RO/RW helpers grant it, which from kernel
// 6.10 would deny every ioctl on every device node the target opens - TCGETS on a freshly
// opened /dev/tty, so isatty and termios fail. This kernel is below that ABI, so the
// denial itself is unreachable here and the rules are inspected instead of applied.
//
// Each set carries a directory AND a regular file, so classifyRules routes both ways and
// the file constructors are covered too - a device node is a file, and a grant naming one
// directly is the case the right exists for.
func TestBothTiersGrantIoctlDevOnTheirPathGrants(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "regular")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{d, f}

	tiers := map[string][]ll.Rule{}
	backstop, err := backstopRules(paths, paths)
	if err != nil {
		t.Fatal(err)
	}
	tiers["bwrap backstop"] = backstop
	degraded, err := degradedRules(paths, paths, nil)
	if err != nil {
		t.Fatal(err)
	}
	tiers["degraded"] = degraded

	for tier, rules := range tiers {
		// One dir rule and one file rule per kind, both kinds per tier.
		if len(rules) != 4 {
			t.Fatalf("%s tier built %d rules for a directory and a file in each set, want 4", tier, len(rules))
		}
		for _, r := range rules {
			if !strings.Contains(fmt.Sprintf("%v", r), "ioctl_dev") {
				t.Errorf("%s tier: rule %v does not grant ioctl_dev, so a handled right is denied everywhere", tier, r)
			}
		}
	}
}
