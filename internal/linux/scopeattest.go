//go:build linux

package linux

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The limits layers were the only gatable layers whose final state was never reconciled
// against what the run applied: the applied report has no channel for them, so
// Result.Report, postRunShortfall and unenforcedRequestedLimits all read what the pre-run
// probe concluded - and that verdict is memoized for the process lifetime. systemd-run
// accepts a MemoryMax for an undelegated controller and silently ignores it, which is the
// exact failure the fail-closed decision cites as its reason to exist.
//
// The launcher cannot answer this from inside the way it answers the pid namespace, the
// netns, the fresh /tmp and the empty capability bounding set: --unshare-cgroup makes
// /proc/self/cgroup read "0::/", /sys/fs/cgroup inside the sandbox is the host's mount
// rooted at the host cgroup root, and mounting a fresh cgroup2 (which would expose the
// namespace root) needs the CAP_SYS_ADMIN namespaceFlags drops by design. All three
// measured; see the bead.
//
// So the attestation is made from the parent, which is not in a cgroup namespace and
// therefore reads absolute paths. systemd-run moves itself into the scope it creates, so
// the wrapper's own pid leads straight to the transient scope's memory.max, pids.max and
// cpu.max: the values the kernel will enforce on this run, not a property the manager
// accepted.

// scopeLimits is one parent-side reading of the transient scope's cgroup, taken while the
// target is alive and carrying the verdicts rather than the path.
//
// The values have to be read at sampling time, not later: --collect removes the scope's
// cgroup about a millisecond after the wrapper exits (measured), and a removed cgroup
// answers ENOENT for memory.max, which is byte-identical to the controller never having
// been there. Reading post-run would therefore accuse every healthy limited run whose
// bookkeeping took longer than that millisecond.
//
// caps holds a controller file only where the question was answerable. An empty map is the
// reading that attests nothing - no scope found - and it worsens no layer: faulting a
// completed run for being fast is worse than the gap it leaves.
//
// How often a fast target actually produces it: 0 of 100 runs of `/bin/true` under a full
// set of limits on a healthy user manager (measured). The sample is taken from the
// WRAPPER's pid, and systemd-run lives in the scope until the target exits, so it is not
// racing the target the way the pid alone suggests - it is the manager that has to be slow.
// The residue is a host whose manager never creates the scope at all, which reads the same
// as a run too fast to sample and reports whatever the pre-run probe concluded.
type scopeLimits struct {
	caps map[string]bool
}

// scopeSampleTimeout bounds the wait for the wrapper to land in its scope. systemd-run has
// to reach the manager and get the scope created first, so it is not there the instant
// Start returns; this is a backstop on a manager that never gets there, and the run is
// already under way throughout, so it costs the sample and not the target.
const scopeSampleTimeout = 2 * time.Second

// controllerFiles are the cgroup-v2 files carrying the caps wrapWithLimits requests. Only
// memory.max is read for the memory layer: memory.swap.max rides the same controller, so
// the undelegated-controller failure this attests cannot split them.
var controllerFiles = []string{"memory.max", "pids.max", "cpu.max"}

// attestScopeLimits reads the scope the wrapper was placed in, given the pid of systemd-run
// itself. It is a var for delegatedControllers' reason: the host this reconcile exists for
// - one whose manager accepts a property it does not apply - cannot be constructed
// in-package, so the run-path wiring is otherwise unreachable from a test, and a call site
// that dropped the reading would still pass.
var attestScopeLimits = func(pid int) scopeLimits {
	deadline := time.Now().Add(scopeSampleTimeout)
	for {
		dir, ok := scopeCgroupOf(pid)
		if ok {
			return readScopeCaps(dir)
		}
		// A wrapper that died before it was ever seen in a scope leaves a zombie whose
		// cgroup line keeps the name with a "(deleted)" marker, and no directory to stat -
		// waiting out the full bound there would hold Wait, and the cancellation arm with
		// it, for a scope that is never coming.
		if gone(pid) || time.Now().After(deadline) {
			return scopeLimits{}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// readScopeCaps takes the verdicts, one file at a time, recording only the answerable ones.
func readScopeCaps(dir string) scopeLimits {
	caps := make(map[string]bool)
	for _, f := range controllerFiles {
		if bound, known := controllerBound(filepath.Join(dir, f)); known {
			caps[f] = bound
		}
	}
	return scopeLimits{caps: caps}
}

// gone reports whether the process has exited or its cgroup has been reaped out from under
// it, which is what a wrapper that failed before the scope existed looks like.
func gone(pid int) bool {
	p, ok := cgroupPathOf(strconv.Itoa(pid))
	return !ok || strings.HasSuffix(p, "(deleted)")
}

// scopeCgroupOf reads the cgroup of the scope the wrapper was placed in, given the
// wrapper's pid. systemd-run moves ITSELF into the transient scope once the manager has
// created it (measured against a real scope from this code path), so the wrapper's own
// cgroup is the scope's - no walk to a child is needed, and there is no window in which the
// right process has to be guessed.
//
// A cgroup equal to bento's own is not a scope: that is what a wrapper still waiting on the
// manager reads, and what a run whose scope was never created reads for good. Telling those
// apart from a real scope is the whole check, so the comparison is the oracle rather than
// the read succeeding.
func scopeCgroupOf(pid int) (string, bool) {
	own, ok := cgroupPathOf(strconv.Itoa(os.Getpid()))
	if !ok {
		return "", false
	}
	scope, ok := cgroupPathOf(strconv.Itoa(pid))
	if !ok || scope == own {
		return "", false
	}
	dir := filepath.Join("/sys/fs/cgroup", scope)
	if _, err := os.Stat(dir); err != nil {
		return "", false
	}
	return dir, true
}

// cgroupPathOf reads the unified ("0::") line of a process's cgroup, which is the absolute
// path from this process's point of view - the parent is in no cgroup namespace, which is
// what makes the path resolvable against /sys/fs/cgroup at all.
func cgroupPathOf(pid string) (string, bool) {
	b, err := os.ReadFile("/proc/" + pid + "/cgroup")
	if err != nil {
		return "", false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.TrimSpace(p), true
		}
	}
	return "", false
}

// noteScopeLimits reconciles the limits layers against what the scope's cgroup actually
// carries. It only ever WORSENS a layer, like the applied report's own reconcile: the
// probe answers what this host can enforce, and this answers what this run got.
func noteScopeLimits(r *enforce.Report, l policy.Limits, a scopeLimits) {
	for _, c := range []struct {
		layer     enforce.Layer
		requested bool
		file      string
		name      string
	}{
		{enforce.LayerLimitsMemory, l.Memory != "", "memory.max", "memory"},
		{enforce.LayerLimitsPIDs, l.PIDs > 0, "pids.max", "pids"},
		{enforce.LayerLimitsCPU, l.CPU != "", "cpu.max", "cpu"},
	} {
		if !c.requested || r.StateOf(c.layer) != enforce.Enforced {
			continue
		}
		if bound, known := a.caps[c.file]; known && !bound {
			r.Set(c.layer, enforce.Unavailable, "the scope this run was given carries no "+c.name+
				" cap: systemd accepted the property and did not apply it, which is what an undelegated "+
				c.name+" controller does, so the target ran unbounded rather than under the limit the manifest asked for")
		}
	}
}

// controllerBound reports whether a scope's controller file names a cap, and whether the
// question was answerable at all. A missing file is an answer: the controller is not on
// this scope, so nothing bound. Any other read error is not, and leaves the layer alone -
// a scope torn down mid-read must not fault a run that was fine.
func controllerBound(path string) (bound, known bool) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, true
	}
	if err != nil {
		return false, false
	}
	// "max" is cgroup-v2's word for no limit, and it is the first field of cpu.max too
	// ("max 100000" against "50000 100000"), so one test covers all three files. An empty
	// file is no answer rather than an unbound one: nothing bento does produces it, and
	// reading it as unbound would fault a run on a shape nobody has seen.
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return false, false
	}
	return f[0] != "max", true
}
