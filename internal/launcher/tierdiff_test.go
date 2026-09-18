//go:build linux

package launcher

import (
	"fmt"
	"os"
	"os/exec"
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

	armUnfenced = "unfenced"
	armDegraded = "degraded"
	armBwrap    = "bwrap"

	// hostSegmentMarker is what the parent writes into the host's System V segment. A
	// child that prints it back read another process's memory.
	hostSegmentMarker = "HOST-SEGMENT-CONTENT"
)

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
		name:     "cap-bounding-set",
		why:      "bv2-7nv8y / grid row 10: --cap-drop ALL empties it on the bwrap tier; the degraded tier cannot, and refuses a privileged run instead",
		unfenced: "nonempty",
		degraded: "nonempty",
		bwrap:    "empty",
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
		why:      "bv2-lpuue: what the degraded substitute DOES cover, pinned so a widening or a regression is visible",
		hostFact: "a controlling terminal",
		unfenced: "permitted",
		degraded: "denied",
		bwrap:    "permitted",
	},
}

func TestTierDifferential(t *testing.T) {
	key, cleanup := hostSegment(t)
	defer cleanup()

	got := map[string]map[string]string{}
	for _, arm := range []string{armUnfenced, armDegraded, armBwrap} {
		got[arm] = runTierArm(t, arm, key)
	}

	for _, p := range tierProbes {
		t.Run(p.name, func(t *testing.T) {
			// Not skipMissingDep: a controlling terminal is a property of how the test
			// was invoked, not a package a host can install, so BENTO_REQUIRE_TEST_DEPS
			// must not turn its absence into a failure. The fence itself is covered
			// unconditionally by internal/seccomp's TestBlockTerminalInjection; what
			// these rows add is the tier COMPARISON, which needs a real terminal.
			if got[armUnfenced][p.name] == "n/a" {
				t.Skipf("%s needs %s, and this run was not started from one", p.name, p.hostFact)
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

// runTierArm runs the probe child under one arm and returns its probe results. A
// missing probe reads as the empty string, which no row expects, so a child that died
// partway through fails the rows it never reached rather than passing them.
func runTierArm(t *testing.T, arm, key string) map[string]string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^TestTierProbeHelper$")
	cmd.Env = append(os.Environ(), sentinelTierArm+"="+arm, sentinelShmKey+"="+key)
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
		cmd.Args = append([]string{
			bwrap, "--dev-bind", "/", "/",
			"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts",
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
		// rows here, and Landlock would confine the probes' own reads.
		for _, f := range []struct {
			what string
			fn   func() error
		}{
			{"egress", seccomp.BlockEgress},
			{"process-reach", seccomp.BlockProcessReach},
			{"terminal", seccomp.BlockTerminalInjection},
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
	// No controlling terminal AND no way to tell "bwrap detached it" from "this host
	// never had one" - so the arm that had none to begin with reports n/a and the rows
	// are skipped rather than asserted against an absence.
	if os.Getenv(sentinelTierArm) == armBwrap {
		report("controlling-terminal", "detached")
		report("tty-inject-ioctl", "permitted")
		return
	}
	report("controlling-terminal", "n/a")
	report("tty-inject-ioctl", "n/a")
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
