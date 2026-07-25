//go:build linux && amd64

package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/internal/i386"
	"github.com/whiskeyjimbo/bento/internal/observe"
	"github.com/whiskeyjimbo/bento/internal/seccomp"
)

// sentinelForeignABI selects one of the three child roles below. The trace and the
// filter are both process-wide and one-way, so neither can run in the test process.
const sentinelForeignABI = "BENTO_TEST_FOREIGN_ABI"

// foreignPath is what the tracee's i386 readlink names. Absolute and distinctive, so
// its presence in a Result can only have come from decoding that syscall.
const foreignPath = "/bento-foreign-abi-probe"

// runForeignABITracer runs one tracer role and returns the lines it reported. It
// skips the calling test on a kernel with no ia32 entry point, where the tracee's
// `int 0x80` raises SIGSEGV and reaches neither the filter nor the decoder.
//
// The skip reads the tracee's runtime dump out of the captured output rather than
// its wait status: the fault lands inside Go code, so the runtime catches SIGSEGV,
// prints the dump and exits 2 UNSIGNALED - the Result would say SIGNAL=0, which is
// indistinguishable from a clean run and would fail these tests on every such host.
func runForeignABITracer(t *testing.T, role string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestForeignABIChild", "-test.v")
	cmd.Env = append(os.Environ(), sentinelForeignABI+"="+role)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "signal SIGSEGV") {
		t.Skip("kernel has no ia32 compat entry point (CONFIG_IA32_EMULATION off or ia32_emulation=0), so no foreign-arch syscall can be issued")
	}
	if err != nil {
		t.Fatalf("%s tracer: %v\n%s", role, err, out)
	}
	return string(out)
}

// A tracee that issues an i386 syscall reaches the decoder before the foreign-arch
// guard kills it - the kernel reports the ptrace syscall-entry stop before running
// seccomp (syscall_trace_enter does ptrace first, "to catch any tracer changes"), so
// the guard is no protection against a misdecode. i386 readlink is 85; amd64 85 is
// creat, so without an ABI check in observe this READ probe becomes a WRITE grant on
// the path it names. observe checks the dispatch arch and drops the stop instead.
//
// Both halves are pinned, because either alone leaves the hole: the ABI check keeps the
// fabricated grant from being synthesized at all, and SeccompKilled is what makes the
// profile command refuse the run (seccompKilledRefusal) as incomplete rather than
// synthesizing from what the killed process managed to touch.
func TestForeignABITraceeIsNotDecodedAndTheRunIsRefused(t *testing.T) {
	if !seccomp.Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	out := runForeignABITracer(t, "guarded")
	if !strings.Contains(out, "SECCOMPKILLED=true") {
		t.Fatalf("the foreign-arch guard should have killed the tracee, and SeccompKilled is what makes the profiler refuse the run:\n%s", out)
	}
	if strings.Contains(out, "ACCESS "+foreignPath) {
		t.Errorf("the i386 readlink was decoded against the amd64 table, fabricating a grant on the path it named:\n%s", out)
	}
}

// The same tracee with no guard at all. The guard is what kills the process, so this is
// the case where the ABI check is the only thing between a foreign syscall and a
// fabricated write grant: nothing here marks the run unobservable, so a caller reading
// Accesses would take them at face value. The foreign syscall shows up as one drop,
// which is how the Result says an access was seen and could not be read.
func TestForeignABIWithoutTheGuardIsDroppedNotDecoded(t *testing.T) {
	if !seccomp.Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	out := runForeignABITracer(t, "plain")
	if strings.Contains(out, "ACCESS "+foreignPath) {
		t.Errorf("an unguarded i386 readlink decoded as an amd64 creat and fabricated a write grant:\n%s", out)
	}
	if !strings.Contains(out, "SECCOMPKILLED=false") {
		t.Errorf("without the guard nothing marks the run unobservable, which is what makes the ABI check load-bearing here:\n%s", out)
	}
	if !strings.Contains(out, "DROPPED=1") {
		t.Errorf("the foreign syscall should be counted once as a dropped observation, at its entry stop:\n%s", out)
	}
}

// TestForeignABIChild is the tracer and tracee half of both tests. The two tracer
// roles differ only in whether the foreign-arch guard is installed before the trace;
// the tracee role is the traced program. Inert unless the parent selected a role.
func TestForeignABIChild(t *testing.T) {
	role := os.Getenv(sentinelForeignABI)
	if role == "" {
		t.Skip("child helper for the foreign-ABI tests")
	}
	if role == "tracee" {
		foreignABITracee()
		return
	}
	if role == "guarded" {
		// The filter is inherited across the fork below, so installing it here is what
		// the launcher's own ordering does: guard first, then fork the tracee.
		if err := seccomp.BlockIoUring(); err != nil {
			fmt.Println("BLOCKIOURING_ERR", err)
			os.Exit(3)
		}
	}
	res, err := observe.Trace(
		[]string{os.Args[0], "-test.run=TestForeignABIChild", "-test.v"},
		append(os.Environ(), sentinelForeignABI+"=tracee"),
		nil, os.Stderr, os.Stderr,
	)
	if err != nil {
		fmt.Println("TRACE_ERR", err)
		os.Exit(3)
	}
	fmt.Printf("SECCOMPKILLED=%v SIGNALED=%v SIGNAL=%d DROPPED=%d\n", res.SeccompKilled, res.Signaled, res.Signal, res.Dropped)
	for _, a := range res.Accesses {
		fmt.Printf("ACCESS %s write=%v\n", a.Path, a.Write)
	}
}

// foreignABITracee issues i386 readlink(foreignPath) and, if it is still running
// afterwards, exits quietly - the tracer reports what its Result says either way.
//
// The path buffer is mapped below 4 GiB because the compat ABI truncates syscall
// arguments to 32 bits: a Go heap pointer would reach the kernel as garbage and a
// wrong-table decode would fail to read a path at all, so the tests above would pass
// on a decoder with no ABI check and assert nothing.
func foreignABITracee() {
	const lowAddr = 0x30000000
	path := foreignPath + "\x00"
	p, _, errno := unix.Syscall6(unix.SYS_MMAP, lowAddr, uintptr(len(path)),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE, ^uintptr(0), 0)
	// NOREPLACE, not plain MAP_FIXED: MAP_FIXED would silently unmap whatever already
	// lived at this address, and the address check below could never fail because
	// MAP_FIXED always returns what it was asked for. On a kernel too old for the flag
	// it is ignored and the address becomes a hint, which the same check catches.
	if errno != 0 || p != lowAddr {
		fmt.Println("MMAP_ERR", errno, p)
		os.Exit(3)
	}
	// Filled through a pipe rather than a Go slice over the mapping: converting the
	// syscall's uintptr back to a pointer is the unsafe.Pointer misuse go vet rejects,
	// and read(2) takes the destination as the address it already is.
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Println("PIPE_ERR", err)
		os.Exit(3)
	}
	if _, err := w.WriteString(path); err != nil {
		fmt.Println("PIPE_WRITE_ERR", err)
		os.Exit(3)
	}
	if _, _, errno := unix.Syscall(unix.SYS_READ, r.Fd(), p, uintptr(len(path))); errno != 0 {
		fmt.Println("PIPE_READ_ERR", errno)
		os.Exit(3)
	}
	i386.Readlink(p, p, uintptr(len(foreignPath)))
}
