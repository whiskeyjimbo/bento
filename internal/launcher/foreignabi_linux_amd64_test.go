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

// runForeignABITracer runs one tracer role and returns the lines it reported.
func runForeignABITracer(t *testing.T, role string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestForeignABIChild", "-test.v")
	cmd.Env = append(os.Environ(), sentinelForeignABI+"="+role)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s tracer: %v\n%s", role, err, out)
	}
	return string(out)
}

// A tracee that issues an i386 syscall IS decoded against the amd64 table, and the
// foreign-arch guard does not prevent it: the kernel reports the ptrace syscall-entry
// stop before running seccomp (syscall_trace_enter does ptrace first, "to catch any
// tracer changes"), so the tracer has already recorded the access by the time the
// filter kills the process. i386 readlink is 85; amd64 85 is creat - a READ probe
// recorded as a WRITE to the path it names.
//
// What keeps that fabricated grant out of a manifest is one layer up: the Result also
// carries SeccompKilled, and the profile command refuses the whole run on it
// (seccompKilledRefusal) rather than synthesizing from it. This pins BOTH halves,
// because either one alone is the bug: the refusal without the fabrication is a test
// of nothing, and the fabrication without the refusal is a write grant entering
// enforcement policy.
func TestForeignABITraceeIsDecodedButTheRunIsRefused(t *testing.T) {
	if !seccomp.Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	out := runForeignABITracer(t, "guarded")
	if strings.Contains(out, "SIGNAL=11") {
		t.Skip("kernel has no ia32 compat entry point (CONFIG_IA32_EMULATION off), so no foreign-arch syscall can be issued")
	}
	if !strings.Contains(out, "SECCOMPKILLED=true") {
		t.Fatalf("the foreign-arch guard should have killed the tracee, and only SeccompKilled makes the profiler refuse the run:\n%s", out)
	}
	if !strings.Contains(out, "ACCESS "+foreignPath+" write=true") {
		t.Errorf("the i386 readlink should still be decoded as an amd64 creat - if this stopped happening, observe grew an ABI check and the refusal above is no longer the only thing standing between a foreign syscall and a fabricated write grant:\n%s", out)
	}
}

// The same tracee with no guard at all: the decode is identical, and the only
// difference is that nothing reports the run as unobservable. This is what the
// fabricated grant looks like when it reaches a caller that does not check
// SeccompKilled - the residual observe.Trace carries for any second caller.
func TestForeignABIWithoutTheGuardLooksLikeACleanRun(t *testing.T) {
	if !seccomp.Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	out := runForeignABITracer(t, "plain")
	if strings.Contains(out, "SIGNAL=11") {
		t.Skip("kernel has no ia32 compat entry point (CONFIG_IA32_EMULATION off), so no foreign-arch syscall can be issued")
	}
	if !strings.Contains(out, "ACCESS "+foreignPath+" write=true") {
		t.Errorf("an unguarded i386 readlink should decode as an amd64 creat and fabricate a write grant:\n%s", out)
	}
	if !strings.Contains(out, "SECCOMPKILLED=false") {
		t.Errorf("without the guard nothing marks the run unobservable, which is the point of this case:\n%s", out)
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
// arguments to 32 bits: a Go heap pointer would reach the kernel as garbage, the
// decoder would fail to read a path and count a drop, and the control would assert
// nothing about a fabricated grant.
func foreignABITracee() {
	const lowAddr = 0x30000000
	path := foreignPath + "\x00"
	p, _, errno := unix.Syscall6(unix.SYS_MMAP, lowAddr, uintptr(len(path)),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED, ^uintptr(0), 0)
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
