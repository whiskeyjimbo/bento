//go:build linux

// Command probe confines itself to a single directory with Landlock, then
// reports whether an inside and an outside path are readable, so a test can
// observe Landlock's real effect in a fresh process (Landlock is irreversible
// for the process that applies it).
//
// Usage: probe <allowed-dir> <inside-path> <outside-path> [extra-write-file]
// Prints "inside=OK|DENIED outside=OK|DENIED". extra-write-file is added to the
// writable set as a regular FILE: Landlock's directory rules reject a non-directory
// with EINVAL and the ruleset is applied all-or-nothing, so a caller that routed it
// to a directory rule would confine nothing at all - which shows up here as
// outside=OK.
//
// Usage: probe otherthread <allowed-dir> <inside-path> <outside-path>
// Prints "otherthread_inside=... otherthread_outside=...", read from a thread that
// already existed when the ruleset was applied.
//
// Usage: probe unixconnect <allowed-dir> <socket-path>
// Confines itself to allowed-dir, then connects to a pathname AF_UNIX socket that
// lives outside it and prints "unixconnect=OK|DENIED". Landlock ABI 9 can restrict
// that connect, and it is restricted whenever the ruleset HANDLES the right, whether
// or not any rule grants it - so this observes what the handled set is, from outside
// the package.
//
// Usage: probe reparent <read-root> <write-dir> <outside-dir>
// Confines itself with read-root readable and write-dir writable, then reparents files.
// Prints "samedir=OK|DENIED crossdir=OK|DENIED crosslink=OK|DENIED escape=OK|DENIED".
// The refer right governs rename(2) and link(2) across directories and nothing else, so
// samedir is the control that separates "the write grant works" from "reparenting works":
// without refer granted, samedir stays OK while crossdir and crosslink fail with EXDEV
// even though both directories are inside the same write grant.
//
// Usage: probe degraded <read-dir> <write-dir> <outside-path> <ungranted-socket> <granted-socket>
// Applies the DEGRADED ruleset - which handles resolve_unix and grants it back on the
// write set - then prints "degraded_outside=OK|DENIED degraded_unixconnect=OK|DENIED
// degraded_grantedsocket=OK|DENIED". Both sockets must be bound by the CALLER, so their
// servers are outside the domain this process creates: that is the only case resolve_unix
// governs, and a socket this process binds itself would be reachable whether or not the
// write rules grant the right. The two differ only in where they live - one under no
// grant, one under the write grant - which is the asymmetry under test. The outside read
// is separate and load-bearing: the write rules ask for a right the handled set no longer
// carries once BestEffort downgrades below ABI 9, and a downgrade that collapsed the
// ruleset instead of intersecting the right away would return no error while confining
// nothing.
//
// Usage: probe procmem <read-dir>
// Starts a child, reaches into its /proc/<pid>/mem and /proc/<pid>/fd once unrestricted,
// then applies the DEGRADED ruleset with read-dir as the sole read grant and reaches
// again. Prints "procmem_baseline=... procmem_restricted=... procfd_baseline=...
// procfd_restricted=...", each OK|DENIED. Pass "/" to grant the broadest read there is:
// what this observes is that both reaches are denied even then, because Landlock's
// ptrace check - not the read set - is what covers them.
//
// Usage: probe procmemchild <read-dir>
// The same, except the child is started AFTER the ruleset is applied, so it inherits
// the domain. Prints "procmem_samedomain=... procfd_samedomain=...". This is the
// control: both must be OK, or the denials above would be the host's ptrace_scope
// rather than Landlock.
//
// Usage: probe sleeper
// Sleeps until killed. The two modes above re-exec this as their child rather than
// depending on a sleep(1) on PATH.
//
// Usage: probe available
// Prints "available=true|false" - so a test can observe Available() in a process
// whose /sys/kernel/security has been masked, reproducing a container.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/whiskeyjimbo/bento/internal/landlock"
)

func main() {
	if len(os.Args) == 5 && os.Args[1] == "otherthread" {
		otherThread(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "unixconnect" {
		unixConnect(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "reparent" {
		reparent(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if len(os.Args) == 7 && os.Args[1] == "degraded" {
		degraded(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6])
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "sleeper" {
		// A bare select{} would trip the runtime's deadlock detector and abort, leaving
		// the parent reading a process that has already died.
		time.Sleep(time.Hour)
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "procmem" {
		procMem(os.Args[2])
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "procmemchild" {
		procMemSameDomain(os.Args[2])
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "available" {
		fmt.Printf("available=%v\n", landlock.Available())
		return
	}
	if len(os.Args) != 4 && len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: probe <allowed-dir> <inside-path> <outside-path> [extra-write-file]")
		os.Exit(2)
	}
	allowed := os.Args[1]
	write := []string{allowed}
	if len(os.Args) == 5 {
		write = append(write, os.Args[4])
	}
	if err := landlock.RestrictTo([]string{allowed}, write); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	fmt.Printf("inside=%s outside=%s\n", readable(os.Args[2]), readable(os.Args[3]))
}

func readable(path string) string {
	if _, err := os.ReadFile(path); err != nil {
		return "DENIED"
	}
	return "OK"
}

// unixConnect confines itself away from socket, then dials it. The socket's server was
// bound before this process existed, so it is outside the Landlock domain - which is
// exactly the case ABI 9's resolve_unix right covers.
func unixConnect(allowed, socket string) {
	if err := landlock.RestrictTo([]string{allowed}, []string{allowed}); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	fmt.Printf("unixconnect=%s\n", dial(socket))
}

// reparent confines itself, then moves and links files between two directories that are
// both inside the SAME write grant - the case Landlock denies outright unless the write
// rules grant refer, whatever else they permit.
//
// The layout the caller builds is fixed: write/a/f exists, write/b is an empty directory,
// and outside is a directory under the read root but under no write grant. The escape arm
// is the one that must stay DENIED; it is not a refer test (a move out of the write grant
// needs make_reg on the destination, which no read rule carries) but the check that
// granting refer widened reparenting only where the write grants already reach.
func reparent(read, write, outside string) {
	if err := landlock.RestrictTo([]string{read}, []string{write}); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	a, b := filepath.Join(write, "a"), filepath.Join(write, "b")
	fmt.Printf("samedir=%s crossdir=%s crosslink=%s escape=%s\n",
		verdict(os.Rename(filepath.Join(a, "f"), filepath.Join(a, "moved"))),
		verdict(os.Rename(filepath.Join(a, "moved"), filepath.Join(b, "f"))),
		verdict(os.Link(filepath.Join(b, "f"), filepath.Join(a, "linked"))),
		verdict(os.Rename(filepath.Join(b, "f"), filepath.Join(outside, "f"))))
}

func verdict(err error) string {
	if err != nil {
		return "DENIED"
	}
	return "OK"
}

// degraded applies the degraded ruleset, then reports the three things the tier's posture
// rests on: a path outside every grant is still denied (so the ruleset was applied at
// all), a socket under no grant, and a socket under the write grant. Both sockets were
// bound by the caller before this process existed, so both servers are outside the domain
// - the only case resolve_unix governs - and the sole difference between them is which
// grant covers their path.
func degraded(read, write, outside, ungranted, granted string) {
	if err := landlock.RestrictDegraded([]string{read}, []string{write}, nil); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	fmt.Printf("degraded_outside=%s degraded_unixconnect=%s degraded_grantedsocket=%s\n",
		readable(outside), dial(ungranted), dial(granted))
}

// procMem reads a child's /proc/<pid>/mem before and after the degraded ruleset is
// applied. The child is started FIRST, so it stays outside the domain this process
// creates - the position every host process is in relative to a degraded run.
//
// The before/after pair is what makes the result readable: a host whose ptrace_scope
// forbids the read outright reports DENIED for both, and the caller skips rather than
// crediting Landlock with a denial the host would have made anyway.
func procMem(read string) {
	child, err := startSleeper()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sleeper:", err)
		os.Exit(2)
	}
	defer func() { _ = child.Kill() }()

	// The mapped address is captured here and reused after the restriction. Re-deriving
	// it from /proc/<pid>/maps would not work: maps takes the same ptrace check mem does,
	// so it fails first afterwards and the result would report a maps denial under the
	// name of a mem denial.
	addr, baseline := memReadable(child.Pid, 0)
	fdBaseline := fdReachable(child.Pid)
	if err := landlock.RestrictDegraded([]string{read}, nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		_ = child.Kill()
		os.Exit(2)
	}
	_, restricted := memReadable(child.Pid, addr)
	fmt.Printf("procmem_baseline=%s procmem_restricted=%s procfd_baseline=%s procfd_restricted=%s\n",
		baseline, restricted, fdBaseline, fdReachable(child.Pid))
}

// procMemSameDomain starts the child AFTER restricting, so it inherits the domain and
// the ptrace check permits the read. Without this arm the denial in procMem would not
// be attributable to Landlock.
func procMemSameDomain(read string) {
	if err := landlock.RestrictDegraded([]string{read}, nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	child, err := startSleeper()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sleeper:", err)
		os.Exit(2)
	}
	defer func() { _ = child.Kill() }()
	_, mem := memReadable(child.Pid, 0)
	fmt.Printf("procmem_samedomain=%s procfd_samedomain=%s\n", mem, fdReachable(child.Pid))
}

// startSleeper re-execs this binary in its sleeper mode. Its descriptors are the
// probe's own already-open ones: the default would have os/exec open /dev/null, which
// a restricted caller has no write grant for.
func startSleeper() (*os.Process, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, "sleeper")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// The read below needs the child's address space mapped, which it is not until the
	// exec completes; poll for the maps rather than racing it.
	for range 100 {
		if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", cmd.Process.Pid)); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cmd.Process, nil
}

// memReadable reads one byte of the target's address space through /proc/<pid>/mem and
// returns the address it succeeded at along with the verdict. With at 0 it discovers a
// readable mapping from /proc/<pid>/maps; with an address from an earlier call it goes
// straight to the read, which is what lets a caller reach mem without touching maps.
//
// The open alone is not the test: it succeeds under a permissive ptrace_scope, and only
// the read enters mm_access.
func memReadable(pid int, at uint64) (uint64, string) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return at, "DENIED"
	}
	defer f.Close()
	if at != 0 {
		if _, err := f.ReadAt(make([]byte, 1), int64(at)); err != nil {
			return at, "DENIED"
		}
		return at, "OK"
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, "DENIED"
	}
	for line := range strings.SplitSeq(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "r") {
			continue
		}
		lo, err := strconv.ParseUint(strings.Split(fields[0], "-")[0], 16, 64)
		if err != nil {
			continue
		}
		if _, err := f.ReadAt(make([]byte, 1), int64(lo)); err == nil {
			return lo, "OK"
		}
	}
	return 0, "DENIED"
}

// fdReachable resolves the target's /proc/<pid>/fd/0 magic link, the other half of the
// procfs cross-process reach: following one reopens the file the target holds, with the
// opener's own credentials rather than the grants. Readlink is enough - it takes the
// same ptrace check the open does. Listing the directory is NOT: readdir yields bare
// descriptor numbers and is permitted either way, so it would report OK regardless.
func fdReachable(pid int) string {
	if _, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/0", pid)); err != nil {
		return "DENIED"
	}
	return "OK"
}

func dial(socket string) string {
	//nolint:gosec // G704: the socket path is this test probe's own argument, and dialing
	// an attacker-chosen path is the point - what is under test is whether Landlock denies it.
	c, err := net.Dial("unix", socket)
	if err != nil {
		return "DENIED"
	}
	c.Close()
	return "OK"
}

// otherThread applies the ruleset while a second OS thread is already parked, then
// has THAT thread do the reads. Landlock is per-thread, and go-landlock reaches the
// others by a mechanism that differs between the cgo and no-cgo builds - libpsx
// versus syscall.AllThreadsSyscall. A thread started after the restrict call would
// inherit it through clone under either one and prove nothing, so the thread here is
// locked and synchronized to exist first.
func otherThread(allowed, inside, outside string) {
	// Both ends pinned so the two tids below are stable and the check that they differ
	// is not a race: without it a scheduler that ran the reads on the restricting
	// thread would make this pass while proving nothing.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	self := syscall.Gettid()

	parked, restricted := make(chan struct{}), make(chan struct{})
	tid := make(chan int)
	result := make(chan string)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid <- syscall.Gettid()
		close(parked)
		<-restricted
		result <- fmt.Sprintf("otherthread_inside=%s otherthread_outside=%s", readable(inside), readable(outside))
	}()
	if other := <-tid; other == self {
		fmt.Fprintln(os.Stderr, "the probe thread is the restricting thread")
		os.Exit(2)
	}
	<-parked
	if err := landlock.RestrictTo([]string{allowed}, []string{allowed}); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	close(restricted)
	fmt.Println(<-result)
}
