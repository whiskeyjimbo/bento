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
// Usage: probe degradednet <read-dir> <port> [preset]
// Opens a TCP socket BEFORE applying the degraded ruleset, connects a second one to prove
// the port answers, then applies the ruleset and connects the pre-existing socket. Prints
// "net_baseline=OK|DENIED net_predomain=OK|DENIED net_fresh=OK|DENIED". The pre-existing
// arm is the load-bearing one: Landlock's net hooks are on connect(2) and evaluate the
// CALLING task's domain, not the domain in force when the socket was created - which is
// what makes this fence the SCM_RIGHTS-passed AF_INET descriptor the seccomp egress
// filter structurally cannot revoke. Were it keyed on creation instead, that arm would
// print OK and the fence would buy nothing.
//
// A trailing preset argument ("V3") swaps every set the tiers request before applying
// them, which needs -tags bentoprobe: below ABI 4 Landlock has no network access set at
// all, so both connects must succeed. That is the pre-ABI-4 column, asserted positively
// rather than left dark on a host that is past it.
//
// Usage: probe scopedipc <read-dir> <write-dir> <outside-path> <abstract-name> <pathname-socket> <port>
// Applies the DEGRADED ruleset, then reports every residual the tier's IPC posture rests
// on at once, so all three of its domains are observed in one process: a connect to an
// abstract unix socket and a signal to a process outside the domain (both governed by the
// scoped domain, which BestEffort installs only from ABI 6), a pathname socket and a
// same-domain signal (which scoping must NOT touch), an outside read (the path domain) and
// a TCP connect (the net domain). Prints "scoped_abstract_baseline=... scoped_abstract=...
// scoped_signal_outside=... scoped_signal_samedomain=... scoped_pathname=...
// scoped_outsideread=... scoped_tcp=...", each OK|DENIED.
//
// Both sockets are bound by the CALLER: scoping is a check on where the peer's domain sits
// relative to this one, unlike the net hooks, so a socket this process bound itself before
// restricting would leave "outside" ambiguous and the verdict meaningless. The signalled
// process outside the domain is a child started BEFORE the ruleset, which is the position
// every host process is in relative to a degraded run; the same-domain one is started
// after and is the control that separates scoping from a host that forbids the signal
// anyway. The baseline arm is the same control for the abstract socket.
//
// A trailing preset argument ("V5") swaps the scoped set the degraded tier requests
// before applying it, which needs -tags bentoprobe and reproduces what a kernel below
// that ABI enforces; without the tag the run fails rather than silently measuring the
// host's own ABI.
//
// Usage: probe fsresiduals <read-dir> <write-dir> <device> [preset]
// Applies the DEGRADED ruleset with read-dir readable and write-dir writable, then
// reports the two filesystem rights whose absence from an older kernel's handled set the
// degraded run report discloses as residuals. read-dir must contain a file named "f" and
// write-dir a file named "w"; device is a device node under read-dir. Prints
// "trunc_readonly=OK|DENIED trunc_write=OK|DENIED ioctl_readonly=OK|DENIED".
//
// trunc_readonly is the arm under test: truncate enters the handled set at ABI 3, and no
// read rule grants it, so from ABI 3 zeroing a read-granted file is denied and below it
// the file can still be zeroed - the integrity gap truncateResidual discloses. trunc_write
// is the control that separates "truncate is restricted" from "the write grant is broken":
// the RW helpers grant truncate, so it must stay OK at every ABI.
//
// ioctl_readonly is a control rather than an arm. ioctl_dev enters the handled set at ABI
// 5 and withIoctlDev grants it back on the read rules as well as the write ones, so a
// GRANTED device node is ioctl-able at every ABI - which is what the residual's own
// disclosure says. The residual is about device nodes OUTSIDE the grants, and those are
// unopenable under the path rules, so there is no arm to assert; this pins the half that
// is observable, so a withIoctlDev that stopped covering read rules fails here.
//
// A trailing preset argument ("V2") swaps every set the tiers request before applying
// them, which needs -tags bentoprobe. See landlock.SetTierPreset for why the result is a
// hybrid rather than a faithful old kernel.
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
// Usage: probe execallow <write-dir> <allowed-binary> <other-binary> <loader>
// Applies RestrictExecAllowlist - the whole tree readable but not executable, with
// execute granted on allowed-binary alone. No policy uses that ruleset; this mode is the
// evidence behind the decision to withhold an exec allowlist. Prints
// "execallow_allowed=OK|DENIED
// execallow_other=... execallow_loader=... execallow_read=...". allowed-binary must be
// statically linked, which is the mode's own precondition: a dynamic one cannot run
// without the loader, and the loader arm here is what shows why granting the loader
// execute would be a bypass rather than a fix.
//
// Usage: probe sleeper
// Sleeps until its parent exits. The modes above re-exec this as their child rather than
// depending on a sleep(1) on PATH. It watches for the exit rather than waiting to be
// killed because a child started BEFORE the degraded ruleset is outside the domain the
// probe then enters, and from ABI 6 signal scoping denies the probe the kill - leaving a
// sleeper that holds the caller's CombinedOutput pipe open for as long as it sleeps.
//
// Usage: probe available
// Prints "available=true|false" - so a test can observe Available() in a process
// whose /sys/kernel/security has been masked, reproducing a container.
package main

import (
	"errors"
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

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/internal/landlock"
)

// quiet is the sleepers' stdio, opened before any mode restricts itself: /dev/null is
// unopenable once a ruleset is in force (no write grant covers it), and a sleeper must not
// inherit this process's stdout - a caller reading the probe with CombinedOutput waits on
// that pipe, so a sleeper holding it open blocks the read until the sleeper exits, and
// from ABI 6 the probe cannot kill one it started before entering the domain.
var quiet *os.File

func main() {
	// Every mode that starts a child AFTER restricting and then reaches for it - a signal
	// under LANDLOCK_SCOPE_SIGNAL, a /proc reach under the ptrace check - is asking whether
	// the child is in the SAME domain, and below ABI 8 that is a per-thread question.
	// go-landlock only has the tsync flag from ABI 8; below it, it restricts each thread
	// separately with psx, and each landlock_restrict_self builds its own domain, so two
	// threads of this process end up in sibling domains rather than one. The child inherits
	// the domain of the thread that forked it, so a reach issued from any other thread is
	// cross-domain and the kernel refuses it - correctly, and at the mercy of which thread
	// the runtime happened to pick. Pinning this goroutine keeps fork and reach on one
	// thread so the arms measure scoping rather than scheduling.
	runtime.LockOSThread()

	q, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "devnull:", err)
		os.Exit(2)
	}
	quiet = q

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
		// Reparenting to init is the exit signal: a bare select{} would trip the runtime's
		// deadlock detector and abort, leaving the parent reading a process that has
		// already died, and an unconditional sleep outlives a probe that cannot kill it.
		for parent := os.Getppid(); os.Getppid() == parent; {
			time.Sleep(100 * time.Millisecond)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "degradednet" {
		degradedNet(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "degradednet" {
		applyTierPreset(os.Args[4])
		degradedNet(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "fsresiduals" {
		fsResiduals(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if len(os.Args) == 6 && os.Args[1] == "fsresiduals" {
		applyTierPreset(os.Args[5])
		fsResiduals(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if len(os.Args) == 8 && os.Args[1] == "scopedipc" {
		scopedIPC(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7])
		return
	}
	if len(os.Args) == 9 && os.Args[1] == "scopedipc" {
		if err := setScopedIPCPreset(os.Args[8]); err != nil {
			fmt.Fprintln(os.Stderr, "preset:", err)
			os.Exit(2)
		}
		scopedIPC(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7])
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
	if len(os.Args) == 6 && os.Args[1] == "execallow" {
		execAllow(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
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

// execAllow applies the exec-allowlist ruleset with allowed as its single entry, then
// tries to spawn three things: the allowlisted binary, a second binary that is readable
// but not allowlisted, and the allowlisted binary again through the dynamic loader.
// Prints "execallow_allowed=... execallow_other=... execallow_loader=...
// execallow_read=...", each OK|DENIED.
//
// The loader arm is the one that decides whether this mode bounds anything at all. If
// the loader is executable, "loader <any readable ELF>" runs it whatever the allowlist
// says, so that arm must be DENIED - and it is what forces allowlist entries to be
// statically linked. The read arm is the control: an allowlist withholds EXECUTE, not
// read, so a file that is merely readable must stay readable.
func execAllow(writeDir, allowed, other, loader string) {
	if err := landlock.RestrictExecAllowlist([]string{writeDir}, []string{allowed}); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(1)
	}
	fmt.Printf("execallow_allowed=%s execallow_other=%s execallow_loader=%s execallow_read=%s\n",
		spawnable(allowed), spawnable(other), spawnable(loader, allowed), readable(other))
}

// spawnable reports whether argv can be executed, as OK or DENIED. Only the exec
// transition is judged: a binary that starts and then exits nonzero for its own reasons
// still answers the question this asks.
func spawnable(argv ...string) string {
	cmd := exec.Command(argv[0], argv[1:]...)
	// The child inherits this process's own stdio rather than being left nil. os/exec
	// opens /dev/null for every nil stream, and under an allowlist ruleset built for a
	// temp directory that open is denied - so every arm would report DENIED for a reason
	// that has nothing to do with the execute right under test. A real run does not meet
	// this: /dev is in the sandbox's writable mounts.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = quiet, quiet, quiet
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return "OK"
	}
	return verdict(err)
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

// signalVerdict is verdict for the two signal arms, which cannot use it: a signal to a
// child that never started or has already been reaped fails with ESRCH, and reporting
// that as DENIED reads as a Landlock refusal the kernel never made. Only EPERM is one -
// anything else is the probe's own problem and exits rather than answering.
func signalVerdict(err error) string {
	switch {
	case err == nil:
		return "OK"
	case errors.Is(err, syscall.EPERM):
		return "DENIED"
	default:
		fmt.Fprintf(os.Stderr, "signal: not a permission answer, so no verdict can be read from it: %v\n", err)
		os.Exit(2)
		return ""
	}
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

// degradedNet reports whether the degraded ruleset's network domain denies TCP connect,
// including on a socket that existed before the domain did. See the usage note above for
// why that arm is the one under test.
func degradedNet(read, port string) {
	p, err := strconv.Atoi(port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "port:", err)
		os.Exit(2)
	}
	pre, err := tcpSocket()
	if err != nil {
		fmt.Fprintln(os.Stderr, "socket:", err)
		os.Exit(2)
	}
	baseline, err := tcpSocket()
	if err != nil {
		fmt.Fprintln(os.Stderr, "socket:", err)
		os.Exit(2)
	}
	base := connectLoopback(baseline, p)
	if err := landlock.RestrictDegraded([]string{read}, nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	fresh, err := tcpSocket()
	if err != nil {
		// socket(2) itself is not what this fences, so a failure here is a broken probe.
		fmt.Fprintln(os.Stderr, "socket:", err)
		os.Exit(2)
	}
	fmt.Printf("net_baseline=%s net_predomain=%s net_fresh=%s\n",
		base, connectLoopback(pre, p), connectLoopback(fresh, p))
}

func scopedIPC(read, write, outside, abstract, pathSock, port string) {
	p, err := strconv.Atoi(port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "port:", err)
		os.Exit(2)
	}
	outsideChild, err := startSleeper()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sleeper:", err)
		os.Exit(2)
	}
	defer func() { _ = outsideChild.Kill() }()

	baseline := dial(abstract)

	if err := landlock.RestrictDegraded([]string{read}, []string{write}, nil); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}

	// The same-domain child re-execs this binary from inside the domain, so the caller
	// must grant read on the directory the probe itself lives in.
	sameDomain, err := startSleeper()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sleeper:", err)
		os.Exit(2)
	}
	defer func() { _ = sameDomain.Kill() }()

	fresh, err := tcpSocket()
	if err != nil {
		fmt.Fprintln(os.Stderr, "socket:", err)
		os.Exit(2)
	}

	// A real signal rather than the zero probe: signal 0 is a permission check whose
	// route through the LSM hook is not worth resting an arm on when a deliverable one
	// answers the same question. Both children are killed on the way out regardless.
	fmt.Printf("scoped_abstract_baseline=%s scoped_abstract=%s scoped_signal_outside=%s scoped_signal_samedomain=%s scoped_pathname=%s scoped_outsideread=%s scoped_tcp=%s\n",
		baseline, dial(abstract),
		signalVerdict(outsideChild.Signal(syscall.SIGTERM)), signalVerdict(sameDomain.Signal(syscall.SIGTERM)),
		dial(pathSock), readable(outside), connectLoopback(fresh, p))
}

// applyTierPreset swaps the tiers' requested sets, exiting rather than continuing on
// failure: a probe that silently measured the host's own ABI would pass as the low-ABI
// coverage it never got.
func applyTierPreset(name string) {
	if err := setTierPreset(name); err != nil {
		fmt.Fprintln(os.Stderr, "preset:", err)
		os.Exit(2)
	}
}

// fsResiduals applies the degraded ruleset and reports the truncate and ioctl_dev arms.
// See the usage note above for which of them is the arm and which are the controls.
func fsResiduals(read, write, device string) {
	if err := landlock.RestrictDegraded([]string{read, filepath.Dir(device)}, []string{write}, nil); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	fmt.Printf("trunc_readonly=%s trunc_write=%s ioctl_readonly=%s\n",
		truncatable(filepath.Join(read, "f")), truncatable(filepath.Join(write, "w")), ioctlable(device))
}

// truncatable reports whether path can be zeroed. os.Truncate is the truncate(2) path
// rather than ftruncate on an open descriptor: Landlock's truncate right is checked at
// open for the descriptor route, so a file opened before the ruleset would answer for a
// moment that has passed rather than for the handled set.
func truncatable(path string) string {
	return verdict(os.Truncate(path, 0))
}

// ioctlable reports whether a device node can be opened and ioctl'd. The open is part of
// the answer, not a precondition: a read rule that stopped covering the node would deny
// there, and reporting that as an ioctl denial would credit the handled set with a path
// refusal.
//
// Only EACCES counts as a denial here, unlike every other arm's plain error check.
// Landlock refuses a handled-but-ungranted ioctl with EACCES, while the device's own
// handler declines a request it does not implement with ENOTTY - and on a node like
// /dev/null the second is the normal answer at every ABI. Treating any error as DENIED
// would report ENOTTY as a Landlock denial and the arm would pass whatever the handled
// set did.
func ioctlable(device string) string {
	f, err := os.Open(device)
	if err != nil {
		return "DENIED"
	}
	defer f.Close()
	if _, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCINQ); errors.Is(err, unix.EACCES) {
		return "DENIED"
	}
	return "OK"
}

func tcpSocket() (int, error) {
	return unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
}

// connectLoopback connects fd to 127.0.0.1:port and closes it either way, so a caller can
// run several arms without leaking descriptors into the restricted domain.
func connectLoopback(fd, port int) string {
	defer unix.Close(fd)
	return verdict(unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}))
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

// startSleeper re-execs this binary in its sleeper mode on quiet's descriptors - see
// there for why they are neither the default nor this process's own.
func startSleeper() (*os.Process, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, "sleeper")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = quiet, quiet, quiet
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// The read below needs the child's address space mapped, which it is not until the
	// exec completes; poll for the maps rather than racing it. The poll gives up rather
	// than failing: a caller that has already applied a ruleset cannot read procfs at
	// all, so an unreadable maps says nothing about the child.
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
