// Package launcher is the in-sandbox stage bento re-execs into.
//
// bwrap runs a single entrypoint; when a run needs setup that must happen inside
// the sandbox - the egress bridge and/or the seccomp exec-block filter - that
// setup happens here, in one place, before the real target runs. Doing both in
// one stage is deliberate: they must not become two competing entrypoints, and
// their ordering matters (the bridge is started before the filter, because
// starting it uses execve, which the filter denies).
package launcher

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento-v2/internal/landlock"
	"github.com/whiskeyjimbo/bento-v2/internal/observe"
	"github.com/whiskeyjimbo/bento-v2/internal/seccomp"
)

// proxyAddr is the fixed loopback address the egress bridge listens on. The
// sandbox has its own isolated network namespace, so nothing else uses it.
const proxyAddr = "127.0.0.1:3128"

// Config describes the in-sandbox setup for one run.
type Config struct {
	// Socket is the bind-mounted unix socket reaching the host-side egress proxy.
	// Empty means the policy allows no egress, so no bridge is set up.
	Socket string
	// Block installs the exec-block seccomp filter (policy exec is none or
	// none-strict). When false the target may spawn subprocesses freely.
	Block bool
	// StrictBlock additionally blocks fork/vfork/process-clone (policy exec is
	// none-strict), where the architecture supports it. Off amd64 it falls back to
	// the execve-only block, which the report surfaces as a degraded exec-strict
	// layer. Only meaningful when Block is set.
	StrictBlock bool
	// Writable are the policy's resolved write-grant paths. Landlock confines
	// writes to these (plus runtime scratch) as a second layer behind bwrap.
	Writable []string
	// ObserveFD, when > 0, runs the target under the ptrace observer instead of
	// enforcing, writing the files it opened and whether it exec'd to this inherited
	// descriptor. It is a descriptor rather than a path so the report is not in the
	// target's mount namespace and is not inherited across exec (see Run). That raises
	// the bar but is not tamper-proof: a descendant can still reopen it via
	// /proc/<launcher>/fd during the run, so the report is trustworthy only to the
	// degree the profiled code is (see runObserve). The profiler
	// uses it to synthesize a manifest from a permissive run; no seccomp or Landlock is
	// applied, so what the target does is fully observed.
	ObserveFD int
	// Target is the absolute command to run: interpreter, script, and args.
	Target []string
}

// Run performs the in-sandbox setup and runs the target, returning its exit code.
//
// Order is load-bearing. The bridge child is started first, while execve still
// works. The exec-block filter is installed next; if it cannot be installed the
// run is refused rather than proceeding unconfined - a report that claims
// "enforced" must never accompany a target that ran without the filter. Finally
// the target is started: under the filter it is reached via execveat (which the
// filter allows), replacing this process; without the filter it is supervised as
// a child so its exit code can be returned.
func Run(cfg Config) (int, error) {
	if len(cfg.Target) == 0 {
		return 0, fmt.Errorf("launcher: no target command")
	}

	// Drop every descriptor bento's parent leaked into this process before anything
	// downstream can inherit it. A file descriptor the host process held open without
	// O_CLOEXEC - an editor, a CI runner, a server embedding bento - passes straight
	// through bwrap to here; the mount namespace, the deny-list, and Landlock all
	// revoke paths, but none of them closes an already-open descriptor, so such a
	// handle is an ungranted read (or write) channel out of the sandbox. This is the
	// one process bento controls between bwrap and the target, so it is where they are
	// dropped, before startBridge re-execs and before the target is reached.
	//
	// CLOEXEC-mark rather than close: the launcher's own Go runtime holds descriptors
	// above 2 (netpoll's epoll, for one), and closing those out from under it would
	// break the launcher itself. Marking them drops them only at the coming exec into
	// the target - the launcher keeps working, and nothing survives into the target.
	// 0/1/2 are the target's own stdio and are left alone; ObserveFD (the profiling
	// report, fd 3) is marked too, which is exactly what the profiler needs - the
	// launcher writes the report in-process after the traced target exits (marking
	// only drops it across exec), while the target and every grandchild are denied an
	// inherited handle to it. A descendant can still reopen it by path via
	// /proc/<launcher>/fd, which runObserve addresses; this only closes the inherited
	// route.
	if err := dropInheritedFDs(); err != nil {
		return 0, err
	}

	// Marking the leaked descriptors close-on-exec drops them at the exec into the
	// target, but on the supervise path (exec: all) the launcher does not exec - it
	// stays alive as the sandbox's pid 2 with those descriptors still open. Reopening
	// one by path through /proc/<launcher>/fd already fails: the descriptor's file
	// lives on a host mount absent from the sandbox namespace, so the kernel's
	// cross-namespace reopen check denies it regardless of file mode (this is the same
	// barrier runObserve relies on for the report descriptor). What that barrier does
	// NOT stop is a plain readlink of /proc/<launcher>/fd, which still discloses the
	// host path behind the descriptor. Making this process non-dumpable reparents its
	// /proc entry to root, closing that path-disclosure channel to the same-uid target.
	// execve resets dumpable, so the exec: none path (which replaces this process with
	// the target) is unaffected.
	if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return 0, fmt.Errorf("launcher: making the launcher non-dumpable: %w", errno)
	}

	env := os.Environ()
	if cfg.Socket != "" {
		if err := startBridge(cfg.Socket); err != nil {
			return 0, err
		}
		env = append(env, proxyEnv()...)
	}

	if cfg.ObserveFD > 0 {
		return runObserve(cfg, env)
	}

	if cfg.Block {
		if err := installExecFilter(cfg.StrictBlock); err != nil {
			// Fail closed: never run the target unconfined while claiming to block
			// subprocesses.
			return 0, fmt.Errorf("launcher: refusing to run - could not install the exec-block filter: %w", err)
		}
	}

	// The Landlock backstop is applied last, after the egress bridge has already
	// started (the bridge must open its socket before writes are confined) and
	// after seccomp. It is inherited across the coming exec, so the target runs
	// under it.
	//
	// It is a best-effort second layer, not the primary guarantee: bwrap already
	// confines the filesystem. So a failure to apply it warns and proceeds rather
	// than aborting the run - failing here would make bwrap's confinement
	// contingent on the backstop, inverting the relationship. (An absent Landlock
	// is a silent no-op inside Restrict, not an error.)
	if err := landlock.Restrict(cfg.Writable); err != nil {
		fmt.Fprintf(os.Stderr, "[bento] warning: the Landlock filesystem backstop could not be applied (%v); bwrap confinement still holds\n", err)
	}

	if cfg.Block {
		// execveat replaces this process with the target under the filters, so this
		// returns only if the transition itself fails.
		return 0, seccomp.Exec(cfg.Target, env)
	}
	return superviseTarget(cfg.Target, env)
}

// runObserve profiles the target: it runs under the ptrace observer (no seccomp,
// no Landlock - a permissive run so every access is seen) and writes what the
// target opened, and whether it exec'd, to the inherited report descriptor for
// the host to read.
func runObserve(cfg Config, env []string) (int, error) {
	res, traceErr := observe.Trace(cfg.Target, env, os.Stdin, os.Stdout, os.Stderr)

	// The report is written here, after Trace returns, through the close-on-exec
	// descriptor secured in Run. Paths are quoted (%q) so a newline in a path cannot
	// forge extra R/W/EXEC records, and the completion marker is written last and only
	// on a successful trace, so a failed or truncated trace lacks it and is rejected by
	// the host. The report is NOT tamper-proof against the profiled target itself (see
	// the Truncate note below): a profiling report is
	// trustworthy only to the degree the profiled code is.
	var b strings.Builder
	if traceErr == nil {
		for _, a := range res.Accesses {
			verb := "R"
			if a.Write {
				verb = "W"
			}
			fmt.Fprintf(&b, "%s %q\n", verb, a.Path)
		}
		if res.Execed {
			b.WriteString("EXEC\n")
		}
		// The run's exit status, so the host can warn when a signaled/nonzero run may
		// have stopped partway and the observations are incomplete. Written before the
		// marker, like the records.
		if res.Signaled {
			fmt.Fprintf(&b, "SIGNAL %d\n", res.Signal)
		} else {
			fmt.Fprintf(&b, "EXIT %d\n", res.ExitCode)
		}
		b.WriteString(observe.ReportStart + "\n")
	}
	report := os.NewFile(uintptr(cfg.ObserveFD), "observe-report")
	if report == nil {
		return 0, fmt.Errorf("launcher: observation descriptor %d is not valid", cfg.ObserveFD)
	}
	// Truncate before writing, to discard anything a descendant wrote to this file
	// through the launcher's /proc/<pid>/fd while it was held open during the run.
	// This is best-effort, not a guarantee: a descendant that mmap'd the report
	// MAP_SHARED keeps writing forged records with plain memory stores (no syscall, so
	// ptrace never stops it - a syscall-free loop is not frozen when Trace returns -
	// and the mapped pages survive this truncate), landing them before the marker.
	// That residual is bounded: a hostile target can already inject arbitrary records
	// by merely *attempting* opens during the permissive run (inspect records the path
	// from the syscall args regardless of whether the open succeeds), so the report's
	// integrity rests on the trusted-code threat model and human manifest review, not
	// on this truncate. PTRACE_O_EXITKILL reaps descendants on launcher exit.
	if err := report.Truncate(0); err != nil {
		return 0, fmt.Errorf("launcher: truncating the observation report: %w", err)
	}
	if _, err := report.Write([]byte(b.String())); err != nil {
		return 0, fmt.Errorf("launcher: writing observations: %w", err)
	}
	if err := report.Close(); err != nil {
		return 0, fmt.Errorf("launcher: closing the observation report: %w", err)
	}
	if traceErr != nil {
		return 0, fmt.Errorf("launcher: observing target: %w", traceErr)
	}
	return res.ExitCode, nil
}

// firstInheritableFD is the lowest descriptor dropInheritedFDs marks close-on-exec.
// 0/1/2 are the target's stdio and are always kept.
const firstInheritableFD = 3

// dropInheritedFDs marks every descriptor from firstInheritableFD up close-on-exec,
// so nothing bento's parent leaked survives the exec into the target. close_range
// with CLOSE_RANGE_CLOEXEC marks in one syscall without closing, so the launcher's
// own runtime descriptors keep working until the exec drops them. It needs Linux
// 5.11; on older kernels it fails rather than leaving descriptors to leak, matching
// the launcher's fail-closed stance on the exec filter.
func dropInheritedFDs() error {
	if err := unix.CloseRange(firstInheritableFD, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("launcher: dropping inherited file descriptors: %w", err)
	}
	return nil
}

// installExecFilter installs the strongest exec-block filter the policy asks for
// and this architecture provides. none-strict gets the fork/clone-blocking filter
// on amd64; where that is unavailable it falls back to the execve-only block, and
// the run report (from Probe) marks the exec-strict layer degraded so the gap is
// never silent.
func installExecFilter(strict bool) error {
	if strict && seccomp.StrictExecSupported() {
		return seccomp.BlockExecStrict()
	}
	return seccomp.BlockExec()
}

// startBridge launches the bridge as a separate child process before any filter
// is installed. It must be its own process, not a goroutine: when the exec-block
// filter is in play the launcher execveats the target and is replaced, which
// would kill an in-process bridge. As a child it survives until the pid namespace
// is torn down at the end of the run.
func startBridge(socket string) error {
	cmd := exec.Command("/proc/self/exe", SentinelBridge, socket)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launcher: starting egress bridge: %w", err)
	}
	return nil
}

func proxyEnv() []string {
	u := "http://" + proxyAddr
	// NO_PROXY exempts loopback so a script that runs its own in-sandbox service
	// (a local server on 127.0.0.1) can reach it directly, instead of the client
	// sending that connection to the host-side proxy - which would try to dial the
	// host's loopback, not the sandbox's. The tradeoff: a manifest cannot allowlist
	// a loopback address as an egress target; `validate` warns when one does. Both
	// casings are set because different tools read different ones.
	const noProxy = "localhost,127.0.0.1,::1"
	return []string{
		"HTTP_PROXY=" + u, "HTTPS_PROXY=" + u,
		"http_proxy=" + u, "https_proxy=" + u,
		"NO_PROXY=" + noProxy, "no_proxy=" + noProxy,
	}
}

// superviseTarget runs the target as a child and returns its exit code. Used
// only when the target is not exec-blocked (nothing needs to replace this
// process, and supervising lets us return the exit code directly).
//
// reapUntil waits on all of this process's children until the target exits, so
// the egress bridge started alongside it is reaped too. Orphaned *grandchildren*
// of a subprocess-spawning target are not this process's concern: bwrap runs its
// own init as PID 1 (this launcher is PID 2), so an orphan reparents to bwrap's
// init, which reaps it. The whole pid namespace is torn down at the end of the
// run regardless.
func superviseTarget(target, env []string) (int, error) {
	cmd := exec.Command(target[0], target[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("launcher: starting target: %w", err)
	}
	return reapUntil(cmd.Process.Pid)
}

// reapUntil reaps every child that exits until the target does, then returns the
// target's exit code. Wait4(-1) blocks until any child exits, so orphaned
// grandchildren are collected as they finish rather than lingering as zombies.
func reapUntil(targetPid int) (int, error) {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		switch {
		case err == syscall.EINTR:
			continue
		case err != nil:
			return 0, fmt.Errorf("launcher: reaping children: %w", err)
		case pid == targetPid:
			return waitExitCode(ws), nil
		}
		// Any other pid was an orphaned grandchild, now reaped - keep going.
	}
}

// waitExitCode maps a wait status to a conventional exit code: a signalled
// process reports 128+signal, matching what a shell would return.
func waitExitCode(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

// BridgeMain is the bridge child (re-exec sentinel SentinelBridge): it forwards
// every loopback connection on proxyAddr to the host-side proxy socket until the
// process is torn down with the sandbox.
func BridgeMain(socket string) error {
	l, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("bridge: cannot listen on %s inside the sandbox: %w", proxyAddr, err)
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go bridgeConn(c, socket)
	}
}

// bridgeConn forwards one loopback connection to the host-side proxy socket in
// both directions, half-closing each side when its source is done so a
// half-closed tunnel is not truncated.
func bridgeConn(client net.Conn, socket string) {
	defer client.Close()
	upstream, err := net.Dial("unix", socket)
	if err != nil {
		return
	}
	defer upstream.Close()

	// Traffic in either direction means the bridge is active, so re-arm the idle
	// deadline on BOTH conns on every read. A long one-way transfer keeps only its
	// own direction busy; if each direction armed only its own conn, the silent
	// side would trip the idle timeout after idleTimeout and - because SetDeadline
	// bounds writes too - kill the active side's next write, dropping a connection
	// that never went idle.
	extend := func() {
		t := time.Now().Add(idleTimeout)
		client.SetDeadline(t)
		upstream.SetDeadline(t)
	}
	extend()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyIdle(upstream, client, extend); halfClose(upstream) }()
	go func() { defer wg.Done(); copyIdle(client, upstream, extend); halfClose(client) }()
	wg.Wait()
}

// idleTimeout tears down a bridged connection that has sat with no traffic this
// long, so a stalled connection cannot pin a goroutine for the life of the run.
var idleTimeout = 5 * time.Minute

// copyIdle copies src→dst, calling extend on every read so activity in this
// direction keeps the bridge's idle deadline fresh; an idle bridge is dropped
// after idleTimeout when neither direction reads.
func copyIdle(dst io.Writer, src io.Reader, extend func()) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			extend()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.SetDeadline(time.Now())
}
