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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/internal/observe"
	"github.com/whiskeyjimbo/bento/internal/seccomp"
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
	// uses it to synthesize a manifest from an observe-only run; no seccomp or Landlock is
	// applied, so what the target does is fully observed.
	ObserveFD int
	// AppliedFD, when > 0, is an inherited descriptor this stage writes its
	// applied-layer report to before the target is reached, so the host's run report
	// reflects what was really installed rather than only what the host probed as
	// possible. See applied.go. Zero means no report.
	AppliedFD int
	// AllowNetworkStdio carries enforce.Process.AllowNetworkStdio: the embedder
	// deliberately handed the target an open network socket as one of its standard
	// streams, so refuseNetworkStdio is skipped. Off by default, including for every
	// CLI run.
	AllowNetworkStdio bool
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
	// The two reports travel the same inherited descriptor (the host places each at fd 3),
	// so a config asking for both would have the observation and the layer report
	// overwriting each other. They are mutually exclusive by design - profiling produces
	// an observation, not an enforcement report - and this is where that is checked
	// rather than only stated.
	if cfg.ObserveFD > 0 && cfg.AppliedFD > 0 {
		return 0, fmt.Errorf("launcher: cannot both profile and report applied layers: descriptors %d and %d", cfg.ObserveFD, cfg.AppliedFD)
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
	// An inherited socket on stdio walks through every fence bento installs, whether
	// or not the policy grants egress: with no egress it falsifies the claim outright,
	// and with egress it bypasses the host proxy's allowlist. So the refusal is
	// unconditional, and the one caller that means to pass a connection says so.
	// Every failing descriptor is examined, not just the first: only the socket itself
	// is opt-in-able, and a descriptor that could not be classified at all stays fatal
	// even under the opt-in - the embedder permitted a connection it knows it passed,
	// not an unreadable stream.
	for _, err := range networkStdioRefusals() {
		var passed *networkStdio
		if !cfg.AllowNetworkStdio || !errors.As(err, &passed) {
			return 0, err
		}
		// Warned from the refusal, not from the opt-in, so it names the descriptor that
		// is actually a socket and stays silent when the embedder set the opt-in but
		// passed an ordinary stream.
		fmt.Fprintf(os.Stderr, "[bento] warning: %v; the embedder permits it, and it bypasses the manifest's egress allowlist\n", passed)
	}

	// Marking the leaked descriptors close-on-exec drops them at the exec into the
	// target, but on the supervise path (exec: all) the launcher does not exec - it
	// stays alive as the sandbox's pid 2 with those descriptors still open. Reopening
	// one by path through /proc/<launcher>/fd reaches the inode directly, so the file
	// living on a host mount absent from the sandbox namespace is no barrier - and a
	// readlink of the same entry discloses the host path behind the descriptor even
	// without opening it. Making this process non-dumpable closes both: its /proc entry
	// reparents to root, so the same-uid target can neither traverse /proc/<launcher>/fd
	// nor read its links. This is not the only thing denying that access today - a probe
	// with the call removed still met EACCES, since crossing into bwrap's user namespace
	// clears dumpable of its own accord - but that is bwrap's behavior to change, and
	// this is the one place bento can make the guarantee its own. execve resets dumpable,
	// so the exec: none path (which replaces this process with the target) is unaffected.
	if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return 0, fmt.Errorf("launcher: making the launcher non-dumpable: %w", errno)
	}

	env := os.Environ()
	if cfg.Socket != "" {
		if err := startBridge(cfg.Socket); err != nil {
			return 0, err
		}
		// Drop any inherited proxy variables first: glibc getenv returns the first
		// occurrence, so an HTTP_PROXY already in this environment would otherwise win
		// over bento's, pointing the target's egress at a chosen proxy instead of the
		// in-sandbox bridge. The host's own environment cannot reach here - args.go
		// emits --clearenv - so the case this covers is a POLICY-declared proxy variable.
		// Fail-closed today (empty netns), but the intercept model requires bento's
		// values to be authoritative.
		env = dropEnv(env, "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy")
		env = append(env, proxyEnv()...)
	}

	if cfg.ObserveFD > 0 {
		return runObserve(cfg, env)
	}

	applied, err := newAppliedReport(cfg.AppliedFD)
	if err != nil {
		return 0, err
	}
	if err := applyLayers(cfg, applied); err != nil {
		return 0, err
	}

	// Written before the target is reached, because on the exec-block path this
	// process is replaced by it and there is no later moment to write from. Every
	// layer above is decided by now, so the report is complete when the marker lands.
	if err := applied.write(); err != nil {
		return 0, err
	}

	return runTarget(cfg.Block, cfg.Target, env, applied)
}

// applyLayers installs the exec-block filter and the Landlock backstop for one run,
// recording in the report what actually landed. It is its own function so those
// outcomes - including the only fail-open branch in this file - are reachable in a test
// without the terminal dispatch, which either replaces this process or supervises a
// child.
func applyLayers(cfg Config, applied *appliedReport) error {
	installed := AppliedExecNone
	if cfg.Block {
		var err error
		if installed, err = installExecFilter(cfg.StrictBlock); err != nil {
			// Fail closed: never run the target unconfined while claiming to block
			// subprocesses. No applied report is written, so the host reports the exec
			// layers unenforced rather than carrying the probe's Enforced through.
			return fmt.Errorf("launcher: refusing to run - could not install the exec-block filter: %w", err)
		}
	}
	applied.record(AppliedExecFilter, installed, nil)

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
	if err := landlockRestrict(cfg.Writable); err != nil {
		fmt.Fprintf(os.Stderr, "[bento] warning: the Landlock filesystem backstop could not be applied (%v); bwrap confinement still holds\n", err)
		applied.record(AppliedLandlock, AppliedNo, err)
	} else if !landlockAvailable() {
		// Restrict is best-effort: on a kernel below the usable ABI it installs no ruleset
		// and still returns nil. Reporting that as applied would make the report assert a
		// backstop that does not exist, which is the whole failure this channel closes.
		applied.record(AppliedLandlock, AppliedAbsent, nil)
	} else {
		applied.record(AppliedLandlock, AppliedYes, nil)
	}
	return nil
}

// runTarget reaches the target the way this run's exec mode requires, and tells the
// report when it could not be reached at all.
//
// Both tiers dispatch through here so neither can grow a route past the marker that
// leaves the report claiming layers for a target that never ran: everything the
// dispatch can refuse - a nonexistent entrypoint, a relative argv[0], a target that
// could not be started - is a run whose confinement confined nothing.
func runTarget(block bool, target, env []string, applied *appliedReport) (int, error) {
	dispatch := func() (int, error) {
		if block {
			// execveat replaces this process with the target under the filters, so this
			// returns only if the transition itself fails.
			return 0, seccomp.Exec(target, env)
		}
		return superviseTarget(target, env)
	}
	code, err := dispatch()
	var ran errTargetRan
	if err != nil && !errors.As(err, &ran) {
		if reportErr := applied.targetUnreached(err); reportErr != nil {
			return 0, errors.Join(err, reportErr)
		}
	}
	return code, err
}

// errTargetRan marks a failure that happened once the target was already executing, so
// runTarget does not record it as a run the target never reached. Both epochs of the
// supervise path surface as a plain error - a target that could not be started, and a
// wait that failed with the target long since running - and a report saying nothing ran
// would be the same untruth as the one this channel exists to stop, pointing the other
// way.
type errTargetRan struct{ error }

func (e errTargetRan) Unwrap() error { return e.error }

// runObserve profiles the target: it runs under the ptrace observer (no seccomp,
// no Landlock - enforcement is off so every access is seen) and writes the paths the
// target reached, and whether it exec'd, to the inherited report descriptor for the
// host to read.
//
// "Reached" is what the decoder in observe covers: opens, the path-mutating syscalls,
// AF_UNIX bind/connect, and the existence probes (stat/access/readlink/chdir) that
// succeeded. It is not every syscall that takes a path - a probe that already failed is
// deliberately not recorded, and io_uring is blocked below rather than decoded.
func runObserve(cfg Config, env []string) (int, error) {
	// Validate the report descriptor before the run rather than after it: os.NewFile
	// never returns nil for a nonnegative fd, so an --observe-fd naming nothing would
	// otherwise survive a full traced run and only surface as an EBADF from Truncate,
	// under an error about the report rather than about the descriptor that was wrong.
	if _, err := unix.FcntlInt(uintptr(cfg.ObserveFD), unix.F_GETFD, 0); err != nil {
		return 0, fmt.Errorf("launcher: observation descriptor %d is not valid: %w", cfg.ObserveFD, err)
	}

	// Block io_uring before forking the tracee (which inherits the process-wide filter
	// and keeps it across its exec): file I/O dispatched through a ring runs in a kernel
	// worker thread and produces no ptrace syscall stop, so it would be silently absent
	// from the synthesized manifest. Forcing the target onto synchronous syscalls keeps
	// the observation complete. Fatal on error - a manifest that cannot be trusted to be
	// complete is worse than a failed profile.
	if err := seccomp.BlockIoUring(); err != nil {
		return 0, fmt.Errorf("launcher: securing complete observation: %w", err)
	}
	res, traceErr := observe.Trace(cfg.Target, env, os.Stdin, os.Stdout, os.Stderr)

	// The report is written here, after Trace returns, through the close-on-exec
	// descriptor secured in Run. Paths are quoted (%q) so a newline in a path cannot
	// forge extra R/W/EXEC records, and the completion marker is written last and only
	// on a successful trace, so a failed or truncated trace lacks it and is rejected by
	// the host. The report is NOT tamper-proof against the profiled target itself (see
	// the Truncate note below): a profiling report is trustworthy only to the degree the
	// profiled code is.
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
		// Accesses the observer could not read. Without this the host cannot tell a
		// target that touched nothing from one whose paths the observer failed to fetch,
		// and a manifest short of what the run needs looks complete.
		if res.Dropped > 0 {
			fmt.Fprintf(&b, "DROPPED %d\n", res.Dropped)
		}
		if res.SeccompKilled {
			b.WriteString("SECCOMPKILLED\n")
		}
		b.WriteString(observe.ReportEnd + "\n")
	}
	report := os.NewFile(uintptr(cfg.ObserveFD), "observe-report")
	// Truncate before writing, to discard anything a descendant wrote to this file
	// through the launcher's /proc/<pid>/fd while it was held open during the run - a
	// truncate drops that content whichever description wrote it.
	//
	// The seek is separate, and defends the write rather than the truncate: Truncate
	// resizes the file without moving this description's offset and Write is write(2)
	// rather than pwrite, so on an advanced offset the report would land past a NUL hole
	// and the host's Scanner would hit ErrTooLong at 64 KiB instead of parsing it.
	// Nothing advances the offset today - this stage does not write to the report before
	// here, and a descendant reaching the file by path gets its own open file description
	// with its own offset - so it is a correctness floor, not a live fix.
	//
	// The truncate is defense in depth against a threat nothing can reach today:
	// PR_SET_DUMPABLE(0) runs in Run before any tracee exists, so /proc/<launcher>/fd is
	// root-owned by the time the target could look. Were a
	// descendant to get there, the residual would remain: an mmap'd MAP_SHARED report
	// keeps taking forged records through plain memory stores, which raise no syscall for
	// ptrace to stop and survive this truncate. That bound is acceptable because a
	// hostile target can already inject arbitrary records by merely *attempting* opens
	// during the permissive run (inspect records the path from the syscall args whether
	// or not the open succeeds), so the report's integrity rests on the trusted-code
	// threat model and human manifest review, not on this truncate.
	if _, err := report.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("launcher: rewinding the observation report: %w", err)
	}
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
// 0/1/2 are the target's stdio and are always kept, so whatever they carry reaches the
// target untouched - see refuseNetworkStdio for the one thing they must not carry.
const firstInheritableFD = 3

// refuseNetworkStdio refuses the run when fd 0, 1, or 2 is an inherited socket that
// could reach a network.
//
// Every other inherited descriptor is dropped by dropInheritedFDs; stdio is kept
// unconditionally because it is the target's own standard streams. No fence bento
// installs revokes what they carry: a network namespace binds at socket CREATION,
// seccomp.BlockEgress filters socket(2) - creation again - and Landlock governs paths,
// not open descriptions. So read/write/sendmsg on an inherited socket are unfiltered,
// and it is a live channel under a policy whose claim is that the target cannot open
// one at all.
//
// It is not an embedding-API-only concern. os/exec passes the raw descriptor whenever
// enforce.Process.Stdin/Stdout is an *os.File - and the CLI passes os.Stdin, so any
// parent that starts `bento run` with a socket on fd 0 (socket activation, an
// inetd-style supervisor, a daemon spawning bento) reaches it with no embedder
// involved. A plain io.Reader is funnelled through a pipe and the socket does not
// survive, which is why only the *os.File case gets here.
//
// So it runs whatever the policy's egress: with none granted an inherited socket
// falsifies the claim outright, and with egress granted it bypasses the host proxy's
// allowlist. The one deliberate case - the socket-activation pattern, where a server
// passes a per-connection handler its accepted conn - opts in through
// enforce.Process.AllowNetworkStdio, which no manifest and no CLI flag can set.
func refuseNetworkStdio() error {
	if errs := networkStdioRefusals(); len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// networkStdioRefusals reports one error per standard descriptor that fails the check,
// rather than the first. The opt-in in Run may waive a socket but never an
// unclassifiable descriptor, and it can only tell them apart if it sees every fd:
// stopping at the first would let a waived socket on fd 0 hide a descriptor on fd 1
// that could not be examined at all.
func networkStdioRefusals() []error {
	var errs []error
	for fd := range firstInheritableFD {
		if err := refuseNetworkFD(fd); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// refuseNetworkFD refuses one descriptor that is a socket of a family able to reach a
// network. The families are an ALLOWLIST, mirroring egressFilter's: AF_UNIX and
// AF_NETLINK pass and every other family is refused, because a denylist would miss a
// family we did not enumerate and "no egress" must not rest on remembering every wire
// family. Enumerating AF_INET and AF_INET6 would let an AF_PACKET descriptor - raw
// frames on the host's wire - through the check written to stop exactly that.
func refuseNetworkFD(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		// Nothing is open there, so nothing was inherited on it and the target gets the
		// same EBADF. Any other errno means the descriptor could not be classified, which
		// is not a thing to assume benign.
		if err == unix.EBADF {
			return nil
		}
		return fmt.Errorf("launcher: refusing to run - standard descriptor %d could not be examined: %w", fd, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil
	}
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return fmt.Errorf("launcher: refusing to run - standard descriptor %d is a socket whose domain could not be read: %w", fd, err)
	}
	if domain != unix.AF_UNIX && domain != unix.AF_NETLINK {
		return fmt.Errorf("launcher: refusing to run - %w", &networkStdio{fd: fd, domain: domain})
	}
	return nil
}

// networkStdio is the one refusal above that an embedder can opt out of, so it is
// typed: Run tells it from the neighbouring "could not be classified" failures, which
// stay fatal, and reuses its text for the opt-in warning.
type networkStdio struct {
	fd     int
	domain int
}

func (e *networkStdio) Error() string {
	return fmt.Sprintf("standard descriptor %d is an inherited socket of family %d; no sandbox layer can revoke an already-open network channel", e.fd, e.domain)
}

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
// and this architecture provides, returning which one landed (AppliedExecStrict or
// AppliedExecBasic). none-strict gets the fork/clone-blocking filter on amd64;
// where that is unavailable it falls back to the execve-only block, and the
// returned value is what tells the host to report the exec-strict layer degraded,
// so the gap is never silent.
func installExecFilter(strict bool) (string, error) {
	if strict && strictExecSupported() {
		if err := blockExecStrict(); err != nil {
			return "", err
		}
		return AppliedExecStrict, nil
	}
	if err := installExecBlock(); err != nil {
		return "", err
	}
	return AppliedExecBasic, nil
}

// startBridge launches the bridge as a separate child process before any filter
// is installed. It must be its own process, not a goroutine: when the exec-block
// filter is in play the launcher execveats the target and is replaced, which
// would kill an in-process bridge. As a child it survives until the pid namespace
// is torn down at the end of the run.
func startBridge(socket string) error {
	// A readiness pipe: the bridge writes one byte after it is non-dumpable and
	// listening, and this call blocks until then, so the launcher only execveat's the
	// target once the bridge can no longer be ptrace-hijacked (its dumpable startup
	// window is over) and its listener is up. The write end is passed to the bridge as
	// an extra file (fd bridgeReadyFD); the launcher drops its own write end so the
	// bridge is the sole writer, and a bridge that dies before signaling closes the
	// pipe - the read then returns EOF and the run is refused rather than started with
	// an attackable or absent bridge.
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("launcher: bridge readiness pipe: %w", err)
	}
	defer r.Close()
	cmd := exec.Command("/proc/self/exe", SentinelBridge, socket)
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{w}
	if err := cmd.Start(); err != nil {
		w.Close()
		return fmt.Errorf("launcher: starting egress bridge: %w", err)
	}
	w.Close()
	return awaitBridgeReady(r)
}

// awaitBridgeReady blocks until the bridge writes its readiness byte, or returns an
// error if the pipe closes first (the bridge died before signaling). EOF is the
// liveness signal - the launcher is the sole holder of the read end and dropped the
// write end, so the only remaining writer is the bridge; its death closes the pipe.
func awaitBridgeReady(r *os.File) error {
	// Bounded, like every other wait in this file. The bridge only has to re-exec and
	// bind a loopback port, so a wait this long means it is wedged rather than slow, and
	// an unbounded read would hang the run with no output at all - a caller driving
	// launcher.Run directly has nothing else watching it.
	if err := r.SetReadDeadline(time.Now().Add(bridgeReadyTimeout)); err != nil {
		return fmt.Errorf("launcher: bounding the egress bridge wait: %w", err)
	}
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return fmt.Errorf("launcher: egress bridge did not come up: %w", err)
	}
	return nil
}

// bridgeReadyTimeout bounds the wait for the bridge's readiness byte.
var bridgeReadyTimeout = 30 * time.Second

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
// of a subprocess-spawning target reparent to whichever ancestor is reaping: under
// bwrap that is its own init as PID 1 (this launcher is PID 2), and the whole pid
// namespace is torn down at the end of the run regardless. RunDegraded calls this
// with no pid namespace at all, so there an orphan reparents to the host's init
// and is reaped there instead; the degraded tier's own leaked-process cleanup is
// the process-group sweep, not this loop.
func superviseTarget(target, env []string) (int, error) {
	// exec.Command does a $PATH lookup when target[0] has no slash, resolving against
	// the target's own (policy-supplied) PATH - a different binary than intended. The
	// Block path (seccomp.Exec via execveat) resolves a relative argv[0] against the
	// working directory rather than a PATH, so it is the milder failure, but it is a
	// failure too; both paths refuse one, which is what keeps the exec modes from
	// diverging on the same target.
	if len(target) == 0 || !filepath.IsAbs(target[0]) {
		return 0, fmt.Errorf("launcher: target command must be an absolute path, got %q", target)
	}
	cmd := exec.Command(target[0], target[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("launcher: starting target: %w", err)
	}
	// Past Start the target is running, so a failure below is no longer "the target was
	// never reached" - reapUntil can fail with the target still executing (Wait4 returns
	// ECHILD when an inherited SIGCHLD=SIG_IGN has the kernel auto-reaping children).
	code, err := reapChildren(cmd.Process.Pid)
	if err != nil {
		return 0, errTargetRan{err}
	}
	return code, nil
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
	// The bridge is a separate process the launcher forks before it execveat's the
	// target; after that transition the bridge is a child of the target and shares
	// its PID namespace, unconfined by the exec-block filter and the Landlock backstop
	// (which the launcher applies only to itself). Its own exec reset dumpable to 1,
	// so mark it non-dumpable: without this, an untrusted target could PTRACE_ATTACH
	// the bridge (a descendant, permitted under yama ptrace_scope<=1) and inject an
	// execve, spawning a subprocess in violation of exec: none. Non-dumpable denies
	// the attach to any non-root, non-CAP_SYS_PTRACE tracer regardless of yama scope.
	if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return fmt.Errorf("bridge: making the bridge non-dumpable: %w", errno)
	}
	l, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("bridge: cannot listen on %s inside the sandbox: %w", proxyAddr, err)
	}
	defer l.Close()
	// Signal the launcher that the bridge is now both non-dumpable and listening, so
	// it may safely execveat the target (see startBridge). fd bridgeReadyFD is the
	// write end of the readiness pipe, passed via ExtraFiles.
	ready := os.NewFile(bridgeReadyFD, "bridge-ready")
	if _, err := ready.Write([]byte{1}); err != nil {
		return fmt.Errorf("bridge: signaling readiness: %w", err)
	}
	ready.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Anything short of a closed listener is transient - EMFILE under a burst,
			// ECONNABORTED from a client that went away - and must not end the bridge.
			// Nothing supervises this process once the launcher has execveat'd the target,
			// so a bridge that returns here takes the run's egress with it while the applied
			// report and the host's result both still say the network layer is enforced.
			// Back off and keep accepting; the warning is the only channel left.
			fmt.Fprintf(os.Stderr, "[bento] warning: the in-sandbox egress bridge could not accept a connection (%v); still accepting\n", err)
			time.Sleep(acceptRetryDelay)
			continue
		}
		go bridgeConn(c, socket)
	}
}

// acceptRetryDelay paces the bridge's retries after a failed Accept, so a persistent
// failure cannot spin the loop.
var acceptRetryDelay = 100 * time.Millisecond

// bridgeReadyFD is the descriptor the launcher passes the bridge (via ExtraFiles, so
// it lands at fd 3) as the write end of the readiness pipe.
const bridgeReadyFD = 3

// bridgeConn forwards one loopback connection to the host-side proxy socket in
// both directions, half-closing each side when its source is done so a
// half-closed tunnel is not truncated.
func bridgeConn(client net.Conn, socket string) {
	defer client.Close()
	upstream, err := net.Dial("unix", socket)
	if err != nil {
		// The target sees only a connection that closed on it, which is indistinguishable
		// from the proxy refusing the destination. Say which it was: every other shortfall
		// in this file reaches the operator through the applied report or stderr, and the
		// bridge has no report to write to.
		fmt.Fprintf(os.Stderr, "[bento] warning: the in-sandbox egress bridge could not reach the host proxy socket (%v); this connection was dropped\n", err)
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
		_ = cw.CloseWrite()
		return
	}
	c.SetDeadline(time.Now())
}
