//go:build linux

package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The bwrap tier installs no terminal-injection filter. Where the degraded tier blocks
// TIOCSTI/TIOCLINUX with seccomp, the full tier relies entirely on bwrap's --new-session
// calling setsid(), which leaves the target with no controlling terminal - and TIOCSTI is
// refused on a terminal that is not yours. If it ever stops holding, a sandboxed program can
// push characters into the terminal that the user's shell reads back as typed input after
// the run exits.
//
// This asserts the guarantee end to end, over a real terminal the launching side owns, and
// skips where the host cannot give it one. canUnshare now also proves it from inside on
// every run, which is what covers the hosts this test can only skip on; see sessionProof and
// TestTheNamespaceProbeProvesTheNewSessionTook below.
//
// Detachment is asserted through open("/dev/tty") rather than through TIOCSTI itself,
// because that call is the definition of "do I have a controlling terminal" and it stays
// meaningful on kernels where dev.tty.legacy_tiocsti is 0 and TIOCSTI is refused for
// everyone. TIOCSTI is still attempted, so a host that does allow it gets the direct
// assertion too.
func buildTTYProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		skipMissingDep(t, "go toolchain not available to build the probe")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "probe.go")
	const prog = `package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const tiocsti = 0x5412

func main() {
	// Opening /dev/tty succeeds only for a process that has a controlling terminal;
	// after setsid() there is none and the kernel answers ENXIO.
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		f.Close()
		fmt.Println("HASCTTY")
	} else {
		fmt.Println("NOCTTY", err)
	}
	// The injection itself, against whatever sits on fd 0.
	var b byte = 'x'
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, 0, tiocsti, uintptr(unsafe.Pointer(&b))); errno == 0 {
		fmt.Println("TIOCSTI_INJECTED")
	} else {
		fmt.Println("TIOCSTI_REFUSED", errno)
	}
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "ttyprobe")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "HOME="+toolchainHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building tty probe: %v\n%s", err, out)
	}
	return bin
}

// openPTY returns a freshly allocated master/slave pair. No cgo: /dev/ptmx plus the
// unlock and pty-number ioctls is what openpty(3) does underneath.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skip("no /dev/ptmx on this host")
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Skipf("cannot unlock a pty here: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Skipf("cannot read the pty number here: %v", err)
	}
	s, err := os.OpenFile(filepath.Join("/dev/pts", strconv.Itoa(n)), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Skipf("cannot open the pty slave: %v", err)
	}
	t.Cleanup(func() { s.Close(); m.Close() })
	return m, s
}

// The launching process must itself own the pty as its controlling terminal, or the whole
// exercise is vacuous: `go test` normally runs with no controlling terminal at all, so a
// sandboxed child reports "none" for free and the assertion passes whether or not
// --new-session did anything. Handing a pty over on fd 0 does not confer it either -
// adopting a controlling terminal takes TIOCSCTTY, which is what Setctty below does. So
// the run happens in a re-exec'd helper that is a session leader owning the pty, the same
// shape the seccomp terminal test uses for its own process-wide effects.
func TestBwrapTierDetachesControllingTerminal(t *testing.T) {
	requireSandbox(t)
	probe := buildTTYProbe(t)
	bento := testBento(t)
	_, slave := openPTY(t)

	cmd := exec.Command(os.Args[0], "-test.run=TestBwrapTierDetachesControllingTerminalHelper", "-test.v")
	cmd.Env = append(os.Environ(),
		"BENTO_TEST_CTTY=1", "BENTO_TEST_PROBE="+probe, "BENTO_TEST_BENTO="+bento)
	cmd.Stdin = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("controlling-terminal helper failed: %v\n%s", err, out)
	}
	got := string(out)

	// Control: the helper really did own the terminal, so "detached" below means the
	// sandbox took it away rather than there never having been one.
	if !strings.Contains(got, "CONTROL_HASCTTY") {
		t.Skipf("could not give the helper a controlling terminal on this host, so the sandboxed result would be vacuous:\n%s", got)
	}
	if !strings.Contains(got, "SANDBOX_NOCTTY") {
		t.Errorf("the bwrap tier must leave the target with no controlling terminal, or TIOCSTI injection into the user's shell is open:\n%s", got)
	}
	if strings.Contains(got, "SANDBOX_TIOCSTI_INJECTED") {
		t.Errorf("the target injected into the terminal through fd 0:\n%s", got)
	}
}

// TestBwrapTierDetachesControllingTerminalHelper is the child half: it owns the pty as its
// controlling terminal, confirms that, then runs the probe under a real sandbox passing
// that same terminal in. It is inert unless the parent set the trigger env var.
func TestBwrapTierDetachesControllingTerminalHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_CTTY") != "1" {
		t.Skip("child helper for TestBwrapTierDetachesControllingTerminal")
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// Report and exit CLEANLY: failing to obtain a controlling terminal is a
		// property of the host, not a broken guarantee, and the parent can only tell
		// the two apart if this half distinguishes them. Fataling here would exit
		// non-zero and the parent would call it a failure instead of skipping.
		t.Logf("CONTROL_NOCTTY %v", err)
		return
	}
	f.Close()
	t.Log("CONTROL_HASCTTY")

	probe := os.Getenv("BENTO_TEST_PROBE")
	var out strings.Builder
	p := &policy.Policy{
		Entrypoint: probe,
		Read:       []string{filepath.Dir(probe)},
		Exec:       policy.ExecAll,
	}
	// os.Stdin is the pty this process holds as its controlling terminal, so the target
	// would inherit it too if bwrap did not start a new session.
	if _, err := enforcerUsing(os.Getenv("BENTO_TEST_BENTO")).Run(context.Background(), p,
		enforce.Process{Stdin: os.Stdin, Stdout: &out, Stderr: &out}, enforce.RunOptions{}); err != nil {
		t.Fatalf("sandboxed run: %v (output: %s)", err, out.String())
	}
	for line := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
		t.Log("SANDBOX_" + line)
	}
}

// The test above needs a controlling terminal the launching process owns, and skips without
// one - which is most CI runners, and every host where /dev/tty answers ENXIO. So the flag
// the whole defence rests on was walked only where a pty was available. canUnshare now
// exercises it from the shared sessionFlags and the canary proves from inside that it took,
// which runs on every Run and every doctor probe on every host.
//
// The proof reads the session id from the fresh procfs inside the PID namespace, where a
// session leader outside that namespace reads back as 0. Nonzero means the sandbox's own
// session leader is inside it, which only setsid() produces.
func TestTheNamespaceProbeProvesTheNewSessionTook(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		skipMissingDep(t, "bwrap not installed")
	}
	ctx := context.Background()

	// Positive control first: a proof a working host fails refuses every run here, which is
	// worse than the gap it closes. A host that genuinely refuses the namespace skips; a
	// probe that could not answer is the failure being guarded against, so it fails.
	if cerr := canUnshare(ctx, bwrap); cerr != nil {
		if ns, reason := classifyUnshare(cerr); ns == namespacesBlocked {
			skipMissingDep(t, "this host refuses the namespace: %s", reason)
		}
		t.Fatalf("real bwrap did not satisfy the session proof, which would refuse every run on a working host: %v", cerr)
	}

	// The failure the check exists for: bwrap that does not detach the session, whether
	// because the flag was dropped here or because a wrapper swallowed it.
	orig := sessionFlags
	sessionFlags = nil
	t.Cleanup(func() { sessionFlags = orig })

	cerr := canUnshare(ctx, bwrap)
	if cerr == nil {
		t.Fatal("canUnshare passed a sandbox built with no --new-session, so the target keeps the invoking terminal and TIOCSTI is host command execution as the user")
	}
	if !strings.Contains(cerr.Error(), "session of its own") {
		t.Errorf("reason = %q, want it to name the missing session rather than a namespace diagnosis", cerr)
	}
	if ns, _ := classifyUnshare(cerr); ns != namespacesUnknown {
		t.Errorf("ns = %v, want unknown: unknown refuses the run, where blocked would offer the degraded tier over an unverified fence", ns)
	}
}
