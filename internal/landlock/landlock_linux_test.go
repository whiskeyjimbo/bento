package landlock

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildProbe compiles the probe the way make build ships bento, and returns its path.
//
// CGO_ENABLED=0 is the point, not boilerplate: where go-landlock reaches the other
// threads from userspace it selects a different mechanism per build tag - cgo routes
// the restrict syscall through libpsx and adds a /proc/$PID/task workaround rule,
// no-cgo uses syscall.AllThreadsSyscall and adds neither. A probe built with cgo
// would verify confinement on a code path the shipped binary never runs.
//
// On Landlock ABI 8 and above go-landlock takes neither: it passes the kernel's own
// TSYNC flag (restrict.go, useTsync := abi.version >= 8) and the build-tag divergence
// disappears. So this forces the shipped build, but on a new enough kernel there is
// no userspace mechanism left for it to be the shipped version OF - which is why
// TestRestrictReachesAPreexistingThread reports which side of that line the host fell
// on rather than letting a green run stand in for fan-out coverage.
func buildProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available to build the probe")
	}
	bin := filepath.Join(t.TempDir(), "probe")
	build := exec.Command("go", "build", "-o", bin, "github.com/whiskeyjimbo/bento/internal/landlock/internal/probe")
	build.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building probe: %v\n%s", err, out)
	}
	return bin
}

func TestAvailableOnLinux(t *testing.T) {
	if !Available() {
		t.Skip("Landlock not present on this kernel")
	}
}

// The regression: Available() must report true on a Landlock-capable kernel even
// when /sys/kernel/security is unavailable - the container case. The old
// implementation parsed /sys/kernel/security/lsm and returned false there, wrongly
// reporting "no backstop" while the syscalls worked. This masks that path with a
// tmpfs under bwrap and asserts Available() still says true.
func TestAvailableWithoutSecurityfs(t *testing.T) {
	if !Available() {
		t.Skip("Landlock not present on this kernel")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not available to mask /sys/kernel/security")
	}
	bin := buildProbe(t)

	// --tmpfs over /sys/kernel/security makes the lsm file unreadable, exactly as a
	// restricted-/sys container does, while the Landlock syscalls stay available.
	out, err := exec.Command(
		bwrap,
		"--dev-bind", "/", "/",
		"--tmpfs", "/sys/kernel/security",
		bin, "available",
	).CombinedOutput()
	if err != nil {
		t.Skipf("bwrap could not run the probe here (%v): %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "available=true" {
		t.Errorf("Available() under a masked /sys/kernel/security = %q, want available=true", got)
	}
}

// Landlock must actually confine filesystem access on this host - that it loads
// without error is not the same as that it denies. The probe confines itself to
// one directory in a fresh process; a path inside must stay readable and a path
// outside must be denied.
func TestRestrictConfinesReads(t *testing.T) {
	if !Available() {
		t.Skip("Landlock not present on this kernel")
	}
	bin := buildProbe(t)

	allowed := t.TempDir()
	inside := filepath.Join(allowed, "in.txt")
	if err := os.WriteFile(inside, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An outside path the process can read without Landlock, so a denial proves
	// Landlock - not permissions - is what confines.
	outside := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(bin, allowed, inside, outside).CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "inside=OK") {
		t.Errorf("a path inside the allowed dir should stay readable: %q", got)
	}
	if !strings.Contains(got, "outside=DENIED") {
		t.Errorf("a path outside the allowed dir must be denied by Landlock: %q", got)
	}

	// A regular file in the writable set must get a file rule. Routed to RWDirs it
	// returns EINVAL, and RestrictPaths applies the ruleset as a whole - so the caller
	// gets an error and (in the launcher) proceeds with no rules at all. Here the probe
	// exits non-zero on that error, which is what this catches. Only the real kernel
	// shows it:
	// the rule kinds are indistinguishable until the ruleset is submitted, which is why
	// this goes through the probe rather than asserting on the rules bento builds.
	t.Run("a file in the writable set does not discard the ruleset", func(t *testing.T) {
		out, err := exec.Command(bin, allowed, inside, outside, inside).CombinedOutput()
		if err != nil {
			t.Fatalf("probe with a file write path: %v\n%s", err, out)
		}
		got := strings.TrimSpace(string(out))
		if !strings.Contains(got, "outside=DENIED") {
			t.Errorf("a file in the writable set left the process unconfined: %q", got)
		}
		if !strings.Contains(got, "inside=OK") {
			t.Errorf("the granted tree stopped being readable: %q", got)
		}
	})
}

// Landlock is applied per thread, and the Go runtime has several. This asserts the
// property every mechanism for covering them exists to deliver: a thread that was
// already parked when the ruleset was applied is confined too. Started before the
// restrict call on purpose; one started after would inherit the restriction through
// clone regardless and prove nothing.
//
// The property holds under either mechanism, so it is asserted unconditionally. WHICH
// one delivered it is the part a pass cannot show - the end state is identical - so the
// subtest below reports that separately rather than leaving a green run to be misread as
// coverage of the userspace fan-out. That distinction is the whole subject of the
// CGO_ENABLED=0 flip in buildProbe: forcing the shipped no-cgo mechanism means nothing
// on a kernel where go-landlock uses neither userspace mechanism.
//
// This test lives in the internal package for one reason: effectiveABI is what decides
// it, and re-deriving the ABI here - the raw syscall plus go-landlock's errata downgrade
// plus the build-tag floor - would put a second copy of security-relevant detection logic
// in a test, which is how a test comes to validate a hybrid nothing ships.
func TestRestrictReachesAPreexistingThread(t *testing.T) {
	if !Available() {
		t.Skip("Landlock not present on this kernel")
	}
	bin := buildProbe(t)

	allowed := t.TempDir()
	inside := filepath.Join(allowed, "in.txt")
	if err := os.WriteFile(inside, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(bin, "otherthread", allowed, inside, outside).CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "otherthread_outside=DENIED") {
		t.Errorf("a thread that existed before the ruleset was applied is unconfined: %q", got)
	}
	if !strings.Contains(got, "otherthread_inside=OK") {
		t.Errorf("the granted tree stopped being readable from the other thread: %q", got)
	}

	// Reaching this subtest without a skip is the record that the assertions above ran
	// against the userspace fan-out. It cannot observe the syscall path directly - both
	// mechanisms leave the same end state - so it gates on the same version go-landlock
	// gates on and says which side of it this host fell.
	t.Run("delivered by the shipped userspace fan-out", func(t *testing.T) {
		if abi := effectiveABI(); abi >= tsyncABI {
			t.Skipf("effective ABI %d: go-landlock passes the kernel's own TSYNC flag on "+
				"LandlockRestrictSelf (restrict.go, useTsync := abi.version >= %d) and never calls "+
				"AllThreadsLandlockRestrictSelf, so the no-cgo syscall.AllThreadsSyscall path "+
				"buildProbe forces did not run and the assertions above do not cover it",
				abi, tsyncABI)
		}
	})
}

// tsyncABI is the Landlock ABI at which go-landlock stops fanning the restrict syscall
// out across threads from userspace and passes the kernel's own TSYNC flag instead
// (v0.9.0 restrict.go: useTsync := abi.version >= 8). Below it the mechanism is the one
// buildProbe's CGO_ENABLED=0 selects; at or above it neither userspace mechanism runs.
//
// Under the landlocktsync build tag the fan-out is unreachable in every configuration,
// so that build never covers it: minRequiredABI is 8 there, so a kernel below 8 floors
// to 0 and Available() sends the test to its skip before the probe is built, while 8 and
// above takes the kernel's TSYNC. That also contains a divergence worth naming: the probe
// is built without propagating build tags, so under that tag the test binary floors at 8
// while the probe floors at 0. The two views can only disagree below ABI 8, and there
// Available() skips before the probe is ever built - so the disagreement never reaches a
// running probe.
const tsyncABI = 8

// A pathname AF_UNIX socket outside the granted tree must stay connectable. Landlock
// restricts a right that is in handled_access_fs whether or not any rule grants it, and
// none of the rule helpers this package builds on grant ABI 9's resolve_unix - so a
// handled set that reached V9 would deny every connect to dbus, X11, /dev/log and glibc's
// NSS socket, with the run still reporting the layer applied. handledFS pins the handled
// set at ABI 8 to keep that from happening; this observes the result from outside.
//
// Below ABI 9 the kernel cannot restrict the connect at all, so this passes trivially
// there. It is not skipped on those kernels: the assertion is what the sandbox must do
// on every kernel, and it starts biting by itself on the first host that has ABI 9.
func TestUnixConnectOutsideTheGrantStaysAllowed(t *testing.T) {
	if !Available() {
		t.Skip("Landlock not present on this kernel")
	}
	bin := buildProbe(t)

	// The listener is bound here, in the parent, so its server is outside the Landlock
	// domain the probe creates - the only case resolve_unix covers.
	socket := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	out, err := exec.Command(bin, "unixconnect", t.TempDir(), socket).CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); !strings.Contains(got, "unixconnect=OK") {
		t.Errorf("connecting to a pathname unix socket outside the grant was denied: %q", got)
	}
}

// The degraded tier handles resolve_unix and grants it back only on the write rules, and
// that asymmetry has to be observed against a real kernel: which rights a rule ends up
// carrying is decided inside go-landlock's BestEffort downgrade, so nothing about it is
// visible from the rules this package builds.
//
// The outside read is the assertion that must not be dropped as redundant. The write
// rules request a right that leaves the handled set the moment BestEffort downgrades
// below ABI 9 - every kernel in the field today - and go-landlock has a shape where an
// unsatisfiable rule collapses the whole ruleset to v0 and returns nil (it takes that
// route only for refer, which is exactly why the resolve_unix path is worth pinning from
// outside). A collapse leaves RestrictDegraded returning no error and the launcher
// recording the layer applied, with the target unconfined; only reading a non-granted
// path catches it.
//
// The two socket assertions are ABI-conditional, since below 9 the kernel cannot restrict
// either connect - so on those kernels this is the collapse regression test and no more.
func TestRestrictDegradedGrantsResolveUnixOnWritesOnly(t *testing.T) {
	if !Available() {
		t.Skip("Landlock not present on this kernel")
	}
	bin := buildProbe(t)

	read, write := t.TempDir(), t.TempDir()
	outside := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Bound in the parent, so its server is outside the domain the probe creates - the
	// only case resolve_unix covers - and under no grant of the probe's.
	socket := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	out, err := exec.Command(bin, "degraded", read, write, outside, socket).CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "degraded_outside=DENIED") {
		t.Errorf("the degraded ruleset confined nothing - a path outside every grant stayed readable: %q", got)
	}
	if !strings.Contains(got, "degraded_ownsocket=OK") {
		t.Errorf("a socket the target created under its own write grant must stay reachable: %q", got)
	}
	wantOutside := "degraded_unixconnect=OK"
	if ResolveUnixRestricted() {
		wantOutside = "degraded_unixconnect=DENIED"
	}
	if !strings.Contains(got, wantOutside) {
		t.Errorf("connecting to a socket outside every grant: got %q, want %s (ABI %d)", got, wantOutside, effectiveABI())
	}
}
