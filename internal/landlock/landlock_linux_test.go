package landlock

import (
	"bytes"
	"debug/elf"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock"
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

// This is the executable evidence for withholding an exec allowlist. No policy reaches
// RestrictExecAllowlist - there is no exec: allowlist mode - so what this test pins is
// not a shipped guarantee but the kernel behaviour the ADR rests on, kept runnable so
// the decision can be re-checked rather than re-argued.
//
// The allowed and other arms are the claim itself. The read arm is the control that
// separates "execute was withheld" from "the ruleset denied everything": an allowlist
// takes away execute, not read, and a mode that also broke reads would pass the first
// two arms while making every run useless.
//
// The loader arm is the one that decides whether the mode bounds anything at all. A
// dynamically linked binary is executed through its PT_INTERP, so making one runnable
// means granting the loader execute - and a loader with execute runs any readable ELF
// handed to it as an argument, including one the target wrote itself. Asserting the
// loader is DENIED is the finding: it is what forces statically linked entries, and
// forcing those is what made the mode too narrow to serve any job class - a script under
// an interpreter needs a dynamic binary to be executable. If this arm ever reports OK on
// some future kernel, the first reason for withholding an exec allowlist has changed
// and the decision is worth
// reopening.
func TestExecAllowlistPermitsOnlyTheAllowlistedBinary(t *testing.T) {
	if !Available() {
		t.Skip("Landlock not present on this kernel")
	}
	// buildProbe builds with CGO_ENABLED=0, so the probe is itself a statically linked
	// binary - which is what an allowlist entry has to be. Using it as the subject keeps
	// the test from depending on a static binary happening to exist on the host.
	bin := buildProbe(t)
	other := filepath.Join(t.TempDir(), "other")
	copyFile(t, bin, other)

	out, err := exec.Command(bin, "execallow", t.TempDir(), bin, other, loaderPath(t)).CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	for _, arm := range []struct{ want, why string }{
		{"execallow_allowed=OK", "the allowlisted binary must stay spawnable, or the mode can run nothing"},
		{"execallow_other=DENIED", "a readable binary that is not on the allowlist must not be spawnable"},
		{"execallow_read=OK", "an allowlist withholds execute, not read; a non-allowlisted file must stay readable"},
		{"execallow_loader=DENIED", "the dynamic loader must not be executable: with it, loader <any readable ELF> spawns anything and the allowlist bounds nothing"},
	} {
		if !strings.Contains(got, arm.want) {
			t.Errorf("%s\n got: %q\nwant: %s", arm.why, got, arm.want)
		}
	}
}

// loaderPath is the dynamic loader this host executes a dynamic binary through, read as
// the PT_INTERP of one rather than guessed from a list of well-known names - it is the
// same fact the kernel acts on, and the arm that uses it is only meaningful if it names
// the real loader.
func loaderPath(t *testing.T) string {
	t.Helper()
	f, err := elf.Open("/bin/sh")
	if err != nil {
		t.Skipf("cannot read /bin/sh to find the dynamic loader: %v", err)
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		interp, err := io.ReadAll(p.Open())
		if err != nil {
			t.Fatalf("reading PT_INTERP: %v", err)
		}
		return string(bytes.TrimRight(interp, "\x00"))
	}
	t.Skip("/bin/sh is statically linked; this host has no loader to probe")
	return ""
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
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
// BOTH sockets are bound here in the parent, before the probe exists, so both servers are
// outside the domain the probe creates - the only case resolve_unix governs. A socket the
// probe bound itself would be in-domain and stay reachable whether or not the write rules
// carry the right, which would leave the granted half of this test passing with the grant
// deleted. The two sockets differ only in which grant covers their path, which is the
// asymmetry under test.
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
	ungranted := listen(t, filepath.Join(t.TempDir(), "s.sock"))
	granted := listen(t, filepath.Join(write, "granted.sock"))

	out, err := exec.Command(bin, "degraded", read, write, outside, ungranted, granted).CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "degraded_outside=DENIED") {
		t.Errorf("the degraded ruleset confined nothing - a path outside every grant stayed readable: %q", got)
	}
	if !strings.Contains(got, "degraded_grantedsocket=OK") {
		t.Errorf("a socket under the target's write grant must stay reachable - the write rules "+
			"grant resolve_unix for exactly this: %q", got)
	}
	wantOutside := "degraded_unixconnect=OK"
	if ResolveUnixRestricted() {
		wantOutside = "degraded_unixconnect=DENIED"
	}
	if !strings.Contains(got, wantOutside) {
		t.Errorf("connecting to a socket outside every grant: got %q, want %s (ABI %d)", got, wantOutside, effectiveABI())
	}
}

// The degraded tier's cross-process memory guarantee rests on Landlock's ptrace check,
// NOT on /proc being absent from the read set - the read set is user-supplied, and
// nothing refuses a manifest that says read: /, which grants /proc recursively along
// with everything else. What actually holds is that Landlock refuses ptrace_may_access
// against a process outside the domain, and /proc/<pid>/mem goes through mm_access,
// which is that check. So the broadest read grant expressible still cannot reach a host
// process's address space.
//
// The probe grants "/" deliberately: a narrower grant would leave the reason for the
// denial ambiguous between the read set and the ptrace check, and the read set is the
// half that does not hold.
func TestRestrictDegradedDeniesOutsideProcessMemory(t *testing.T) {
	if !Available() {
		t.Skip("Landlock not present on this kernel")
	}
	bin := buildProbe(t)

	out, err := exec.Command(bin, "procmem", "/").CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	// Under ptrace_scope 2 or 3 the host forbids the read whatever Landlock does, so a
	// DENIED result there would credit Landlock with a denial it did not make.
	if strings.Contains(got, "procmem_baseline=DENIED") || strings.Contains(got, "procfd_baseline=DENIED") {
		t.Skipf("this host forbids the unrestricted reach too, so the restricted one proves nothing: %q", got)
	}
	if !strings.Contains(got, "procmem_restricted=DENIED") {
		t.Errorf("a read grant of \"/\" reopened another process's memory through /proc/<pid>/mem: %q", got)
	}
	if !strings.Contains(got, "procfd_restricted=DENIED") {
		t.Errorf("a read grant of \"/\" reopened another process's descriptors through /proc/<pid>/fd: %q", got)
	}

	// The control. Without it the denial above could be any blanket ptrace refusal
	// rather than Landlock's domain comparison, and the test would keep passing if the
	// domain check were removed and replaced with something that denied everything.
	out, err = exec.Command(bin, "procmemchild", "/").CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	got = strings.TrimSpace(string(out))
	if !strings.Contains(got, "procmem_samedomain=OK") || !strings.Contains(got, "procfd_samedomain=OK") {
		t.Errorf("a process inside the domain must stay reachable, or the denials above are not the domain check: %q", got)
	}
}

// listen binds a unix listener at path and serves it for the test's duration, returning
// path. The accept loop only has to complete the handshake - the probe reports whether the
// connect succeeded, and nothing is sent.
func listen(t *testing.T, path string) string {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return path
}

// Landlock denies rename(2) and link(2) ACROSS directories unless the write rules grant
// refer, even when both directories sit inside the same write grant - so the backstop
// broke the write-a-temp-file-then-rename-into-place shape most tools use to write
// atomically, with an EXDEV that names no layer. This only shows against the real kernel:
// the granted-versus-handled question is answerable from the rules (the invariant test in
// abi_internal_linux_test.go), but whether the kernel then permits the rename is not.
//
// The same-directory arm is the control. Without refer it stays OK while the two
// cross-directory arms fail, which is exactly why the bug survived: the write grant looks
// like it works.
func TestRestrictPermitsReparentingInsideAWriteGrant(t *testing.T) {
	if !Available() {
		t.Skip("Landlock not present on this kernel")
	}
	if !referSupported() {
		t.Skipf("effective ABI %d: refer arrived in ABI 2, and below it the kernel denies "+
			"cross-directory reparenting under any ruleset", effectiveABI())
	}
	bin := buildProbe(t)

	// One tree, so the read root covers the write grant and the ungranted directory both -
	// the escape arm has to fail for want of a WRITE grant, not for want of a path.
	root := t.TempDir()
	write := filepath.Join(root, "write")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{filepath.Join(write, "a"), filepath.Join(write, "b"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(write, "a", "f"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(bin, "reparent", root, write, outside).CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "samedir=OK") {
		t.Fatalf("a rename within one directory of the write grant was denied, so the grant "+
			"itself is broken and the cross-directory arms below prove nothing: %q", got)
	}
	if !strings.Contains(got, "crossdir=OK") {
		t.Errorf("a rename between two directories inside the same write grant was denied; "+
			"the write rules are not granting refer: %q", got)
	}
	if !strings.Contains(got, "crosslink=OK") {
		t.Errorf("a link between two directories inside the same write grant was denied; "+
			"refer governs link(2) as well as rename(2): %q", got)
	}
	if !strings.Contains(got, "escape=DENIED") {
		t.Errorf("a rename out of the write grant into the read-only tree succeeded, so "+
			"granting refer widened reparenting past the write grants: %q", got)
	}
}

// The whole IPC-scoping restriction rests on the V6 preset carrying a non-empty scoped
// set: RestrictScoped keeps only that field, and an empty one restricts nothing and
// returns success, which no run on any kernel would notice.
func TestScopedIPCCarriesBothScopes(t *testing.T) {
	// String() abbreviates a full set to "all"; V5, the last ABI with no scopes at all,
	// is what an empty one looks like, and is here so the assertion cannot pass on it.
	got, empty := scopedIPC.String(), ll.V5.String()
	if !strings.Contains(got, "Scoped: all") {
		t.Errorf("scopedIPC = %s, want a full scoped set", got)
	}
	if strings.Contains(empty, "Scoped: all") {
		t.Fatalf("V5 = %s: this assertion cannot tell a full scoped set from an empty one", empty)
	}
}
