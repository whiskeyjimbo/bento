//go:build linux

package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The whole point of reading this from inside the sandbox is that a bwrap whose --tmpfs
// /tmp was filtered out of argv answers the pre-run probe identically. So the verdict has
// to name a host filesystem for what it is. EXT4_SUPER_MAGIC stands in for "whatever the
// host's /tmp is on"; the check is an equality against tmpfs, not a denylist.
func TestIsTmpfsRejectsAHostFilesystem(t *testing.T) {
	if isTmpfs(unix.EXT4_SUPER_MAGIC) {
		t.Error("isTmpfs accepted ext4; a --bind of the host's /tmp would go unnoticed")
	}
	if !isTmpfs(unix.TMPFS_MAGIC) {
		t.Error("isTmpfs rejected tmpfs, which is what a sandboxed run's /tmp is")
	}
}

const sentinelVerifyRun = "BENTO_TEST_VERIFY_RUN"

// The check is worth nothing if Run stops calling it, and a fixture test on the predicate
// cannot see that. This runs a launch stage in a sandbox weakened in exactly one place -
// the host's /tmp bound in where the fresh tmpfs belongs, which is what a shim filtering
// that flag out of argv leaves behind - and requires the refusal. In a child because Run makes the
// process permanently non-dumpable.
func TestRunRefusesTheHostsTmp(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "tmp")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Run proceeded on the host's /tmp:\n%s", out)
	}
	if !strings.Contains(string(out), "is not the fresh tmpfs") {
		t.Errorf("Run failed without the scratch-mount refusal: %q", out)
	}
}

// The other half of the same claim: a sandbox bento really did build must not be refused.
// Without this the refusal above passes just as well with the check wired to always fail.
func TestRunAcceptsTheSandboxBentoBuilds(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Run refused the sandbox bento itself asks bwrap for: %v\n%s", err, out)
	}
}

// A launch stage that has spawned nothing sees its namespace's init and itself. Anything
// else is a process bento did not start, which is what a bwrap whose --unshare-pid was
// filtered out of argv leaves the sandbox looking at.
func TestForeignPidsNamesProcessesBentoDidNotStart(t *testing.T) {
	host := []string{"1", "2", "417", "9021", "self", "meminfo", "net"}
	if got := foreignPids(host, 2); !slices.Equal(got, []string{"417", "9021"}) {
		t.Fatalf("foreignPids = %v, want the two host processes; a stripped --unshare-pid would go unnoticed", got)
	}
	if got := foreignPids([]string{"1", "2", "self", "meminfo"}, 2); len(got) != 0 {
		t.Errorf("foreignPids = %v, want none: an unshared namespace holds init and the launcher", got)
	}
}

// The check is worth nothing if Run stops calling it. Same shape as the /tmp refusal: a
// real sandbox weakened in exactly one place, here by leaving --unshare-pid out while the
// fresh procfs is still mounted - so /proc lists the host's processes.
func TestRunRefusesTheHostsPidNamespace(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "pid")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Run proceeded in the host's pid namespace:\n%s", out)
	}
	if !strings.Contains(string(out), "pid namespace is not the unshared one") {
		t.Errorf("Run failed without the pid-namespace refusal: %q", out)
	}
}

// A sandbox's /dev holds only what bwrap put there. The host's holds the machine's
// device nodes, which is what a bwrap whose --dev was filtered out of argv leaves
// showing through a recursive bind - and /dev is a granted write, so those nodes are
// writable too. The names are real entries from an ordinary host's /dev.
func TestForeignDevNodesNamesNodesBwrapDidNotCreate(t *testing.T) {
	host := []string{"null", "zero", "kvm", "pts", "mem", "shm", "sda", "tty", "net"}
	if got := foreignDevNodes(host, nil); !slices.Equal(got, []string{"kvm", "mem", "sda", "net"}) {
		t.Fatalf("foreignDevNodes = %v, want the host's own nodes; a stripped --dev would go unnoticed", got)
	}
	bwrapDev := []string{"core", "fd", "full", "null", "ptmx", "pts", "random", "shm", "stderr", "stdin", "stdout", "tty", "urandom", "zero"}
	if got := foreignDevNodes(bwrapDev, nil); len(got) != 0 {
		t.Errorf("foreignDevNodes = %v, want none: this is exactly what bwrap's --dev builds", got)
	}
}

// A policy may grant a path inside /dev - internal/linux's checkGrantNotManagedMount
// refuses only the whole root - and bwrap carves that bind into the sandbox's own /dev, so
// the name is one --dev never creates. Refusing it would fail a legitimate run with a
// message blaming a shimmed bwrap, and the run's own grant set is what tells the two apart.
//
// The names this is handed are Config.GrantedDevNames, which the host derived from the
// resolved grants; "mem" here is the shim's injected node and stays foreign precisely
// because no grant named it. That is the half mount-ness could never answer: an injected
// --dev-bind is a mount exactly as a grant's bind is.
func TestForeignDevNodesAcceptsAGrantBentoMounted(t *testing.T) {
	names := []string{"null", "dri", "net", "kvm", "sda", "mem"}
	if got := foreignDevNodes(names, []string{"dri", "net"}); !slices.Equal(got, []string{"kvm", "sda", "mem"}) {
		t.Fatalf("foreignDevNodes = %v, want only the names no grant reached: a granted /dev/dri run must not be refused, and an injected /dev/mem must not be let past", got)
	}
}

// The check is worth nothing if Run stops calling it. Same shape as the /tmp refusal: a
// real sandbox weakened in exactly one place, here by leaving --dev out so the host's
// device directory shows through the ro-bind of /.
func TestRunRefusesTheHostsDev(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "dev")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Run proceeded on the host's /dev:\n%s", out)
	}
	if !strings.Contains(string(out), "is not the device directory bwrap builds") {
		t.Errorf("Run failed without the device-mount refusal: %q", out)
	}
}

// The other half of the /dev claim, and the half a fixture cannot show: a real sandbox
// carrying a granted bind inside /dev must not be refused. Without this the refusal above
// passes just as well with the allowlist short of every name a policy can add.
func TestRunAcceptsAGrantInsideDev(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{GrantedDevNames: []string{"net"}, Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "devgrant")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Run refused a sandbox carrying a granted path inside /dev: %v\n%s", err, out)
	}
}

// The residual the grant set closes, and the reason it is on Config at all: a shim that
// APPENDS a device bind to bwrap's argv leaves a /dev holding one extra name, mounted
// exactly as a legitimate grant's bind is. Against a mount test the two are the same
// thing; against the run's grant set the injected one is a name nobody granted.
//
// The same sandbox as TestRunAcceptsAGrantInsideDev, and Run is handed the same shape of
// Config - a grant on /dev/net/tun - so what differs between the two is only which name is
// there.
func TestRunRefusesADeviceNodeNoGrantNamed(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{GrantedDevNames: []string{"net"}, Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "devinject")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Run proceeded with a device node no grant named:\n%s", out)
	}
	if !strings.Contains(string(out), "is not the device directory bwrap builds") {
		t.Errorf("Run failed without the device-mount refusal: %q", out)
	}
	if !strings.Contains(string(out), "mem") {
		t.Errorf("the refusal did not name the injected node: %q", out)
	}
}

// The bounding set is what stops a target from remounting bento's read-only shields
// read-write, so the parse has to read a held capability as one. The masks are real: the
// first is what an ordinary host process holds, the second what a sandboxed one does.
func TestCapBoundingReadsAHeldCapability(t *testing.T) {
	const held = "Name:\tbash\nCapInh:\t0000000000000000\nCapBnd:\t000001ffffffffff\nSeccomp:\t0\n"
	if got, err := capBounding([]byte(held)); err != nil || got == 0 {
		t.Fatalf("capBounding = %016x, %v; want the host's full bounding set, or a stray --cap-add goes unnoticed", got, err)
	}
	const empty = "Name:\tbento\nCapInh:\t0000000000000000\nCapBnd:\t0000000000000000\n"
	if got, err := capBounding([]byte(empty)); err != nil || got != 0 {
		t.Errorf("capBounding = %016x, %v; want an empty set, which is what a sandboxed run holds", got, err)
	}
	// A kernel that does not answer must not read as one answering "none".
	if _, err := capBounding([]byte("Name:\tbento\n")); err == nil {
		t.Error("capBounding accepted a status dump with no CapBnd line as an empty bounding set")
	}
}

// The whole function, read seam included, against the state it exists to refuse: the test
// process runs on the host, where the bounding set is full. A fixture cannot show that the
// path from /proc/self/status to the verdict is connected.
func TestVerifyEmptyCapBoundRefusesAHostBoundingSet(t *testing.T) {
	held, err := capBounding(mustReadStatus(t))
	if err != nil {
		t.Skipf("cannot read this host's bounding set: %v", err)
	}
	if held == 0 {
		t.Skip("this process already holds an empty bounding set, so there is nothing here to refuse")
	}
	err = verifyEmptyCapBound()
	if err == nil {
		t.Fatal("verifyEmptyCapBound accepted the host's own capability bounding set")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%016x", held)) {
		t.Errorf("error = %q, want it to name the set it saw (%016x)", err, held)
	}
}

func mustReadStatus(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(procSelfStatus)
	if err != nil {
		t.Skipf("cannot read %s: %v", procSelfStatus, err)
	}
	return data
}

// The bridge exception, against the kernel's own answer rather than a fake: the same live
// child must be refused when the stage started none and accepted when it is the bridge.
// Getting that backwards either breaks every profiling run with egress or leaves the
// check refusing nothing.
func TestStrayChildVerdictTurnsOnTheBridgePid(t *testing.T) {
	child := exec.Command("/bin/sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	pid := child.Process.Pid

	err := verifyNoStrayChild(0)
	if err == nil {
		t.Errorf("a live child of the stage was accepted where no bridge was started")
	} else if !strings.Contains(err.Error(), fmt.Sprint(pid)) {
		t.Errorf("the refusal does not name the live child pid %d: %v", pid, err)
	}
	if err := verifyNoStrayChild(pid); err != nil {
		t.Errorf("the bridge this stage started itself must not be a stray child: %v", err)
	}
}

// The deny-list shields are the one filesystem layer with no backstop: the Landlock
// ruleset read-grants "/", so a --ro-bind argument pair dropped on the way to bwrap leaves
// the credential store readable for the whole run while the report says the filesystem
// layer was enforced. From inside, an unshielded store looks like host content where the
// empty stand-in should be.
func TestShieldHiddenTellsTheStandInFromTheRealThing(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := shieldHidden(store); err != nil || !got {
		t.Errorf("shieldHidden(empty dir) = %v, %v; want true: a tmpfs over a directory is what hides one", got, err)
	}
	if err := os.WriteFile(filepath.Join(store, "id_rsa"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := shieldHidden(store); err != nil || got {
		t.Errorf("shieldHidden(populated dir) = %v, %v; want false: this is the store showing through a dropped shield", got, err)
	}

	file := filepath.Join(dir, "netrc")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := shieldHidden(file); err != nil || !got {
		t.Errorf("shieldHidden(empty file) = %v, %v; want true: an empty read-only bind is what hides a file", got, err)
	}
	if err := os.WriteFile(file, []byte("machine x login y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := shieldHidden(file); err != nil || got {
		t.Errorf("shieldHidden(nonempty file) = %v, %v; want false", got, err)
	}

	// Absent is the strongest hiding there is, and it is a state bento reaches: a shield
	// over a path bwrap had no mount point to create leaves nothing behind.
	if got, err := shieldHidden(filepath.Join(dir, "never")); err != nil || !got {
		t.Errorf("shieldHidden(absent) = %v, %v; want true", got, err)
	}
}

// isReadOnlyMount's verdict, unit-tested for isTmpfs' reason: a test cannot mount anything
// read-only on a host that restricts unprivileged user namespaces.
func TestIsReadOnlyMountReadsTheFlag(t *testing.T) {
	if isReadOnlyMount(0) {
		t.Error("a mount with no flags is writable; calling it read-only would vouch for an unshielded path")
	}
	if !isReadOnlyMount(unix.ST_RDONLY | unix.ST_NOSUID) {
		t.Error("ST_RDONLY alongside another flag is still read-only")
	}
}

// The checks are worth nothing if Run stops calling them, so this is the wiring: a real
// sandbox, and a Config naming a shield the sandbox does not carry. /etc stands in for a
// credential store whose --ro-bind a shim filtered out - it is populated in every sandbox
// inSandbox builds, which is exactly what an unshielded store looks like.
func TestRunRefusesAnUnshieldedDenyPath(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{HiddenShields: []string{"/etc"}, Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Run proceeded with a deny path the sandbox never shielded:\n%s", out)
	}
	if !strings.Contains(string(out), "is not the empty stand-in") {
		t.Errorf("Run failed without the shield refusal: %q", out)
	}
}

// The read-only half, and the case that distinguishes the check from asking whether the
// sandbox root is read-only: /tmp is the fresh writable tmpfs every run gets, so a
// read-only shield claimed over it is a shield that is not there. Outside a write grant
// the root remount already answers read-only, which is why the assertion has to be made
// somewhere a grant makes the path writable.
func TestRunRefusesAWritableReadOnlyShield(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{ReadOnlyShields: []string{"/tmp"}, Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Run proceeded with a read-only shield over a writable mount:\n%s", out)
	}
	if !strings.Contains(string(out), "is on a writable mount") {
		t.Errorf("Run failed without the shield refusal: %q", out)
	}
}
