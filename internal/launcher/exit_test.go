//go:build linux

package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The target's env is where the egress fence becomes visible to the program inside: a
// client that reads only the lowercase pair (curl, most of the Python stack) and one
// that reads only the uppercase pair must both be pointed at the bridge, or that
// client's traffic leaves without meeting the host proxy's allowlist at all. The
// loopback exemption is the other half - without it a target's own in-sandbox server
// is dialled through the bridge, which resolves 127.0.0.1 on the HOST.
func TestProxyEnvSetsBothCasingsAndExemptsLoopback(t *testing.T) {
	got := map[string]string{}
	for _, kv := range proxyEnv() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("proxyEnv produced a non-assignment entry %q", kv)
		}
		got[k] = v
	}

	// Spelled out rather than built from proxyAddr: the bridge listens on that address
	// inside the sandbox, so a test that derived the expectation from the same constant
	// would follow a change of it and never fail.
	const want = "http://127.0.0.1:3128"
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
			if !strings.Contains(got[k], host) {
				t.Errorf("%s = %q does not exempt %s; an in-sandbox service would be dialled on the host", k, got[k], host)
			}
		}
	}
	if len(got) != 6 {
		t.Errorf("proxyEnv set %d variables, want 6: %v", len(got), got)
	}
}

// waitExitCode is what `bento run` finally exits with, so the shell convention is the
// contract: a target killed by a signal must not come back as the 0 that Wait4's exit
// field carries for it. The statuses are cross-checked against Signaled() first so a
// wrong bit layout in the test cannot make a wrong mapping look right.
func TestWaitExitCode(t *testing.T) {
	cases := []struct {
		name     string
		ws       syscall.WaitStatus
		signaled bool
		want     int
	}{
		{"a plain exit keeps its status", syscall.WaitStatus(3 << 8), false, 3},
		{"a clean exit is zero", syscall.WaitStatus(0), false, 0},
		{"a signalled target reports 128+signal", syscall.WaitStatus(syscall.SIGKILL), true, 137},
		{"SIGTERM likewise", syscall.WaitStatus(syscall.SIGTERM), true, 143},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.ws.Signaled() != tc.signaled {
				t.Fatalf("test built a status Signaled()=%v, want %v", tc.ws.Signaled(), tc.signaled)
			}
			if got := waitExitCode(tc.ws); got != tc.want {
				t.Errorf("waitExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

// sentinelReap makes the test binary re-exec itself as the process that does the
// reaping.
const sentinelReap = "BENTO_TEST_REAP"

// reapUntil calls Wait4(-1), which collects ANY child of the calling process - so it
// must be driven in a process of its own. Run in the test binary it would steal the
// wait status of another test's re-exec'd child, which passes locally and flakes
// elsewhere; and the property under test is precisely that a sibling exiting first
// does not end the wait.
//
// That sibling is the egress bridge in a real run: it is started alongside the target
// and exits when the sandbox comes down, so a reapUntil that returned on the first
// child to exit would hand the host the bridge's exit code as the target's.
func TestReapUntilReturnsTheTargetNotTheFirstChild(t *testing.T) {
	if os.Getenv(sentinelReap) != "" {
		reapChild()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelReap+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the reaping child failed: %v\n%s", err, out)
	}
	// 128+SIGTERM: the target is signalled, so this also pins waitExitCode's mapping to
	// a status the kernel produced rather than one the test built.
	if !strings.Contains(string(out), "REAP_OK 143") {
		t.Errorf("reapUntil did not return the signalled target's code: %s", out)
	}
}

// reapChild starts a sibling, waits for it to be a zombie, and only then lets the
// target exit - so the ordering the property needs holds without a timing assumption.
// A sleep long enough to be safe on an idle machine is still a coin flip on a loaded
// one, and it would fail as "a child survived reapUntil" rather than as a timeout.
func reapChild() {
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stdout, format+"\n", a...)
		os.Exit(1)
	}
	sibling := exec.Command("/bin/true")
	if err := sibling.Start(); err != nil {
		fail("starting the sibling: %v", err)
	}
	// The target blocks on a read until its stdin is closed, so nothing but this process
	// decides when it exits.
	target := exec.Command("/bin/sh", "-c", "read _; kill -TERM $$")
	release, err := target.StdinPipe()
	if err != nil {
		fail("target stdin: %v", err)
	}
	if err := target.Start(); err != nil {
		fail("starting the target: %v", err)
	}

	// Zombie is the state to wait for, not "exited": nothing has reaped the sibling yet,
	// so its staying a zombie is itself proof reapUntil has not run.
	if err := awaitZombie(sibling.Process.Pid); err != nil {
		fail("%v", err)
	}
	release.Close()

	code, err := reapUntil(target.Process.Pid)
	if err != nil {
		fail("reapUntil: %v", err)
	}
	// The sibling must have been collected on the way past, not left as a zombie: that
	// is the whole reason the loop waits on -1 rather than on the target alone.
	var ws syscall.WaitStatus
	if pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil); err != syscall.ECHILD {
		fail("a child survived reapUntil: pid=%d err=%v", pid, err)
	}
	fmt.Fprintf(os.Stdout, "REAP_OK %d\n", code)
	os.Exit(0)
}

// awaitZombie blocks until pid has exited and not yet been reaped.
func awaitZombie(pid int) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return fmt.Errorf("reading the sibling's state: %w", err)
		}
		// The state field follows the comm, which is parenthesised and may itself contain
		// spaces or a close paren - so it is found from the END of the comm, not by
		// splitting the whole line.
		rest := string(stat[strings.LastIndex(string(stat), ")")+1:])
		if fields := strings.Fields(rest); len(fields) > 0 && fields[0] == "Z" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the sibling never became a zombie: %s", stat)
		}
		time.Sleep(time.Millisecond)
	}
}
