//go:build linux

package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
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

	want := "http://" + proxyAddr
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

// reapChild starts a sibling that exits immediately and a target that outlives it, then
// reports what reapUntil made of them.
func reapChild() {
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stdout, format+"\n", a...)
		os.Exit(1)
	}
	sibling := exec.Command("/bin/sh", "-c", "exit 0")
	if err := sibling.Start(); err != nil {
		fail("starting the sibling: %v", err)
	}
	target := exec.Command("/bin/sh", "-c", "sleep 0.3; kill -TERM $$")
	if err := target.Start(); err != nil {
		fail("starting the target: %v", err)
	}

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
