//go:build linux

package launcher

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// The whole point of reading this from inside the sandbox is that a bwrap whose
// --unshare-net was filtered out of argv answers the probe and the run identically -
// bento's own binary looking at the kernel's answer is the only leg that is not the
// suspect's word. So the parse has to name a host stack for what it is.
func TestForeignInterfacesNamesAHostNetworkStack(t *testing.T) {
	const hostNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 19942778482 173494032    0    0    0     0          0         0 19942778482 173494032    0    0    0     0       0          0
 ens18: 75364521780 146650725    0    0    0     0          0         0 70388444709 87820160    0    0    0     0       0          0
docker0:       0       0    0    0    0     0          0         0        0        0    0    0    0     0       0          0
`
	got := foreignInterfaces([]byte(hostNetDev))
	if !slices.Equal(got, []string{"ens18", "docker0"}) {
		t.Fatalf("foreignInterfaces = %v, want the two host interfaces; a stripped --unshare-net would go unnoticed", got)
	}
}

// An unshared namespace has exactly the loopback the kernel created with it. The bridge
// listens on that same lo and adds no interface, so a run bento did sandbox must not be
// refused by this check.
func TestForeignInterfacesAcceptsAnEmptyNamespace(t *testing.T) {
	const emptyNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0       0    0    0    0     0          0         0        0        0    0    0    0     0       0          0
`
	if got := foreignInterfaces([]byte(emptyNetDev)); len(got) != 0 {
		t.Errorf("foreignInterfaces = %v, want none: an unshared netns holds only lo", got)
	}
}

// The verdict has to name what it saw. An operator reading "the sandbox is not isolated"
// with no interface in the sentence cannot tell a shimmed bwrap from a bento bug.
func TestVerifyEmptyNetnsNamesWhatItSaw(t *testing.T) {
	// The test process runs in the host namespace, which is exactly the state the check
	// exists to refuse - so on any host with a second interface this is the real thing
	// rather than a fixture.
	data, err := os.ReadFile(procNetDev)
	if err != nil {
		t.Skipf("cannot read %s: %v", procNetDev, err)
	}
	extra := foreignInterfaces(data)
	if len(extra) == 0 {
		t.Skip("this host's namespace holds only lo, so there is nothing here to refuse")
	}
	err = verifyEmptyNetns()
	if err == nil {
		t.Fatal("verifyEmptyNetns accepted the host's own network namespace")
	}
	if !strings.Contains(err.Error(), extra[0]) {
		t.Errorf("error = %q, want it to name %s", err, extra[0])
	}
}

// inEmptyNetns puts a re-exec'd child in its own network namespace. Run verifies from the
// inside that its namespace is the empty one the host asked bwrap for, so a child that
// calls Run has to be in one or it refuses before reaching what the test is about.
// Unprivileged, through a user namespace, which is the permission the sandbox needs too.
func inEmptyNetns(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
}
