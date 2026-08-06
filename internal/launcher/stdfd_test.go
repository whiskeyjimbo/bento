//go:build linux

package launcher

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Every descriptor the launch invocation names must clear the target's own standard
// streams. newAppliedReport has had this floor since it was written; the liveness pipe
// and the observation report are the same case, and worse in one respect - the liveness
// descriptor is closed once the bridge holds it, so one naming fd 1 closes the
// launcher's stdout mid-setup and a later allocation lands there. Only in-tree callers
// pass constants, but DecodeLaunch takes both off the wire with no bound.
func TestStandardStreamsAreRefusedAsReportDescriptors(t *testing.T) {
	// Zero, which means no liveness channel at all, is not a case here: Run returns at
	// the floor before it touches anything, and a config that passes it would go on to
	// re-exec the bridge from inside the test binary.
	for fd := 1; fd < firstInheritableFD; fd++ {
		_, err := Run(Config{Target: []string{"/bin/true"}, Socket: "/nonexistent.sock", BridgeLivenessFD: fd})
		if err == nil || !strings.Contains(err.Error(), "standard streams") {
			t.Errorf("liveness descriptor %d was accepted: %v", fd, err)
		}
	}

	for fd := 1; fd < firstInheritableFD; fd++ {
		if _, err := runObserve(Config{Target: []string{"/bin/true"}, ObserveFD: fd}, os.Environ()); err == nil || !strings.Contains(err.Error(), "standard streams") {
			t.Errorf("observation descriptor %d was accepted: %v", fd, err)
		}
	}
}

// The opt-in exists for socket activation: an accepted TCP connection handed to a
// handler as stdio. A family-blind waiver also passed AF_NETLINK (host interface,
// address and route enumeration) and AF_PACKET (raw frames on the host wire) - the
// exact reach the check was written for - on nothing but a stderr warning.
func TestOnlyIPSocketsAreWaivable(t *testing.T) {
	for _, tc := range []struct {
		domain int
		want   bool
	}{
		{unix.AF_INET, true},
		{unix.AF_INET6, true},
		{unix.AF_NETLINK, false},
		{unix.AF_PACKET, false},
		{unix.AF_VSOCK, false},
	} {
		if got := (&networkStdio{fd: 0, domain: tc.domain}).waivable(); got != tc.want {
			t.Errorf("family %d waivable = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

// The intercept model requires bento's proxy values to be authoritative, and curl reads
// ALL_PROXY for any protocol with no protocol-specific variable set - so scrubbing only
// the HTTP pair leaves a policy-declared proxy in charge of everything else.
func TestProxyScrubCoversAllProxy(t *testing.T) {
	env := []string{"ALL_PROXY=http://declared:3128", "all_proxy=http://declared:3128", "FTP_PROXY=x", "ftp_proxy=x", "PATH=/bin"}
	got := dropEnv(env, proxyEnvNames...)
	if len(got) != 1 || got[0] != "PATH=/bin" {
		t.Errorf("proxy variables survived the scrub: %q", got)
	}
}
