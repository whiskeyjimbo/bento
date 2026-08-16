//go:build linux

package launcher

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

// procNetDev lists the interfaces of the caller's network namespace. It is read from
// inside the sandbox, where /proc is the fresh procfs bwrap mounted into the namespace,
// so it describes this namespace and not the host's.
const procNetDev = "/proc/net/dev"

// verifyEmptyNetns is the launcher's own check that the network namespace it is running
// in really is the empty one the run was admitted on. The host asks for it with
// --unshare-net, but everything that verifies that flag - the capability probe, the run
// itself - goes through the same PATH-resolved bwrap that would be doing the lying, so
// the guarantee has no leg that is not the suspect's own word. This is that leg: bento's
// own binary, re-exec'd inside the sandbox, reading what the kernel says it can see.
//
// An unshared namespace has exactly one interface, the loopback the kernel creates with
// it - the bridge's forwarder listens on that same lo and adds nothing. Any other
// interface means the sandbox is on a network stack it was not granted, so the run is
// refused before the target is reached rather than reported as enforced afterwards.
func verifyEmptyNetns() error {
	data, err := os.ReadFile(procNetDev)
	if err != nil {
		// Loudly, not skipped: the run was admitted on a network guarantee, and a
		// namespace bento cannot inspect is one it cannot vouch for. /proc is mounted by
		// the same bwrap invocation that is supposed to have unshared the netns, so a
		// missing one is the same suspect failing a different way.
		return fmt.Errorf("launcher: reading %s to verify the network namespace: %w", procNetDev, err)
	}
	if extra := foreignInterfaces(data); len(extra) > 0 {
		return fmt.Errorf("launcher: the sandbox's network namespace is not the empty one this run was admitted on; it can see %s", strings.Join(extra, ", "))
	}
	return nil
}

// foreignInterfaces names every interface in a /proc/net/dev dump other than loopback.
// The two header lines carry no colon-terminated name and are skipped by the same parse
// that reads the rows.
func foreignInterfaces(data []byte) []string {
	var extra []string
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		name, _, ok := strings.Cut(strings.TrimSpace(scan.Text()), ":")
		if !ok || name == "" || name == "lo" {
			continue
		}
		extra = append(extra, name)
	}
	return extra
}
