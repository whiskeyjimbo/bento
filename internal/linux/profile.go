package linux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/observe"
	"github.com/whiskeyjimbo/bento-v2/internal/proxy"
	"github.com/whiskeyjimbo/bento-v2/policy"
	"github.com/whiskeyjimbo/bento-v2/profile"
)

// Profile runs p under observation and reports what the target did. p is default-deny
// like a real run - nothing under $HOME is mounted - with exec and network open so the
// run exercises its real code paths; the observer records even the target's attempts to
// open ungranted paths, so the caller synthesizes from what the program WANTED (the
// consent surface) with no credential ever exposed. The filesystem accesses come from
// the in-sandbox ptrace observer; the outbound hosts come from
// the egress proxy, which sees hostnames the target would otherwise resolve to
// bare IPs. By default the proxy records those hosts but refuses to forward the
// traffic, so profiling untrusted code cannot exfiltrate; allowNetwork forwards
// it for a faithful run of code whose later behavior depends on the response.
func (e *Enforcer) Profile(ctx context.Context, p *policy.Policy, proc enforce.Process, allowNetwork bool, denyPaths []string) (profile.Observation, error) {
	if err := p.Validate(); err != nil {
		return profile.Observation{}, err
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return profile.Observation{}, fmt.Errorf("linux: bubblewrap (bwrap) not found: %w", err)
	}

	// Profiling never consults a gate (the proxy runs in refuse mode), so no gate
	// presence is signalled here. denyPaths shield caller-owned state (e.g. a
	// supervising wrapper's permission store) even behind a grant that would cover it;
	// they are set on the sandbox before the shield-cleanup defer below reads it.
	sb, cleanup, err := newSandbox(p, e.selfPath, false, denyPaths)
	if err != nil {
		return profile.Observation{}, err
	}
	defer cleanup()

	// Remove directory shield mount points bwrap creates on the host, as Run does -
	// profiling applies the same deny-list shields, so it leaves the same artifacts.
	if reads, writes, err := resolveGrants(p); err == nil {
		_, optIns := explicitShieldOptIns(sb, p.Read)
		defer removeCreatedShieldDirs(createdShieldDirs(sb, exposedPaths(sb, reads, writes), writes, optIns))
	}

	report, err := os.CreateTemp("", "bento-observe-")
	if err != nil {
		return profile.Observation{}, fmt.Errorf("linux: creating observation report: %w", err)
	}
	reportPath := report.Name()
	defer os.Remove(reportPath)
	defer report.Close()
	sb.observe = true

	var (
		mu    sync.Mutex
		hosts []profile.HostPort
	)
	var stopProxy func()
	// Safety net for early error returns; the happy path stops it explicitly below.
	defer func() {
		if stopProxy != nil {
			stopProxy()
		}
	}()
	if sb.proxySocket != "" {
		stop, err := startRecordingProxy(ctx, p, sb.proxySocket, allowNetwork, func(host, port string) {
			mu.Lock()
			hosts = append(hosts, profile.HostPort{Host: host, Port: port})
			mu.Unlock()
		})
		if err != nil {
			return profile.Observation{}, err
		}
		stopProxy = stop
	}

	args, _, err := compile(p, proc, sb)
	if err != nil {
		return profile.Observation{}, err
	}
	cmd := exec.CommandContext(ctx, bwrap, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = proc.Stdin, proc.Stdout, proc.Stderr
	// The open report file becomes FD observeReportFD in the bwrap child, which bwrap
	// passes through to the launcher. The launcher writes observations there and marks
	// it close-on-exec, so the profiled target never inherits the channel - though a
	// descendant can still reach it via /proc/<launcher>/fd, so the report is
	// trustworthy only to the degree the profiled code is (see the launcher's
	// runObserve). The host reads it back by path below.
	cmd.ExtraFiles = []*os.File{report}
	if err := cmd.Run(); err != nil && !isExitError(err) {
		return profile.Observation{}, fmt.Errorf("linux: profiling run: %w", err)
	}

	obs, err := parseObservations(reportPath)
	if err != nil {
		return profile.Observation{}, err
	}
	// Stop the recording proxy before reading hosts, so a destination the target reached
	// during teardown is recorded before the snapshot, not lost to the still-running
	// handler. Run stops its proxy before reading its report for the same reason.
	if stopProxy != nil {
		stopProxy()
		stopProxy = nil
	}
	mu.Lock()
	obs.Hosts = hosts
	mu.Unlock()
	obs.Interpreter = sb.interpreter
	return obs, nil
}

// startRecordingProxy runs the egress proxy and reports every destination a
// profiling run reaches for, by hostname. By default the proxy records each
// CONNECT and refuses it, so the script's data never leaves the host; passing
// allowNetwork forwards the traffic for a faithful run of network-dependent code.
// Either way the host is recorded, so the proposed manifest is the same.
func startRecordingProxy(ctx context.Context, p *policy.Policy, socket string, allowNetwork bool, record func(host, port string)) (func(), error) {
	var opts []proxy.Option
	if allowNetwork {
		// Forwarding mode dials upstream, so it needs the same SSRF hardening as the
		// real-egress proxy: without NAT64 discovery, guardUpstream decodes only the
		// well-known Pref64 and a custom-prefix AAAA embedding an RFC1918 address would
		// be dialed - and the profiling policy's allowlist is *:*, so the hostname check
		// does not backstop it.
		opts = append(opts, proxy.WithNAT64Discovery(proxy.DefaultNAT64Lookup))
	} else {
		opts = append(opts, proxy.WithoutEgress())
	}
	stop, err := startProxyWith(ctx, p, socket, func(d proxy.Decision, host, port string) {
		record(host, port)
	}, opts...)
	return stop, err
}

// parseObservations reads the launcher's observation report: "R <path>" and
// "W <path>" lines for opens, an "EXEC" line if the target spawned a subprocess,
// and an "EXIT <code>" or "SIGNAL <n>" line carrying the run's exit status.
func parseObservations(path string) (profile.Observation, error) {
	f, err := os.Open(path)
	if err != nil {
		return profile.Observation{}, fmt.Errorf("linux: reading observations: %w", err)
	}
	defer f.Close()

	var obs profile.Observation
	var started bool
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if started {
			// The completion marker is written last, in the launcher's single write.
			// Anything after it did not come from that write, so treat the report as
			// tampered rather than parse records from an appended tail. This is defense
			// in depth against a target that reaches the report via /proc/<launcher>/fd
			// and appends records after the launcher's marker.
			if line != "" {
				return profile.Observation{}, fmt.Errorf("linux: observation report has content after the completion marker; treating it as tampered")
			}
			continue
		}
		switch {
		case line == observe.ReportStart:
			started = true
		case line == "EXEC":
			obs.Execed = true
		case strings.HasPrefix(line, "R "):
			if p, err := strconv.Unquote(line[2:]); err == nil {
				obs.Reads = append(obs.Reads, p)
			}
		case strings.HasPrefix(line, "W "):
			if p, err := strconv.Unquote(line[2:]); err == nil {
				obs.Writes = append(obs.Writes, p)
			}
		case strings.HasPrefix(line, "EXIT "):
			if n, err := strconv.Atoi(line[5:]); err == nil {
				obs.ExitCode = n
			}
		case strings.HasPrefix(line, "SIGNAL "):
			if n, err := strconv.Atoi(line[7:]); err == nil {
				obs.Signaled = true
				obs.Signal = n
				obs.ExitCode = 128 + n
			}
		}
	}
	if err := s.Err(); err != nil {
		return profile.Observation{}, err
	}
	// A missing completion marker means the observer did not finish: the sandbox
	// failed to start, tracing failed, or the report was truncated. Surfacing an
	// error here is what stops the profiler from proposing a silently-empty or
	// partial manifest instead of the run's real accesses.
	if !started {
		return profile.Observation{}, fmt.Errorf("linux: profiling did not complete (the observation report is empty or truncated); the sandbox may have failed to start")
	}
	return obs, nil
}
