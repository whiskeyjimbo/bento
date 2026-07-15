package linux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
	"github.com/whiskeyjimbo/bento-v2/internal/profile"
	"github.com/whiskeyjimbo/bento-v2/internal/proxy"
)

// Profile runs p under observation and reports what the target did. p should be
// permissive (broad reads, exec allowed) so the run exercises the script's real
// behavior; the caller synthesizes a tight policy from the result. The filesystem
// accesses come from the in-sandbox ptrace observer; the outbound hosts come from
// the egress proxy, which sees hostnames the target would otherwise resolve to
// bare IPs. By default the proxy records those hosts but refuses to forward the
// traffic, so profiling untrusted code cannot exfiltrate; allowNetwork forwards
// it for a faithful run of code whose later behavior depends on the response.
func (e *Enforcer) Profile(ctx context.Context, p *policy.Policy, proc enforce.Process, allowNetwork bool) (profile.Observation, error) {
	if err := p.Validate(); err != nil {
		return profile.Observation{}, err
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return profile.Observation{}, fmt.Errorf("linux: bubblewrap (bwrap) not found: %w", err)
	}

	sb, cleanup, err := newSandbox(p, e.selfPath)
	if err != nil {
		return profile.Observation{}, err
	}
	defer cleanup()

	report, err := os.CreateTemp("", "bento-observe-")
	if err != nil {
		return profile.Observation{}, fmt.Errorf("linux: creating observation report: %w", err)
	}
	reportPath := report.Name()
	report.Close()
	defer os.Remove(reportPath)
	sb.observe = reportPath

	var (
		mu    sync.Mutex
		hosts []profile.HostPort
	)
	if sb.proxySocket != "" {
		stop, err := startRecordingProxy(ctx, p, sb.proxySocket, allowNetwork, func(host, port string) {
			mu.Lock()
			hosts = append(hosts, profile.HostPort{Host: host, Port: port})
			mu.Unlock()
		})
		if err != nil {
			return profile.Observation{}, err
		}
		defer stop()
	}

	args, err := compile(p, proc, sb)
	if err != nil {
		return profile.Observation{}, err
	}
	cmd := exec.CommandContext(ctx, bwrap, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = proc.Stdin, proc.Stdout, proc.Stderr
	if err := cmd.Run(); err != nil && !isExitError(err) {
		return profile.Observation{}, fmt.Errorf("linux: profiling run: %w", err)
	}

	obs, err := parseObservations(reportPath)
	if err != nil {
		return profile.Observation{}, err
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
	if !allowNetwork {
		opts = append(opts, proxy.WithoutEgress())
	}
	stop, _, err := startProxyWith(ctx, p, socket, func(d proxy.Decision, host, port string) {
		record(host, port)
	}, opts...)
	return stop, err
}

// parseObservations reads the launcher's observation report: "R <path>" and
// "W <path>" lines for opens, and an "EXEC" line if the target spawned a
// subprocess.
func parseObservations(path string) (profile.Observation, error) {
	f, err := os.Open(path)
	if err != nil {
		return profile.Observation{}, fmt.Errorf("linux: reading observations: %w", err)
	}
	defer f.Close()

	var obs profile.Observation
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		switch {
		case line == "EXEC":
			obs.Execed = true
		case strings.HasPrefix(line, "R "):
			obs.Reads = append(obs.Reads, line[2:])
		case strings.HasPrefix(line, "W "):
			obs.Writes = append(obs.Writes, line[2:])
		}
	}
	return obs, s.Err()
}
