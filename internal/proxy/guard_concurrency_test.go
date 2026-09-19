package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/policy"
)

// The gate-concurrency test replaces p.dial wholesale, so guardUpstream never runs in
// it: the property "a host the gatekeeper admitted but the SSRF guard blocks never gets
// a tunnel" is covered one connection at a time and nowhere under load. This holds many
// connections AT THE GUARD - not at the gate, which has already returned by then - and
// releases them together, so a guard verdict that leaked between connections would show
// up as a tunnel to a non-public address or a 403 on a public one.
//
// The dialer fake exists only to resolve a name without touching the network and to
// avoid a real connect; the verdict itself comes from the production guardUpstream and
// its error is propagated verbatim, so what the handler sees is what production returns.
//
// Note what this is and is not. It admits every host and carries no rules, so the guard
// here reads only p.rules and p.nat64, both fixed before Serve: what it covers is the
// address classification under load, not the per-connection state. That state - the
// literal grant, and the blocked flag beside it - is what the test below holds many
// connections against. Unlike the gate test, neither leans on the race detector: parking
// a verdict on the Proxy struct and reusing it fails under plain go test, because the
// wrong verdict opens a real tunnel the assertions count.
func TestGuardUnderConcurrencyBlocksOnlyNonPublicTunnels(t *testing.T) {
	const conns = 64 // half public, half not, all held at the guard at once

	// The resolution the fake dialer stands in for. The non-public half spans the
	// distinct classes the guard must catch, so a verdict crossing connections cannot
	// hide behind one address family.
	// The classes classify actually distinguishes, including the transition forms that
	// wrap a host-reserved v4 address in a public-looking v6 one - those are the ones a
	// crossed verdict could hide behind.
	// The decision each one must be reported as is spelled out rather than derived from
	// the guard's own classification: the causes carry different operator remedies -
	// metadata says a script went for the instance's credentials, host-reserved says it
	// reached for the host itself, private-no-grant says a permitted name landed on the
	// LAN - and a table computed the way the code computes it would agree with a guard
	// that had lost the distinction entirely.
	nonPublic := []struct {
		ip   string
		want Decision
	}{
		{"127.0.0.1", GuardBlockedReserved},
		{"10.0.0.5", GuardBlockedPrivate},
		{"169.254.169.254", GuardBlockedMetadata},
		{"fd00::1", GuardBlockedPrivate},
		{"100.64.0.1", GuardBlockedPrivate},              // CGNAT: infrastructure, but reachable by literal
		{"64:ff9b::a9fe:a9fe", GuardBlockedMetadata},     // well-known NAT64 prefix wrapping the metadata address
		{"::ffff:169.254.169.254", GuardBlockedMetadata}, // IPv4-mapped metadata
		{"2002:a9fe:a9fe::1", GuardBlockedMetadata},      // 6to4 wrapping the same
		{"198.18.0.1", GuardBlockedReserved},             // RFC 2544 benchmarking
		{"240.0.0.1", GuardBlockedReserved},              // reserved v4
	}
	resolved := map[string]string{}
	wantDecision := map[string]Decision{}
	hosts := make([]string, 0, conns)
	for i := range conns {
		host := fmt.Sprintf("pub%d.example.com", i)
		ip := "93.184.216.34"
		want := AdmittedByGate
		if i%2 == 1 {
			host = fmt.Sprintf("priv%d.example.com", i)
			// i is odd here, so index on the pair number or half the list is unreachable.
			entry := nonPublic[(i/2)%len(nonPublic)]
			ip, want = entry.ip, entry.want
		}
		resolved[host] = ip
		wantDecision[host] = want
		hosts = append(hosts, host)
	}

	var (
		mu        sync.Mutex
		dialed    []string
		decisions = map[string]Decision{}
	)
	arrived := make(chan struct{}, conns)
	release := make(chan struct{})

	// Declared first so the dialer fake can call the proxy's own guard: the fake stands
	// in for resolution only, never for the verdict.
	var p *Proxy
	p = New(
		nil,
		// Every host is admitted: the subject here is the guard behind the gate, not
		// the gate's own verdict.
		WithGatekeeper(func(context.Context, string, string) bool { return true }),
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, ok := resolved[host]
			if !ok {
				return nil, fmt.Errorf("test dialer: no resolution for %q", host)
			}
			// Park every connection here until they are all at the guard, so the
			// verdicts below are decided concurrently.
			arrived <- struct{}{}
			<-release
			if err := p.guardUpstream(ctx, network, net.JoinHostPort(ip, port), nil); err != nil {
				return nil, err
			}
			// Recorded only AFTER the guard passes: recording on entry would make the
			// no-tunnel assertion below pass no matter what the guard decided.
			mu.Lock()
			dialed = append(dialed, host)
			mu.Unlock()
			return fakeDialer("tunnel")(ctx, network, addr)
		}),
		WithObserver(func(d Decision, host, port string) {
			mu.Lock()
			decisions[host] = d
			mu.Unlock()
		}),
	)
	dialProxy, stop := startProxy(t, p)
	unblock := sync.OnceFunc(func() { close(release) })
	defer func() { unblock(); stop() }()

	type result struct{ host, status, body string }
	results := make(chan result, len(hosts))
	for _, host := range hosts {
		c := dialProxy()
		defer c.Close()
		go func() {
			c.SetDeadline(time.Now().Add(30 * time.Second))
			fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\n\r\n", host)
			br := bufio.NewReader(c)
			status, err := br.ReadString('\n')
			if err != nil {
				status = "read error: " + err.Error()
			}
			body, _ := io.ReadAll(br)
			results <- result{host, strings.TrimSpace(status), string(body)}
		}()
	}

	for range conns {
		select {
		case <-arrived:
		case <-time.After(30 * time.Second):
			t.Fatal("not every connection reached the guard; a handler is stuck before the dial")
		}
	}
	unblock()

	for range hosts {
		r := <-results
		want := "200"
		if strings.HasPrefix(r.host, "priv") {
			// The guard's refusal is indistinguishable from an ordinary dial failure by
			// design, so what the client sees can no longer tell the two apart; the
			// per-connection property is carried by the observer's decisions below.
			want = "502"
		}
		if !strings.Contains(r.status, want) {
			t.Errorf("%s got %q, want %s - a guard verdict landed on the wrong connection", r.host, r.status, want)
			continue
		}
		if want == "502" && !strings.Contains(r.body, r.host) {
			t.Errorf("%s was refused without naming itself: %q", r.host, r.body)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	// Each refusal must be reported as ITS OWN cause, not merely as a refusal: the causes
	// are decided per connection on shared per-dial state, so a cause leaking between two
	// connections held at the guard together still blocks both and shows up only here.
	for host, d := range decisions {
		if want := wantDecision[host]; d != want {
			t.Errorf("observer reported %s (%s) as %q, want %q", host, resolved[host], d, want)
		}
	}
	if len(decisions) != len(hosts) {
		t.Errorf("observer saw %d decisions, want one per connection (%d)", len(decisions), len(hosts))
	}
	// The teeth: a guard-blocked host must never have had a tunnel opened, which the
	// refusal alone does not show - the same handler writes it either way.
	if want := conns / 2; len(dialed) != want {
		t.Errorf("opened %d tunnels, want one per public host (%d): %v", len(dialed), want, dialed)
	}
	for _, host := range dialed {
		if strings.HasPrefix(host, "priv") {
			t.Errorf("opened a tunnel to %q, which resolves to the non-public address %s", host, resolved[host])
		}
	}
}

// The half of the guard that IS per-connection state: the private-IP literal grant, which
// handle decides per connection (proxy.go) and carries in the dial context. The test above
// runs with an admit-all gatekeeper and no rules, so literalGrantFor never returns one and
// no grant is ever in flight - the leak that matters is not exercised there.
//
// Here half the connections carry a grant for 10.0.0.5 and half do not, and every one of
// them resolves to that same address. A refactor that parks the grant on the Proxy struct
// rather than the context - the exact refactor the tripwire above exists for - opens a
// tunnel for a hostname the allowlist admits and the guard must refuse, which the tunnel
// count catches under plain go test.
func TestLiteralGrantUnderConcurrencyDoesNotCrossConnections(t *testing.T) {
	const conns = 64 // half literal (granted), half hostname (not), all held at the guard

	const target = "10.0.0.5"
	var (
		mu       sync.Mutex
		tunneled []string
		refused  []string
	)
	arrived := make(chan struct{}, conns)
	release := make(chan struct{})

	var p *Proxy
	p = New(
		[]policy.NetworkRule{{Host: ".example.com", Port: "*"}, {Host: target, Port: "443"}},
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// Every name resolves onto the granted literal, so nothing but the
			// connection's own grant can tell the two halves apart.
			arrived <- struct{}{}
			<-release
			if err := p.guardUpstream(ctx, network, net.JoinHostPort(target, port), nil); err != nil {
				mu.Lock()
				refused = append(refused, host)
				mu.Unlock()
				return nil, err
			}
			mu.Lock()
			tunneled = append(tunneled, host)
			mu.Unlock()
			return fakeDialer("tunnel")(ctx, network, addr)
		}),
	)
	dialProxy, stop := startProxy(t, p)
	unblock := sync.OnceFunc(func() { close(release) })
	defer func() { unblock(); stop() }()

	for i := range conns {
		host := target
		if i%2 == 1 {
			host = fmt.Sprintf("x%d.example.com", i)
		}
		c := dialProxy()
		defer c.Close()
		go func() {
			c.SetDeadline(time.Now().Add(30 * time.Second))
			fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\n\r\n", host)
			io.Copy(io.Discard, c) //nolint:errcheck // the verdict is read from the guard below
		}()
	}
	for range conns {
		select {
		case <-arrived:
		case <-time.After(30 * time.Second):
			t.Fatal("not every connection reached the guard; a handler is stuck before the dial")
		}
	}
	unblock()

	deadline := time.Now().Add(30 * time.Second)
	for {
		mu.Lock()
		done := len(tunneled)+len(refused) == conns
		mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(tunneled) != conns/2 {
		t.Errorf("opened %d tunnels, want one per literal CONNECT (%d): %v", len(tunneled), conns/2, tunneled)
	}
	for _, host := range tunneled {
		if host != target {
			t.Errorf("opened a tunnel for %q, which named no literal and so carried no grant - a grant crossed connections", host)
		}
	}
	for _, host := range refused {
		if host == target {
			t.Errorf("refused %q, which named the granted literal - a missing grant crossed connections", host)
		}
	}
}
