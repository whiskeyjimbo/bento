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
// Note what this is and is not. guardUpstream today reads only p.rules and p.nat64,
// both fixed before Serve, so there is no per-connection state to cross yet: this is a
// tripwire for a refactor that introduces some. Unlike the gate test, it does not lean
// on the race detector - parking the verdict on the Proxy struct and reusing it fails
// this test under plain go test, because the wrong verdict opens a real tunnel the
// assertions count.
func TestGuardUnderConcurrencyBlocksOnlyNonPublicTunnels(t *testing.T) {
	const conns = 64 // half public, half not, all held at the guard at once

	// The resolution the fake dialer stands in for. The non-public half spans the
	// distinct classes the guard must catch, so a verdict crossing connections cannot
	// hide behind one address family.
	// The classes classify actually distinguishes, including the transition forms that
	// wrap a host-reserved v4 address in a public-looking v6 one - those are the ones a
	// crossed verdict could hide behind.
	nonPublic := []string{
		"127.0.0.1", "10.0.0.5", "169.254.169.254", "fd00::1", "100.64.0.1",
		"64:ff9b::a9fe:a9fe",      // well-known NAT64 prefix wrapping the metadata address
		"::ffff:169.254.169.254",  // IPv4-mapped metadata
		"2002:a9fe:a9fe::1",       // 6to4 wrapping the same
		"198.18.0.1", "240.0.0.1", // benchmarking and reserved v4
	}
	resolved := map[string]string{}
	hosts := make([]string, 0, conns)
	for i := range conns {
		host := fmt.Sprintf("pub%d.example.com", i)
		ip := "93.184.216.34"
		if i%2 == 1 {
			host = fmt.Sprintf("priv%d.example.com", i)
			// i is odd here, so index on the pair number or half the list is unreachable.
			ip = nonPublic[(i/2)%len(nonPublic)]
		}
		resolved[host] = ip
		hosts = append(hosts, host)
	}

	var (
		mu     sync.Mutex
		dialed []string
		// refusals records the guard's own verdict text per host. The 403 body
		// deliberately does not name the resolved address (it would enumerate the
		// host's DNS for the sandbox), so the per-connection property - this
		// connection was blocked for ITS address, not another's - is read here,
		// where the guard's error is still intact.
		refusals  = map[string]string{}
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
				mu.Lock()
				refusals[host] = err.Error()
				mu.Unlock()
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
			// per-connection property is carried by decisions and refusals below.
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

	// The guard's own verdict names the address that was blocked, so a verdict
	// carrying another connection's address - the block holding but for the wrong
	// reason - is caught too, not just a swapped allow/deny.
	// Compared in canonical form: the guard names the parsed address, so an
	// IPv4-mapped literal is reported as the plain v4 address it wraps.
	mu.Lock()
	for host, ip := range resolved {
		if !strings.HasPrefix(host, "priv") {
			continue
		}
		blocked := net.ParseIP(ip).String()
		if !strings.Contains(refusals[host], blocked) {
			t.Errorf("%s was refused naming a different address than %s: %q", host, blocked, refusals[host])
		}
	}
	mu.Unlock()

	mu.Lock()
	defer mu.Unlock()
	for host, d := range decisions {
		want := AdmittedByGate
		if strings.HasPrefix(host, "priv") {
			want = GuardBlocked // the guard's refusal, after the gate admitted it
		}
		if d != want {
			t.Errorf("observer reported %s as %q, want %q", host, d, want)
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
