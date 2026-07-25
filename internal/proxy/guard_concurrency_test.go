package proxy

import (
	"bufio"
	"context"
	"fmt"
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
	nonPublic := []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "fd00::1", "100.64.0.1"}
	resolved := map[string]string{}
	hosts := make([]string, 0, conns)
	for i := range conns {
		host := fmt.Sprintf("pub%d.example.com", i)
		ip := "93.184.216.34"
		if i%2 == 1 {
			host = fmt.Sprintf("priv%d.example.com", i)
			ip = nonPublic[i%len(nonPublic)]
		}
		resolved[host] = ip
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

	type result struct{ host, status string }
	results := make(chan result, len(hosts))
	for _, host := range hosts {
		c := dialProxy()
		defer c.Close()
		go func() {
			c.SetDeadline(time.Now().Add(30 * time.Second))
			fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\n\r\n", host)
			status, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				status = "read error: " + err.Error()
			}
			results <- result{host, strings.TrimSpace(status)}
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
			want = "403"
		}
		if !strings.Contains(r.status, want) {
			t.Errorf("%s got %q, want %s - a guard verdict landed on the wrong connection", r.host, r.status, want)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for host, d := range decisions {
		want := AdmittedByGate
		if strings.HasPrefix(host, "priv") {
			want = Denied // the guard's refusal, after the gate admitted it
		}
		if d != want {
			t.Errorf("observer reported %s as %q, want %q", host, d, want)
		}
	}
	// The teeth: a guard-blocked host must never have had a tunnel opened, which the
	// 403 alone does not show - the same handler writes it either way.
	if want := conns / 2; len(dialed) != want {
		t.Errorf("opened %d tunnels, want one per public host (%d): %v", len(dialed), want, dialed)
	}
	for _, host := range dialed {
		if strings.HasPrefix(host, "priv") {
			t.Errorf("opened a tunnel to %q, which resolves to the non-public address %s", host, resolved[host])
		}
	}
}
