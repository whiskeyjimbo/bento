package grants

import "testing"

func TestCacheLookupMiss(t *testing.T) {
	c := NewCache()
	if _, ok := c.Lookup(Request{Host: "x", Port: 1}); ok {
		t.Error("empty cache should miss")
	}
}

func TestCacheStoreAndLookup(t *testing.T) {
	c := NewCache()
	r := Request{Host: "api.example.com", Port: 443}
	c.Store(r, DecisionAllow)
	got, ok := c.Lookup(r)
	if !ok || got != DecisionAllow {
		t.Errorf("expected (Allow, true), got (%v, %v)", got, ok)
	}
	// Same host different port: distinct entry.
	if _, ok := c.Lookup(Request{Host: "api.example.com", Port: 80}); ok {
		t.Error("different port should not match")
	}
}

func TestCacheOverwrite(t *testing.T) {
	c := NewCache()
	r := Request{Host: "x", Port: 1}
	c.Store(r, DecisionAllow)
	c.Store(r, DecisionDeny)
	got, _ := c.Lookup(r)
	if got != DecisionDeny {
		t.Errorf("re-store should overwrite, got %v", got)
	}
}

func TestRequestKey(t *testing.T) {
	cases := []struct {
		r    Request
		want string
	}{
		{Request{Host: "x", Port: 0}, "x:0"},
		{Request{Host: "api.github.com", Port: 443}, "api.github.com:443"},
		{Request{Host: "h", Port: 65535}, "h:65535"},
	}
	for _, c := range cases {
		if got := c.r.key(); got != c.want {
			t.Errorf("key(%v) = %q, want %q", c.r, got, c.want)
		}
	}
}
