package policy

import (
	"reflect"
	"testing"
)

func TestFingerprintStableAcrossReordering(t *testing.T) {
	a := &Policy{
		Entrypoint: "./x",
		Env:        []string{"A", "B"},
		Read:       []string{"/one", "/two"},
		Network:    []NetworkRule{{Host: "a.com", Port: "443"}, {Host: "b.com", Port: "80"}},
	}
	b := &Policy{
		Entrypoint: "./x",
		Env:        []string{"B", "A"},                                                       // reordered
		Read:       []string{"/two", "/one"},                                                 // reordered
		Network:    []NetworkRule{{Host: "b.com", Port: "80"}, {Host: "a.com", Port: "443"}}, // reordered
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("reordering set-like fields must not change the fingerprint")
	}
}

func TestFingerprintChangesWithPermissions(t *testing.T) {
	base := &Policy{Entrypoint: "./x", Read: []string{"/data"}}
	fp := base.Fingerprint()

	// Every field that defines what the sandbox permits must move the fingerprint:
	// approval attests the fingerprint, so a sandbox-affecting field left out of the
	// hash would let permissions change under an approval that still reads as current.
	// This covers all nine Policy fields, including each Limits sub-field.
	cases := map[string]func(*Policy){
		"changed entry":       func(p *Policy) { p.Entrypoint = "./y" },
		"changed interpreter": func(p *Policy) { p.Interpreter = "python3" },
		"added arg":           func(p *Policy) { p.Args = []string{"--flag"} },
		"added env":           func(p *Policy) { p.Env = []string{"PATH"} },
		"added read":          func(p *Policy) { p.Read = append(p.Read, "/more") },
		"added write":         func(p *Policy) { p.Write = []string{"/out"} },
		"added network":       func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: "443"}} },
		"changed exec":        func(p *Policy) { p.Exec = ExecAll },
		"added limit memory":  func(p *Policy) { p.Limits = Limits{Memory: "1M"} },
		"added limit cpu":     func(p *Policy) { p.Limits = Limits{CPU: "50%"} },
		"added limit pids":    func(p *Policy) { p.Limits = Limits{PIDs: 128} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			p := &Policy{Entrypoint: "./x", Read: []string{"/data"}}
			mut(p)
			if p.Fingerprint() == fp {
				t.Error("a permission change must change the fingerprint")
			}
		})
	}
}

// TestFingerprintChangesWithPermissions names its cases by hand, so a field added
// to Policy later is silently uncovered. Walk the struct instead: every field must
// move the fingerprint, including one that does not exist yet.
func TestFingerprintCoversEveryPolicyField(t *testing.T) {
	base := Policy{Entrypoint: "./x", Read: []string{"/data"}}
	fp := base.Fingerprint()

	for f := range reflect.ValueOf(base).Fields() {
		t.Run(f.Name, func(t *testing.T) {
			p := base
			p.Read = []string{"/data"}
			mutate(t, reflect.ValueOf(&p).Elem().FieldByIndex(f.Index))
			if p.Fingerprint() == fp {
				t.Errorf("Policy.%s is not covered by the fingerprint", f.Name)
			}
		})
	}
}

// mutate sets v to a value distinct from the one it holds, descending into a
// struct field so each sub-field (Limits.Memory/CPU/PIDs) is exercised.
func mutate(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		v.SetString(v.String() + "-changed")
	case reflect.Int, reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Slice:
		e := reflect.New(v.Type().Elem()).Elem()
		mutate(t, e)
		v.Set(reflect.Append(v, e))
	case reflect.Struct:
		for _, sub := range v.Fields() {
			mutate(t, sub)
		}
	default:
		t.Fatalf("cannot mutate a %s field; teach mutate this kind", v.Kind())
	}
}

// Arg order is meaningful and must affect the fingerprint.
func TestFingerprintArgOrderMatters(t *testing.T) {
	a := &Policy{Entrypoint: "./x", Args: []string{"--a", "--b"}}
	b := &Policy{Entrypoint: "./x", Args: []string{"--b", "--a"}}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("arg order is significant and must change the fingerprint")
	}
}
