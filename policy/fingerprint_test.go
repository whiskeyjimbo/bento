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
// to Policy later is silently uncovered. Walk the struct instead, one leaf at a
// time: a leaf mutated on its own must move the fingerprint, so a sibling that is
// hashed cannot cover for one that is not.
//
// The base is fully populated on purpose. Every leaf is mutated in place rather
// than appended, because appending to an empty slice moves the fingerprint on the
// strength of the record existing at all - which is how NetworkRule.Port escaped
// the hash undetected.
func TestFingerprintCoversEveryPolicyField(t *testing.T) {
	// A fresh policy per case: copying one would share its slice backing arrays, and
	// an in-place leaf mutation writes through to every later case.
	base := func() Policy {
		return Policy{
			Entrypoint:  "./x",
			Interpreter: "python3",
			Args:        []string{"--flag"},
			Env:         []string{"PATH"},
			Read:        []string{"/data"},
			Write:       []string{"/out"},
			Network:     []NetworkRule{{Host: "a.com", Port: "443"}},
			Exec:        ExecAll,
			Limits:      Limits{Memory: "1M", CPU: "50%", PIDs: 128},
		}
	}
	unchanged := base()
	fp := unchanged.Fingerprint()

	for _, leaf := range leaves(t, reflect.TypeFor[Policy]()) {
		t.Run(leaf.name, func(t *testing.T) {
			p := base()
			leaf.mutate(reflect.ValueOf(&p).Elem())
			if p.Fingerprint() == fp {
				t.Errorf("Policy.%s is not covered by the fingerprint", leaf.name)
			}
		})
	}
}

// join names a nested leaf: the outer step, then the inner path if there is one.
func join(outer, inner string) string {
	if inner == "" {
		return outer
	}
	return outer + "." + inner
}

// leaf is one scalar reachable from a Policy, and the mutation that changes it
// and nothing else.
type leaf struct {
	name   string
	mutate func(reflect.Value)
}

// leaves enumerates every scalar under t, descending through structs and slice
// element types. A slice leaf mutates element zero, so the base must supply one.
func leaves(t *testing.T, typ reflect.Type) []leaf {
	t.Helper()
	switch typ.Kind() {
	case reflect.String:
		return []leaf{{mutate: func(v reflect.Value) { v.SetString(v.String() + "-changed") }}}
	case reflect.Int, reflect.Int64:
		return []leaf{{mutate: func(v reflect.Value) { v.SetInt(v.Int() + 1) }}}
	case reflect.Slice:
		var out []leaf
		for _, l := range leaves(t, typ.Elem()) {
			out = append(out, leaf{name: join("[0]", l.name), mutate: func(v reflect.Value) {
				if v.Len() == 0 {
					t.Fatalf("the base policy leaves a %s empty; give it an element", typ)
				}
				l.mutate(v.Index(0))
			}})
		}
		return out
	case reflect.Struct:
		var out []leaf
		for _, f := range reflect.VisibleFields(typ) {
			if !f.IsExported() {
				t.Fatalf("cannot mutate unexported field %s; teach leaves this shape", f.Name)
			}
			for _, l := range leaves(t, f.Type) {
				out = append(out, leaf{name: join(f.Name, l.name), mutate: func(v reflect.Value) {
					l.mutate(v.FieldByIndex(f.Index))
				}})
			}
		}
		return out
	default:
		t.Fatalf("cannot mutate a %s field; teach leaves this kind", typ.Kind())
		return nil
	}
}

// An omitted exec mode and an explicit "none" are the same permission to the
// enforcer, so they must not need two approvals.
func TestFingerprintTreatsEmptyExecAsNone(t *testing.T) {
	omitted := &Policy{Entrypoint: "./x"}
	spelled := &Policy{Entrypoint: "./x", Exec: ExecNone}
	if omitted.Fingerprint() != spelled.Fingerprint() {
		t.Error("an omitted exec mode must fingerprint as none")
	}
	strict := &Policy{Entrypoint: "./x", Exec: ExecNoneStrict}
	if strict.Fingerprint() == spelled.Fingerprint() {
		t.Error("none and none-strict are different permissions and must fingerprint apart")
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
