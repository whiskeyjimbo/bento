package policy

import (
	"reflect"
	"testing"
)

// The fingerprint is what a manifest's approval attests, so its byte output is a
// wire format: any change to how it is computed invalidates every approval in the
// wild. The other tests here are self-consistent - they compare fingerprints to
// each other and would stay green through a rewrite that shifted every hash. This
// one pins the actual bytes.
//
// The fixture is built to exercise the sort paths: each set-like field arrives out
// of order, and the network rules include a host tie on differing ports, which is
// the only input that distinguishes the two-key rule comparator.
//
// If this fails, do not re-pin it. Either the change was meant to be invisible and
// is not, or the fingerprint format changed deliberately - and that needs a story
// for the approvals it strands.
func TestFingerprintGolden(t *testing.T) {
	p := &Policy{
		Entrypoint:  "./x",
		Interpreter: "python3",
		Args:        []string{"--b", "--a"},
		Env:         []string{"PATH", "HOME", "LANG"},
		Read:        []string{"/two", "/one"},
		Write:       []string{"/out/b", "/out/a"},
		Network: []NetworkRule{
			{Host: "b.com", Port: "80"},
			{Host: "a.com", Port: "443"},
			{Host: "a.com", Port: "80"},
		},
		Exec:   ExecAll,
		Limits: Limits{Memory: "1M", CPU: "50%", PIDs: 128},
	}
	const want = "aa2f73e71ab6923705ca40cd8c9096becc6dcdc3cccc2a834f2e62d777a624ad"
	if got := p.Fingerprint(); got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
}

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
			// Set so the field is covered below, and set here only: the golden hash
			// above must keep proving that a policy without it hashes as it always did.
			InterpreterArgs: []string{"-u"},
			Args:            []string{"--flag"},
			Env:             []string{"PATH"},
			Read:            []string{"/data"},
			Write:           []string{"/out"},
			Network:         []NetworkRule{{Host: "a.com", Port: "443"}},
			// The mode and the allowlist move together: exec_allow is only valid under
			// exec: allowlist, so a base holding one and not the other would be a policy
			// Validate refuses, and this test would be enumerating a shape nothing can run.
			Exec:      ExecAllowlist,
			ExecAllow: []string{"/opt/tool"},
			Limits:    Limits{Memory: "1M", CPU: "50%", PIDs: 128},
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
// The allowlist names what a run may spawn, so two policies differing only there
// permit different things. Sharing one approval between them is the security bug this
// field could most easily introduce, and it is invisible to every test that only checks
// the mode.
func TestFingerprintSeparatesDifferentAllowlists(t *testing.T) {
	allow := func(paths ...string) string {
		p := &Policy{Entrypoint: "./x", Exec: ExecAllowlist, ExecAllow: paths}
		return p.Fingerprint()
	}
	lint := allow("/opt/lint")
	if same := allow("/opt/deploy"); same == lint {
		t.Error("two allowlists naming different binaries share a fingerprint, so one approval attests both")
	}
	if wider := allow("/opt/lint", "/opt/deploy"); wider == lint {
		t.Error("adding a binary to the allowlist left the fingerprint unchanged")
	}
	// Set-like, as the other grant fields are: the order entries are written in does
	// not change what the run may spawn, so it must not force a re-approval.
	if reordered := allow("/opt/deploy", "/opt/lint"); reordered != allow("/opt/lint", "/opt/deploy") {
		t.Error("reordering the allowlist changed the fingerprint")
	}
}

func TestFingerprintArgOrderMatters(t *testing.T) {
	a := &Policy{Entrypoint: "./x", Args: []string{"--a", "--b"}}
	b := &Policy{Entrypoint: "./x", Args: []string{"--b", "--a"}}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("arg order is significant and must change the fingerprint")
	}
}

// A nil policy fingerprints as empty rather than panicking, and must not collide
// with the empty-but-real policy - an approval stamped for one would otherwise read
// as current for the other.
func TestFingerprintNilPolicy(t *testing.T) {
	var p *Policy
	if fp := p.Fingerprint(); fp != "" {
		t.Errorf("nil policy fingerprint = %q, want empty", fp)
	}
	if (&Policy{}).Fingerprint() == "" {
		t.Error("the zero policy must fingerprint distinctly from nil")
	}
}

// The order of the interpreter's options is meaningful - `-c` decides what the words
// after it are - so a reordering is a different policy and must need re-approval.
func TestFingerprintIsSensitiveToInterpreterArgOrder(t *testing.T) {
	a := &Policy{Entrypoint: "./x", Interpreter: "python3", InterpreterArgs: []string{"-u", "-B"}}
	b := &Policy{Entrypoint: "./x", Interpreter: "python3", InterpreterArgs: []string{"-B", "-u"}}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("reordering interpreter_args must change the fingerprint")
	}
}

// The two lists are separate fields and must not be confusable in the canonical form:
// `python3 -u script` and `python3 script -u` are different runs.
func TestFingerprintSeparatesInterpreterArgsFromArgs(t *testing.T) {
	a := &Policy{Entrypoint: "./x", Interpreter: "python3", InterpreterArgs: []string{"-u"}}
	b := &Policy{Entrypoint: "./x", Interpreter: "python3", Args: []string{"-u"}}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("an interpreter option and a script argument of the same text must not fingerprint alike")
	}
}

// The compatibility claim stated exactly: a policy that sets no interpreter args
// hashes as it did before the field existed, whether the field is nil or an empty
// slice. Emitting one line per element rather than one line for the list is what buys
// that, and it is what kept every approve stamp in existence valid.
func TestFingerprintIgnoresAbsentInterpreterArgs(t *testing.T) {
	nilArgs := &Policy{Entrypoint: "./x", Interpreter: "python3"}
	empty := &Policy{Entrypoint: "./x", Interpreter: "python3", InterpreterArgs: []string{}}
	if nilArgs.Fingerprint() != empty.Fingerprint() {
		t.Error("an empty interpreter_args must hash the same as an absent one")
	}
}
