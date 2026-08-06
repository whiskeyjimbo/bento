//go:build linux

package linux

import (
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// internal/shield owns containment - whether a grant lands inside a shield. Nothing
// owned ORDER, which is the other half: bwrap applies mounts in argv order and the
// last one wins, so a shield that is emitted before a bind covering it is inert. Three
// P1/P2 escapes have come from position in argv while containment was right (the
// entrypoint re-bind landing after the deny-list, the interpreter prefix mount, a
// whole-/proc grant overmounting the hardened procfs), each found by someone reasoning
// about it rather than by a gate. These two properties are that gate.

// argvMount is one bwrap mount in the compiled argv: where it lands and where in the
// sequence it lands. Only the destination matters for last-wins, and the destination
// operand's position depends on the flag's arity - reading it as the operand right
// after the flag would take the SOURCE of a two-operand bind and pass vacuously.
type argvMount struct {
	i    int
	dest string
}

func argvMounts(args []string) []argvMount {
	var out []argvMount
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--":
			// Everything past the separator is the launcher's own argv and then the
			// target's. Those are not bwrap flags, and a target argument spelled
			// "--tmpfs" would otherwise be read as a mount.
			return out
		case "--setenv":
			i += 2 // a value spelled like a flag is a value, not a mount
		case "--bind", "--bind-try", "--ro-bind", "--ro-bind-try", "--symlink":
			if i+2 < len(args) {
				out = append(out, argvMount{i, args[i+2]})
				i += 2
			}
		case "--tmpfs", "--dev", "--proc":
			if i+1 < len(args) {
				out = append(out, argvMount{i, args[i+1]})
				i++
			}
		}
	}
	return out
}

// assertShieldsWin checks both directions of the ordering invariant for every shield
// the run actually applied.
//
// Covering: the last mount whose destination covers a shielded path must be the shield
// itself. This is the property all three historical escapes violated, and it is
// checkable without running bwrap.
//
// Nesting: nothing emitted after a shield may land strictly under it, because such a
// mount re-creates content inside a hidden tree. Three binds are allowed to: a nested
// stricter shield (a hidden store inside a read-only config tree is emitted after its
// parent on purpose), and the entrypoint and interpreter re-binds, which exist so a
// shield cannot leave the run with nothing to execute. Caller-supplied denies are
// refused outright at newSandbox, so what those two can expose is a built-in shield the
// operator pointed bento at directly.
//
// --remount-ro is not a mount: it re-flags "/" in place and exposes no content, so it
// covers every shield without winning over any. --proc and --dev are mounts and are
// deliberately included; a run that overmounts them past a shield is the whole-/proc
// escape, and the only way to reach it is refused by checkGrants.
func assertShieldsWin(t *testing.T, args []string, applied []enforce.ShieldApplied, sb sandbox) {
	t.Helper()
	if len(applied) == 0 {
		t.Fatal("no shield applied: the row proves nothing about ordering")
	}
	mounts := argvMounts(args)
	shielded := map[string]bool{}
	for _, s := range applied {
		shielded[s.Path] = true
	}
	allowedUnder := map[string]bool{sb.entrypoint: true, sb.interpreter: true, sandboxBentoPath: true, sandboxProxySocket: true}

	for _, s := range applied {
		covering, own := -1, -1
		for _, m := range mounts {
			if policy.CoversResolved(m.dest, s.Path) {
				covering = m.i
				if m.dest == s.Path {
					own = m.i
				}
			}
			if m.i > own && own >= 0 && !shielded[m.dest] && !allowedUnder[m.dest] && policy.CoversResolved(s.Path, m.dest) && m.dest != s.Path {
				t.Errorf("%s lands under the shield on %s at argv %d, re-exposing content inside it", m.dest, s.Path, m.i)
			}
		}
		if own < 0 {
			t.Errorf("shield on %s is reported applied but nothing in argv binds it", s.Path)
			continue
		}
		if covering != own {
			t.Errorf("a mount at argv %d covers the shield on %s bound at argv %d, so the shield loses", covering, s.Path, own)
		}
	}
}

// The rows are the shapes where a covering bind and a shield meet: a home read grant
// (the case that reaches the shields at all - a write grant above one is refused), an
// interpreter under $HOME (bound as a file by systemMounts, then re-bound last), an
// entrypoint inside a built-in shield, and a profiling run, whose $HOME tmpfs is
// emitted before the grants precisely so they overmount it.
func TestShieldsWinTheArgvOrder(t *testing.T) {
	home := func(extra ...string) sandbox {
		return testSandbox(append([]string{"/home/u/.ssh", "/home/u/.ssh/id_rsa", "/home/u/.aws", "/home/u/.config/gh"}, extra...)...)
	}
	for _, tc := range []struct {
		name string
		p    *policy.Policy
		sb   func() sandbox
		proc enforce.Process
	}{
		{"home read grant", &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}, func() sandbox { return home() }, enforce.Process{}},
		{"root read grant", &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/"}}, func() sandbox { return home() }, enforce.Process{}},
		{"exec all", &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}, Exec: policy.ExecAll}, func() sandbox { return home() }, enforce.Process{}},
		{"write grant under home", &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}, Write: []string{"/home/u/proj"}}, func() sandbox {
			return home("/home/u/proj/src")
		}, enforce.Process{}},
		{"interpreter under home", &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}, func() sandbox {
			sb := home("/home/u/bin/python")
			sb.interpreter = "/home/u/bin/python"
			return sb
		}, enforce.Process{}},
		{"entrypoint inside a shield", &policy.Policy{Entrypoint: "/home/u/.ssh/id_rsa", Read: []string{"/home/u"}}, func() sandbox {
			sb := home()
			sb.entrypoint = "/home/u/.ssh/id_rsa"
			return sb
		}, enforce.Process{}},
		{"profiling run", &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}, func() sandbox {
			sb := home()
			sb.observe = true
			return sb
		}, enforce.Process{Env: map[string]string{"HOME": "/home/u"}}},
		{"launcher with egress", &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}, func() sandbox {
			sb := home()
			sb.bentoPath, sb.proxySocket = "/usr/bin/bento", "/run/bento/proxy.sock"
			return sb
		}, enforce.Process{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := tc.sb()
			args, applied, err := compile(tc.p, tc.proc, sb)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if sb.observe && !has(args, "--tmpfs", "/home/u") {
				t.Fatal("the profiling row exists for the $HOME tmpfs; without it the row is the plain home grant again")
			}
			assertShieldsWin(t, args, applied, sb)
		})
	}
}

// The parser is what the invariant rests on, so it gets its own check: a bind's
// destination is its SECOND operand. Reading the first would silently make every
// assertion above vacuous for the file shields, which bind an empty host file over the
// credential path.
func TestArgvMountsReadsTheDestination(t *testing.T) {
	got := argvMounts([]string{"--ro-bind", "/tmp/shield", "/home/u/.ssh/id_rsa", "--tmpfs", "/home/u/.aws", "--setenv", "HOME", "/home/u", "--remount-ro", "/"})
	want := []string{"/home/u/.ssh/id_rsa", "/home/u/.aws"}
	if len(got) != len(want) {
		t.Fatalf("argvMounts returned %v, want destinations %v", got, want)
	}
	for i, m := range got {
		if m.dest != want[i] {
			t.Errorf("mount %d dest = %q, want %q", i, m.dest, want[i])
		}
	}
}

// The deny-list emits DenyWrite before DenyAll so a hidden credential lands after the
// readable tree bind that contains it - the shape the coding-agent rules turn on, where
// ~/.claude is read-only and ~/.claude/.credentials.json is hidden inside it. Asserted on
// denyArgs rather than through compile, because the only grant that engages a DenyWrite
// directory shield is a write reaching it, and checkGrants refuses every one of those:
// the argv property the deny-list relies on outlives the refusal that hides it here.
func TestHiddenCredentialLandsAfterTheReadableTreeThatHoldsIt(t *testing.T) {
	tree, secret := "/home/u/.claude", "/home/u/.claude/.credentials.json"
	sb := testSandbox(tree, secret, "/home/u/.claude/settings.json")
	args, applied := denyArgs(sb, []string{"/home/u"}, []string{tree}, nil)

	mounts := argvMounts(args)
	at := func(dest string) int {
		last := -1
		for _, m := range mounts {
			if m.dest == dest {
				last = m.i
			}
		}
		return last
	}
	if !hasShield(shieldsApplied(applied), tree, "read-only") || !hasShield(shieldsApplied(applied), secret, "hidden") {
		t.Fatalf("expected a read-only %s holding a hidden %s; got %v", tree, secret, shieldsApplied(applied))
	}
	if at(secret) < at(tree) {
		t.Errorf("the hidden credential is bound at argv %d, before the readable tree at %d, so the tree re-exposes it", at(secret), at(tree))
	}
}
