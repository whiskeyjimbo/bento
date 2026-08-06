//go:build linux

package linux

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
)

// The security invariant the sandbox rests on: a policy the grant checks ACCEPT
// must never leave a credential both reachable by a grant and unshielded, and an
// explicit opt-in must expose the real path rather than be silently blanked by a
// residual interior shield. That second half is a real defect class - a shield
// emitted at or under an opted-in directory blanks the very file the opt-in exists
// to expose (a KUBECONFIG=~/.kube/config restatement did exactly this before it was
// dropped). These properties couple the validator (checkNotShielded) to the emitter
// (denyArgs), so a future change that drifts them apart fails here rather than in
// production.
//
// The checker also pins the two values it would otherwise have to trust - the
// opt-in set and the accept/refuse verdict - against independent ground truth built
// from the fixed menus below. Without that, a change making opt-in matching too
// broad (say read:/ opting into every store) would make denyArgs emit no shield,
// and both properties would pass vacuously while production served ~/.ssh over a
// read:/ grant.
//
// The model is deliberately narrow: a single READ grant, DenyAll builtin shields,
// no symlinks (testSandbox.resolve is identity - the real resolve() would follow
// host symlinks for paths that happen to exist, so this stays hermetic; symlink
// resolution is fuzzed separately). Write-grant persistence shields (gitDirShields,
// Workspace) need a different oracle and are covered elsewhere.

// A DenyAll credential a read grant might reach, and the ancestor dirs implied by
// its existence (a file under ~/.ssh means ~/.ssh exists too, which is what a real
// filesystem guarantees and what shieldNeeded keys off).
var fuzzSecrets = []string{
	"/home/u/.ssh/id_rsa",
	"/home/u/.aws/credentials",
	"/home/u/.kube/config",
	"/home/u/.gnupg/secring.gpg",
	"/home/u/.config/gcloud/creds",
	"/run/docker.sock",
}

// Read grants to try: broad grants that must shield everything they sweep in,
// literal opt-ins that must expose the named store, an unrelated directory, and a
// grant strictly inside a shield (which the checks must refuse outright).
var fuzzGrants = []string{
	"/",
	"/home/u",
	"/home/u/.ssh",
	"/home/u/.aws",
	"/home/u/.kube",
	"/home/u/.config/gcloud",
	"/home/u/proj",
	"/run",
	"/home/u/.ssh/id_rsa",
}

// fuzzOptInable is the independent ground truth for which grants in the menu are
// literal DenyAll shield paths a read may opt into (Home + Runtime shields). If
// explicitShieldOptIns ever returns something other than exactly [g] for these (or
// anything for the others), the coupling assertion fails instead of the properties
// going silently vacuous.
var fuzzOptInable = map[string]bool{
	"/home/u/.ssh":           true,
	"/home/u/.aws":           true,
	"/home/u/.kube":          true,
	"/home/u/.config/gcloud": true,
	"/run":                   true,
}

// fuzzRefusedGrant is the one menu grant checkNotShielded must refuse: it names a
// path strictly inside a shield without opting into the shield itself. Every other
// menu grant is accepted (a broad read that merely contains shields is fine, a
// literal opt-in is honored, an unrelated path is free).
const fuzzRefusedGrant = "/home/u/.ssh/id_rsa"

// ancestorsUnderHome returns the directory components of a file between home and the
// file itself, so placing a secret also marks its parent store as existing.
func ancestorsUnderHome(file string) []string {
	var dirs []string
	for d := filepath.Dir(file); d != "/" && d != "/home"; d = filepath.Dir(d) {
		dirs = append(dirs, d)
	}
	return dirs
}

// shieldDests extracts the destination path of every shield mount denyArgs emits,
// independent of denyArgs' own logic: --tmpfs <dst> and --ro-bind <src> <dst>. When
// hidingOnly is set, only shields that HIDE content are returned - a --tmpfs, or a
// --ro-bind whose source is the empty shield file. A DenyWrite --ro-bind of a path
// onto itself keeps the content readable, so it must not count as "the secret is
// hidden" (it doesn't, today writes are absent so no such rule is emitted - this
// keeps the oracle correct when write grants are added later).
func shieldDests(args []string, emptyFile string, hidingOnly bool) []string {
	var dsts []string
	for i := 0; i < len(args); {
		switch args[i] {
		case "--tmpfs":
			dsts = append(dsts, args[i+1])
			i += 2
		case "--ro-bind":
			src, dst := args[i+1], args[i+2]
			if !hidingOnly || src == emptyFile {
				dsts = append(dsts, dst)
			}
			i += 3
		default:
			i++
		}
	}
	return dsts
}

// checkShieldInvariants runs the coupling and property assertions for one (grant,
// existence-mask) input. Shared by the fuzz and the exhaustive subtest so both hold
// the same guarantees.
func checkShieldInvariants(t *testing.T, grantIdx, existMask int) {
	t.Helper()
	g := fuzzGrants[((grantIdx%len(fuzzGrants))+len(fuzzGrants))%len(fuzzGrants)]

	var existing []string
	var present []string
	for i, s := range fuzzSecrets {
		if existMask&(1<<i) == 0 {
			continue
		}
		present = append(present, s)
		existing = append(existing, s)
		existing = append(existing, ancestorsUnderHome(s)...)
	}
	sb := testSandbox(existing...)

	reads := []string{g}
	optIns := explicitShieldOptIns(sb, reads)
	optInLit, optInRes := optInPaths(optIns), shield.Targets(optIns)

	// Coupling 1: the opt-in set matches independent ground truth. resolve is
	// identity here, so literal and resolved are equal and both must be exactly [g]
	// for an opt-in-able grant, empty otherwise.
	var wantOptIn []string
	if fuzzOptInable[g] {
		wantOptIn = []string{g}
	}
	if !slices.Equal(optInRes, wantOptIn) || !slices.Equal(optInLit, wantOptIn) {
		t.Fatalf("grant %q: opt-in set = %v/%v, want %v", g, optInLit, optInRes, wantOptIn)
	}

	// Coupling 2: the accept/refuse verdict matches ground truth, so a stricter
	// future check cannot silently delete the assertion regions below.
	err := checkReadNotShielded(sb, reads, optInRes)
	wantRefused := g == fuzzRefusedGrant
	if (err != nil) != wantRefused {
		t.Fatalf("grant %q: refused=%v (want %v): %v", g, err != nil, wantRefused, err)
	}
	if err != nil {
		return // a refused policy is never enforced; nothing to prove about its shields
	}

	args, _ := denyArgs(sb, reads, nil, optInRes)
	allDests := shieldDests(args, sb.emptyFile, false)
	hidingDests := shieldDests(args, sb.emptyFile, true)

	// Property B: an opted-in store exposes its real content, so nothing at or under
	// it may be shielded at all - a residual interior shield would blank it.
	for _, d := range optInRes {
		for _, dst := range allDests {
			if dst == d || policy.CoversResolved(d, dst) {
				t.Fatalf("opt-in %q blanked: shield emitted at %q (opt-in %v)", d, dst, optInLit)
			}
		}
	}

	// Property A: any existing secret the grant reaches, and that is not inside an
	// opted-in store, must be HIDDEN by a shield (not merely rebound read-only).
	for _, s := range present {
		if !reachable(s, reads) || coveredBy(s, optInRes) {
			continue
		}
		if !coveredBy(s, hidingDests) {
			t.Fatalf("secret %q reachable by grant %q but not hidden; hiding shields=%v", s, g, hidingDests)
		}
	}
}

func FuzzShieldCoversReachableSecrets(f *testing.F) {
	f.Add(0, 0)                     // no secrets, root grant
	f.Add(0, 1<<len(fuzzSecrets)-1) // every secret, root grant: must shield all
	f.Add(2, 1)                     // opt-in ~/.ssh with id_rsa present
	f.Add(8, 1)                     // grant inside ~/.ssh: must be refused
	f.Add(1, 1<<len(fuzzSecrets)-1) // broad home grant, every secret
	f.Fuzz(checkShieldInvariants)
}

// TestShieldInvariantsExhaustive runs every (grant, existence-mask) combination -
// the input space is small enough to enumerate, so coverage is guaranteed rather
// than left to the fuzz corpus.
func TestShieldInvariantsExhaustive(t *testing.T) {
	for gi := range fuzzGrants {
		for mask := 0; mask < 1<<len(fuzzSecrets); mask++ {
			t.Run(fmt.Sprintf("grant%d_mask%d", gi, mask), func(t *testing.T) {
				checkShieldInvariants(t, gi, mask)
			})
		}
	}
}
