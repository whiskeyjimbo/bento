package linux

import (
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/policy"
)

// The security invariant the sandbox rests on: a policy the grant checks ACCEPT
// must never leave a credential both reachable by a grant and unshielded, and an
// explicit opt-in must expose the real path rather than be silently blanked by a
// residual interior shield. That second half is a real defect class - a shield
// emitted at or under an opted-in directory blanks the very file the opt-in exists
// to expose (a KUBECONFIG=~/.kube/config restatement did exactly this before it was
// dropped). These properties couple the validator (checkNotShielded) to the emitter
// (denyArgs), so a future change that drifts them apart fails here rather than in
// production. The fuzz drives the pure, filesystem-injected path so it stays
// hermetic (the real resolve() would follow host symlinks for paths that happen to
// exist).

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
// independent of denyArgs' own logic: --tmpfs <dst> and --ro-bind <src> <dst>.
func shieldDests(args []string) []string {
	var dsts []string
	for i := 0; i < len(args); {
		switch args[i] {
		case "--tmpfs":
			dsts = append(dsts, args[i+1])
			i += 2
		case "--ro-bind":
			dsts = append(dsts, args[i+2])
			i += 3
		default:
			i++
		}
	}
	return dsts
}

func FuzzShieldCoversReachableSecrets(f *testing.F) {
	f.Add(0, 0)                              // no secrets, root grant
	f.Add(0, 1<<len(fuzzSecrets)-1)          // every secret, root grant: must shield all
	f.Add(2, 1)                              // opt-in ~/.ssh with id_rsa present
	f.Add(8, 1)                              // grant inside ~/.ssh: must be refused, skipped
	f.Add(1, 1<<len(fuzzSecrets)-1)          // broad home grant, every secret

	f.Fuzz(func(t *testing.T, grantIdx, existMask int) {
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

		p := &policy.Policy{Read: []string{g}}
		reads := []string{g}

		optInLit, optInRes := explicitShieldOptIns(sb, p.Read)
		if err := checkNotShielded(sb, reads, optInRes); err != nil {
			return // a refused policy is never enforced; nothing to prove about its shields
		}

		dests := shieldDests(denyArgs(sb, reads, nil, optInRes))

		// Property B: an opted-in store exposes its real content, so nothing at or
		// under it may be shielded - a residual interior shield would blank it.
		for _, d := range optInRes {
			for _, dst := range dests {
				if dst == d || under(dst, d) {
					t.Fatalf("opt-in %q blanked: shield emitted at %q (opt-in literals %v)", d, dst, optInLit)
				}
			}
		}

		// Property A: any existing secret the grant reaches, and that is not inside an
		// opted-in store, must be behind a shield.
		for _, s := range present {
			if !reachable(s, reads) {
				continue
			}
			if optedIn := coveredBy(s, optInRes); optedIn {
				continue
			}
			if !coveredBy(s, dests) {
				t.Fatalf("secret %q reachable by grant %q but not shielded; shields=%v", s, g, dests)
			}
		}
	})
}
