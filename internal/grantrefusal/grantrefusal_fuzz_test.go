package grantrefusal

import (
	"errors"
	"testing"
)

// FuzzRefusalsAreTerminalSafe applies the property FuzzParseManifest asserts of the
// decoder's refusals to this package's fourteen. The subject is the same: every sentence
// here is built from a path bento did not write - a grant out of somebody's manifest, a
// shield relocated by an environment variable - and every one goes to a terminal, where a
// raw C0 or C1 control is not text but a command. %q is what makes them safe today, and
// nothing until now failed if one of them were reworded to %s.
//
// Stricter than the manifest's version on tab and newline, which that one exempts because
// the YAML decoder lays its annotation out with both. A refusal here is one line, so a
// control of any kind in it came out of the path.
func FuzzRefusalsAreTerminalSafe(f *testing.F) {
	f.Add("/srv/app", "/home/op/.ssh", "/etc")
	f.Add("\x1b[31mBAD\x1b[0m", "/home/op/.ssh", "/etc")
	f.Add("/srv/app", "\u009b31m", "/etc")
	f.Add("/srv/app", "/home/op/.ssh", "a\x00b")
	f.Add("\x7f", "\r\n", "\t")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, grant, shield, dir string) {
		// The wrapped error is deliberately control-free: WriteUnstattable renders the
		// host's own *fs.PathError verbatim through %w, which quotes nothing, so what this
		// can assert is the constructor's own contribution. Not the whole sentence, and the
		// gap is not the grant - policy.FirstUnsafeRune screens control runes out of that -
		// but the path the PathError names, which is the symlink-RESOLVED one both call
		// sites stat (gate.go:236, internal/linux/linux.go:731). Its components are host
		// symlink targets no manifest screen ever saw.
		stat := errors.New("permission denied")
		// The one argument held out of the fuzz. GrantIsManagedMount renders its mount
		// through %s, twice, which quotes nothing - and that is not a hole because the
		// mount is never a path off a manifest: both call sites iterate
		// denylist.ManagedMounts, five literals in a package-level var. Fuzzing it would
		// assert a property the sentence does not claim and flag a defect nothing can reach.
		const mount = "/tmp"
		for _, err := range []error{
			WriteIsFile(grant),
			InsideShield(grant, shield),
			WriteInsideShield(grant, shield),
			InsideCallerShield(grant, shield),
			WriteUnderReadOnlyShield(grant, shield),
			WriteAboveShield(grant, shield),
			WriteAboveWriteShield(grant, shield),
			FoldedShield(grant, shield),
			WriteIsRoot(),
			GrantIsProcess(grant, shield),
			GrantIsManagedMount(grant, shield, mount),
			ShieldNotCarvable(grant, shield, dir),
			WriteUnstattable(grant, stat),
			Looped(grant),
		} {
			for _, r := range err.Error() {
				if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
					t.Fatalf("a refusal carries the raw control character %U, which the terminal it is printed to acts on: %q", r, err.Error())
				}
			}
		}
	})
}
