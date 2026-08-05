// Package grantrefusal holds the words bento refuses a grant in.
//
// A refusal is raised at whichever point in the run first sees the host fact behind it -
// a write grant that is a file is caught by the argv compiler on one path and by the
// directory preparation on another, a loop by the grant check on one and by the same
// preparation on another - and `bento validate` predicts all of them before anything
// runs - and `bento approve` refuses to stamp what it predicts. That is thirteen call
// sites for five sentences. Shared here so a reader who meets one
// of them in a CI gate and again at run time reads the same sentence, and so a reworded
// refusal cannot answer half of them.
//
// The sentence, not the path it quotes. The run names the grant as it resolved it and the
// gate as the manifest spells it, which is what each reader is looking at.
//
// The wording only. Each caller keeps its own stat: they work on paths resolved to
// different degrees and answer differently - the run refuses, the gate reports - and a
// classifier common to all of them would have to be parameterized into saying nothing.
package grantrefusal

import "fmt"

// WriteIsFile refuses a write grant that names an existing file. Write grants name
// directories - the sandbox binds one - so a grant naming a file inside it cannot be
// honored as written, and creating a directory over it would destroy nothing but confuse
// everything.
func WriteIsFile(grant string) error {
	return fmt.Errorf("write grant %q is a file; grant its parent directory instead", grant)
}

// InsideShield refuses a READ grant at or inside a fully-shielded location (a DenyAll
// deny-list directory such as ~/.ssh). The shield wins over the grant, so honoring it
// would leave the author believing a path is available when it is not. The remedy it
// offers is the read opt-in, which only a read can take - a write of the same path gets
// WriteInsideShield.
func InsideShield(grant, shield string) error {
	return fmt.Errorf("grant %q is inside the always-shielded path %q and cannot be honored; a read: grant of %q itself opts in (exposing it read-only, with a warning) - or remove this grant", grant, shield, shield)
}

// WriteInsideShield refuses a WRITE grant at or inside a fully-shielded location. It is
// InsideShield's counterpart and exists because that sentence's remedy is a read: grant,
// which a write grant cannot use: the opt-in is read-only by construction - it takes the
// policy's reads alone - and extending it to writes would grant exactly the plant the
// deny-list holds these paths for. Offering it here would send the author around a
// refusal loop with no exit, adding a read: line that leaves the write refused.
func WriteInsideShield(grant, shield string) error {
	return fmt.Errorf("write grant %q is inside the always-shielded path %q and cannot be honored; there is no opt-in for a write, because it would grant the credential plant the shield exists to stop - remove this grant, or write somewhere outside %q", grant, shield, shield)
}

// InsideCallerShield refuses a grant at or inside a deny path the embedding program
// supplied. Separate from InsideShield because that sentence offers the read opt-in, and
// there is none here: the opt-in lifts bento's own built-in shields, and an embedder's
// deny belongs to a trust domain the manifest it runs must not be able to talk its way
// out of.
func InsideCallerShield(grant, shield string) error {
	return fmt.Errorf("grant %q is inside %q, which the program running bento shields from this manifest; that shield has no opt-in - remove this grant, or take it up with whatever launched the run", grant, shield)
}

// WriteUnderReadOnlyShield refuses a write grant at or inside a DenyWrite shield
// (~/.local/bin, ~/.bashrc, ...). Unlike the DenyAll shields there is no opt-in: the
// content is readable already, so the only thing an opt-in could grant is the plant.
func WriteUnderReadOnlyShield(grant, shield string) error {
	return fmt.Errorf("write grant %q is at or inside the always-write-shielded path %q and cannot be honored - the shield is read-only and there is no opt-in, because it exists to stop a plant that the host runs later; remove this grant, or write somewhere outside %q", grant, shield, shield)
}

// WriteAboveShield refuses a write grant that contains a shielded path, which would make
// the shield's own name writable in a directory the run can reach.
func WriteAboveShield(grant, shield string) error {
	return fmt.Errorf("write grant %q contains the always-shielded path %q, so its parent would be writable and a run could tamper with or expose it; grant a narrower directory instead", grant, shield)
}

// Looped refuses a grant whose symlinks loop. Read and write alike: bwrap's --ro-bind-try
// tolerates only a missing source, not ELOOP, so a looping grant of either kind aborts
// the run naming bwrap rather than the grant.
func Looped(grant string) error {
	return fmt.Errorf("grant %q loops through itself on the host, so it names nothing that can be bound; fix the link or remove the grant", grant)
}
