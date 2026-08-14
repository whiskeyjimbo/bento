// Package grantrefusal holds the words bento refuses a grant in.
//
// A refusal is raised at whichever point in the run first sees the host fact behind it -
// a write grant that is a file is caught by the argv compiler on one path and by the
// directory preparation on another, a loop by the grant check on one and by the same
// preparation on another - and `bento validate` predicts all of them before anything
// runs - and `bento approve` refuses to stamp what it predicts. That is many call sites for
// a handful of sentences. Shared here so a reader who meets one of them in a CI gate and
// again at run time reads the same sentence, and so a reworded refusal cannot answer half
// of them.
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

// WriteUnderReadOnlyShield refuses a write grant at or inside a DenyWrite shield: a
// home store (~/.local/bin, ~/.bashrc, ...) or a checkout's own execution surface
// (.git/hooks, .vscode). Unlike the DenyAll shields there is no opt-in: the content is
// readable already, so the only thing an opt-in could grant is the plant. The sentence
// names no anchor, because the workspace shields are derived from the write grants
// rather than applied on every run.
func WriteUnderReadOnlyShield(grant, shield string) error {
	return fmt.Errorf("write grant %q is at or inside the write-shielded path %q and cannot be honored - the shield is read-only and there is no opt-in, because it exists to stop a plant that the host runs later; remove this grant, or write somewhere outside %q", grant, shield, shield)
}

// WriteAboveShield refuses a write grant that contains a shielded path, which would make
// the shield's own name writable in a directory the run can reach.
func WriteAboveShield(grant, shield string) error {
	return fmt.Errorf("write grant %q contains the always-shielded path %q, so its parent would be writable and a run could tamper with or expose it; grant a narrower directory instead", grant, shield)
}

// WriteAboveWriteShield refuses a write grant that contains a write-shielded path, on the
// degraded tier only. It names the tier because the same manifest runs under bwrap: there
// the shield's read-only bind lands after the grant and holds, and here there is nothing
// to land - Landlock unions the rights of every matching rule, so no narrower rule can
// carve the shield back out of a granted tree.
func WriteAboveWriteShield(grant, shield string) error {
	return fmt.Errorf("write grant %q contains the write-shielded path %q, which the degraded tier cannot shield: without a mount namespace there is nothing to bind read-only over it, so a run could plant an executable there that the host runs later; grant a directory that does not contain %q, or run without --allow-degraded", grant, shield, shield)
}

// FoldedShield refuses a grant containing a shielded path whose directory folds case, so
// the shield's single byte-exact bind leaves the same file readable under another
// spelling. It offers no opt-in and no narrower grant of the shield itself, because a
// folding directory reaches one inode under every spelling there is: nothing bento can
// bind contains it, and only a grant that stops short of the directory does.
func FoldedShield(grant, shield string) error {
	return fmt.Errorf("grant %q contains the always-shielded path %q on a case-insensitive filesystem, where a second spelling of that name reaches the same file past the shield; no set of shields can cover every spelling - grant a directory that does not contain %q, or move it to a case-sensitive filesystem", grant, shield, shield)
}

// WriteIsRoot refuses a write grant of the host root, which would defeat the sandbox
// outright. Unlike a read grant, "/" is never expanded for writes.
func WriteIsRoot() error {
	return fmt.Errorf("write grant %q would make the entire host root writable; grant a specific directory", "/")
}

// GrantIsProcess refuses a grant landing in a host process's /proc/<pid> directory. The
// sandbox has a pid namespace and a procfs of its own, so the pid the grant names is a
// different process inside it, or none.
func GrantIsProcess(grant, resolved string) error {
	return fmt.Errorf("grant %q resolves to %q, a host process's directory in /proc; the sandbox has a pid namespace and a /proc of its own, where that pid is a different process or none at all; remove the grant - /proc is always mounted", grant, resolved)
}

// GrantIsManagedMount refuses a grant naming, whole, a pseudo-filesystem the sandbox
// mounts fresh (denylist.ManagedMounts). Bound whole the host's version overmounts the
// sandbox's hardened one, since the last mount in argv order wins. A specific path
// inside one still binds fine.
func GrantIsManagedMount(grant, resolved, mount string) error {
	return fmt.Errorf("grant %q resolves to %q, a pseudo-filesystem the sandbox mounts fresh; granting it whole would overmount the sandbox's hardened %s with the host's and re-expose host process environs, device nodes, or other processes' temp files; %s is always mounted - grant a specific path inside it instead", grant, resolved, mount, mount)
}

// ShieldNotCarvable refuses a write grant on a directory this uid cannot create entries
// in, where the run's own shields have to be carved. It names the directory that refused
// rather than the grant alone: the grant can be a whole tree and only one directory
// inside it is the one the mkdir needs.
func ShieldNotCarvable(grant, shield, dir string) error {
	return fmt.Errorf("write grant %q cannot be honored: bento shields %q inside it, and creating that mount point needs write permission on %q, which your user does not have; remove the grant, or write somewhere your user owns", grant, shield, dir)
}

// WriteUnstattable refuses a write grant the invoking user cannot stat for any reason but
// absence or a loop - a directory above it their user cannot traverse being the ordinary
// one. Unlike a read grant, the answer is not narrowed by the sandbox seeing the tree as
// another user's view: the run stats it as the invoker, before the sandbox exists, and
// refuses on what it finds there.
func WriteUnstattable(grant string, err error) error {
	return fmt.Errorf("write grant %q cannot be checked on this host: %w; the run stats it as your own user before the sandbox exists, so a directory above it that your user cannot traverse refuses the run - grant a path your user can reach", grant, err)
}

// Looped refuses a grant whose symlinks loop. Read and write alike: bwrap's --ro-bind-try
// tolerates only a missing source, not ELOOP, so a looping grant of either kind aborts
// the run naming bwrap rather than the grant.
func Looped(grant string) error {
	return fmt.Errorf("grant %q loops through itself on the host, so it names nothing that can be bound; fix the link or remove the grant", grant)
}
