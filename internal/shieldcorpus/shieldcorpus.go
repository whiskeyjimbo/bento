// Package shieldcorpus is one set of grants, one host layout, and one expected verdict
// per grant, shared by the three places that independently answer "does this grant land
// inside a shield": the Linux backend's grant checks, the validate gate's shield
// problems, and the profiler's proposal clamp.
//
// They are required to agree and have diverged, which is the whole reason this exists.
// The three cannot be driven from one test binary - the backend is //go:build linux and
// the other two live in package main, so neither side can import the other - so agreement
// is asserted the only way left: each site is tested against this table in its own
// package, and a site that answers differently goes red on its own.
//
// The backend is authoritative. Verdict is what a RUN does, and the other two are
// measured against it, because the run is the thing that actually refuses. Where a site
// deliberately answers something else, the case says so in a field and gives the reason;
// a divergence with no field is a bug in that site, not a case to be edited.
package shieldcorpus

import (
	"fmt"
	"os"
	"path/filepath"
)

// Verdict is what the backend does with a grant.
type Verdict int

const (
	// Honored means the run binds the grant: no shield check refuses it.
	Honored Verdict = iota
	// InsideShield means a grant at or inside a DenyAll shield, refused by
	// grantrefusal.InsideShield for a read and WriteInsideShield for a write.
	InsideShield
	// UnderWriteShield means a write at or inside a DenyWrite shield, refused by
	// grantrefusal.WriteUnderReadOnlyShield. There is no read counterpart: a DenyWrite
	// shield leaves its content readable.
	UnderWriteShield
	// AboveShield means a write that CONTAINS a DenyAll shield, refused by
	// grantrefusal.WriteAboveShield.
	AboveShield
)

func (v Verdict) String() string {
	switch v {
	case Honored:
		return "honored"
	case InsideShield:
		return "inside a DenyAll shield"
	case UnderWriteShield:
		return "under a DenyWrite shield"
	case AboveShield:
		return "above a DenyAll shield"
	}
	return fmt.Sprintf("Verdict(%d)", int(v))
}

// Case is one grant judged against one host layout.
type Case struct {
	// Name identifies the case in a failure; Why says what shape it is covering, so a
	// site that goes red says what it got wrong rather than only that it did.
	Name string
	Why  string
	// Grant is relative to the home Build populated, joined by Path.
	Grant string
	// Write reports the grant's kind. The two kinds are separate cases even over the
	// same path, because the read opt-in has no write counterpart.
	Write bool
	// Verdict is what the run does. Everything else is measured against it.
	Verdict Verdict
	// OptInRead marks a read that names a DenyAll shield's own deny-list path. The run
	// honors it as a warned, deliberate opt-in; the profiler still drops it from a
	// proposal, since an opt-in is something a reviewer adds by hand rather than
	// something a draft manifest arrives with.
	OptInRead bool
	// ClampKeeps marks a case the profiler's clamp deliberately does not mirror. Only
	// AboveShield: the clamp keeps a grant that merely contains a shield, because the
	// enforced run re-shields the interior, and dropping every enclosing grant would gut
	// the ordinary "read: ~" proposal.
	ClampKeeps bool
	// ShieldOntoHome adds a shield rule whose symlink lands on the home anchor itself.
	// Only the case testing that shape gets it: a rule resolving onto the home covers
	// every other grant in the layout, so leaving it in place for all of them would let
	// one divergence mask the rest.
	ShieldOntoHome bool
}

// Path is the case's grant as an absolute path under the home Build populated.
func (c Case) Path(home string) string { return filepath.Join(home, c.Grant) }

// Cases is the corpus. Every entry is a shape the three sites have to answer alike, or a
// shape where one of them is already known to answer differently - those are the point.
var Cases = []Case{
	{
		Name:    "write to a symlinked credential entry's target",
		Why:     "stow and chezmoi make ~/.ssh/known_hosts a link into a dotfiles tree; the backend expands the link into a shield of its own (credentialLinkShields) so the store cannot be written by naming where it points",
		Grant:   "farm/ssh/known_hosts",
		Write:   true,
		Verdict: InsideShield,
	},
	{
		Name:      "read of a symlinked credential entry's target",
		Why:       "the read counterpart is honored, not refused: the expansion shields the target at its own path, so naming that path literally is the same warned opt-in a read of ~/.ssh itself is",
		Grant:     "farm/ssh/known_hosts",
		Verdict:   Honored,
		OptInRead: true,
	},
	{
		Name:    "read strictly inside a symlinked credential subdirectory",
		Why:     "the expansion one level up: ~/.ssh/keys is a link to a real directory, and no opt-in lifts part of a shield, so a file inside the target is refused where the target itself would have been opt-in-able",
		Grant:   "farm/keys/id_ed25519",
		Verdict: InsideShield,
	},
	{
		Name:    "write into a symlinked credential subdirectory's target",
		Why:     "a write to that directory plants a key the host's ssh reads, and a write is never an opt-in",
		Grant:   "farm/keys/id_ed25519",
		Write:   true,
		Verdict: InsideShield,
	},
	{
		Name:           "read under a shield that resolved onto the home anchor",
		Why:            "a rule whose symlink lands on a home (or above one) is not shielded at all - shielding it would hide everything the policy granted rather than one store - so the run honors this and a site that refuses it refuses what the run allows",
		Grant:          "gnupg-target/notes",
		Verdict:        Honored,
		ShieldOntoHome: true,
	},
	{
		Name:    "write to a not-yet-existing path behind a shielded link",
		Why:     "a dotfiles tree checked out lazily leaves the shield's target dangling; resolving with EvalSymlinks answers differently there than resolving the way a write would actually land",
		Grant:   "farm/pending/id_rsa",
		Write:   true,
		Verdict: InsideShield,
	},
	{
		Name:      "read naming a shield's own deny-list path",
		Why:       "the control case: a read of ~/.ssh itself is the deliberate warned opt-in, and every site is supposed to converge on honoring it",
		Grant:     ".ssh",
		Verdict:   Honored,
		OptInRead: true,
	},
	{
		Name:    "read strictly inside a shield",
		Why:     "the other control: no opt-in lifts part of a shield, so naming a file inside one is refused everywhere",
		Grant:   ".ssh/config",
		Verdict: InsideShield,
	},
	{
		Name:    "write inside a DenyWrite shield",
		Why:     "~/.local/bin is readable but not writable and has no opt-in at all, so a write there is refused in its own sentence",
		Grant:   ".local/bin/mytool",
		Write:   true,
		Verdict: UnderWriteShield,
	},
	{
		Name:       "write containing a shield",
		Why:        "a write of the home itself would make ~/.ssh's own name replaceable; the clamp alone keeps it, because the run re-shields the interior",
		Grant:      ".",
		Write:      true,
		Verdict:    AboveShield,
		ClampKeeps: true,
	},
}

// Build populates dir as the home the case is judged against and returns it. One layout
// serves every case, so a site is tested against one rule set the way a run sees one - a
// shield the layout produces for one case is in play for all of them, which is the
// condition a real host presents. The single exception is the case's own ShieldOntoHome,
// which covers the whole layout and would otherwise mask every other divergence.
func Build(dir string, c Case) (string, error) {
	for _, d := range []string{
		".ssh",
		".local/bin",
		"farm/ssh",
		"farm/keys",
		"gnupg-target",
	} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return "", err
		}
	}
	for _, f := range []string{".ssh/config", "farm/ssh/known_hosts", "gnupg-target/notes"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			return "", err
		}
	}
	for _, l := range []struct{ from, to string }{
		// A credential FILE linked out of the store, and a credential SUBDIRECTORY linked
		// out of it. The expansion walks from the ~/.ssh directory rule, so both shapes
		// have to be present to tell an expansion that stops at files from one that does
		// not walk at all.
		{".ssh/known_hosts", "../farm/ssh/known_hosts"},
		{".ssh/keys", "../farm/keys"},
		// Dangling on purpose: the target is never created.
		{".ssh/pending", "../farm/pending"},
	} {
		if err := os.Symlink(l.to, filepath.Join(dir, l.from)); err != nil {
			return "", err
		}
	}
	if c.ShieldOntoHome {
		// ~/.gnupg is a DenyAll directory rule, so pointing it at the home makes a shield
		// that resolves onto the anchor: the shape the backend refuses to shield at all,
		// rather than swallow every grant the policy made.
		if err := os.Symlink(".", filepath.Join(dir, ".gnupg")); err != nil {
			return "", err
		}
	}
	return dir, nil
}
