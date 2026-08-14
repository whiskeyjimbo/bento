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
// The backend is authoritative, and the other two are measured against it, because the
// run is the thing that actually refuses. Where a site deliberately answers something
// else, the case says so in a field and gives the reason; a divergence with no field is a
// bug in that site, not a case to be edited.
//
// SCOPE, and it is narrower than "what a run does". Verdict models four of checkGrants'
// checks on the FULL tier. Three refusals a run raises have no member here and no case
// can express them: checkWriteNotRoot, which the shield checks are documented as relying
// on; checkWorkspaceShieldNotRedirected, whose position between two of the modelled
// checks is itself load-bearing; and checkWriteNotAboveWriteShield, which only the
// degraded tier raises. So agreement across the three sites is agreement about the four,
// and the gap runs in the UNDER-refusing direction: a shape this table calls Honored may
// still be hard-refused by a run.
package shieldcorpus

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/shield"
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
	// FoldedShield means a grant that CONTAINS a DenyAll shield whose directory folds
	// case, refused by grantrefusal.FoldedShield for either kind. It is the one verdict
	// no layout on disk produces (see Case.Folding).
	FoldedShield
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
	case FoldedShield:
		return "above a DenyAll shield on a case-folding mount"
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
	// Folding judges the case against a host whose mount folds case. It is the one host
	// property Build cannot stage - creating two spellings under a temp directory on ext4
	// makes two genuinely different files - so each site injects it through its own
	// filesystem seam, all of them off FoldedPath so they cannot fold differently.
	//
	// Per case rather than per run, for ShieldOntoHome's reason: a folding mount changes
	// the verdict of every grant in the layout, so leaving it on throughout would let one
	// divergence mask the rest.
	Folding bool
	// WorkspaceDerived marks a case whose refusal comes from a shield derived from the
	// checkout under the grant rather than from the deny list. The backend and the clamp
	// both derive them; gate.writeShieldProblem passes none to Contains, because the gate
	// judges a manifest without walking the grants, so it answers Honored. That divergence
	// is deliberate and one-directional - it misses a refusal rather than inventing one -
	// and this field is where it is stated instead of being a hole in the corpus.
	//
	// The clamp's derivation is the shallower of the two: it skips the recursive gitdir
	// scan the backend runs for submodules and linked worktrees, so a case anchored there
	// would diverge again.
	WorkspaceDerived bool
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
		Why:     "stow and chezmoi make ~/.ssh/known_hosts a link into a dotfiles tree; the run expands the link into a shield of its own so the store cannot be written by naming where it points",
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
		Name:    "write to an absent path inside a symlinked credential subdirectory",
		Why:     "the two cases above name a file that is there; this one does not, and the pair is what holds a site to answering the same way for both - an absent write admitted at preflight is created by the run and refused on the next pass with the artifact already on the host",
		Grant:   "farm/keys/id_absent",
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
		Name:    "write inside a DenyWrite shield reached by a folded spelling",
		Why:     "a DenyWrite shield is one byte-exact bind too, so where the mount folds, ~/.local/BIN reaches the same shim directory the shield binds at ~/.local/bin; there is no opt-in to weigh here, which is why this one is refused where the folding cases above a DenyAll shield are refused in their own sentence",
		Grant:   ".local/BIN/mytool",
		Write:   true,
		Folding: true,
		Verdict: UnderWriteShield,
	},
	{
		Name:             "write to the hooks dir of an enclosing checkout",
		Why:              "a write grant under a git checkout shields that checkout's .git/hooks, so a planted pre-commit cannot run on the host at the developer's next commit; the shield is derived from the checkout rather than listed, which only the backend can do",
		Grant:            "checkout/.git/hooks",
		Write:            true,
		Verdict:          UnderWriteShield,
		WorkspaceDerived: true,
	},
	{
		Name:       "write containing a shield",
		Why:        "a write of the home itself would make ~/.ssh's own name replaceable; the clamp alone keeps it, because the run re-shields the interior",
		Grant:      ".",
		Write:      true,
		Verdict:    AboveShield,
		ClampKeeps: true,
	},
	{
		Name:    "read containing a shield on a case-folding mount",
		Why:     "a read of the home is the ordinary honored case; where the mount folds, ~/.SSH reaches the store beside the one byte-exact bind that shields it, so the same grant has to be refused instead - and for a READ, where nothing needs to be writable for the content to leak",
		Grant:   ".",
		Folding: true,
		Verdict: FoldedShield,
	},
	{
		Name:    "write containing a shield on a case-folding mount",
		Why:     "the same grant as the write-above case, on a folding mount: the folding refusal is checked before the write-only verdicts and wins, because no narrower shield fixes it while re-shielding the interior would have covered the above-shield one",
		Grant:   ".",
		Write:   true,
		Folding: true,
		Verdict: FoldedShield,
	},
	{
		Name:      "read naming a shield's own path on a case-folding mount",
		Why:       "the opt-in survives the folding refusal: it binds the store's real content read-only, so a second spelling reaching that same content exposes nothing the author did not ask for - and refusing here would leave the folding sentence pointing its reader at a remedy it had just taken away",
		Grant:     ".ssh",
		Folding:   true,
		OptInRead: true,
		Verdict:   Honored,
	},
	{
		Name:    "write naming a shield's own path on a case-folding mount",
		Why:     "the collision between the two DenyAll checks: a grant AT a shield is both inside it and above it, so on a folding mount both refusals fit and the inside one has to win - it is the one whose read counterpart offers the opt-in, and answering with the folding sentence would tell the author no spelling can be granted when naming the shield is exactly what they did",
		Grant:   ".ssh",
		Write:   true,
		Folding: true,
		Verdict: InsideShield,
	},
}

// FS is the host the case is judged against: the real filesystem, with identity answered
// the way the case's mount answers it. The two sites that pass a shield.FS take it from
// here rather than building shield.Host() themselves; the backend, whose seams are its
// own, folds the same way off FoldedPath.
func FS(c Case) shield.FS {
	fs := shield.Host()
	if c.Folding {
		fs.SameFile = func(a, b string) bool { return sameFolded(a, b) }
	}
	return fs
}

// sameFolded is host identity on a folding mount: two spellings reach one file when they
// fold onto the same entry. A name with nothing behind it still reaches nothing, which is
// what keeps a shield that does not exist from being reported as folding.
func sameFolded(a, b string) bool {
	a, b = FoldedPath(a), FoldedPath(b)
	if a != b {
		return false
	}
	_, err := os.Lstat(a)
	return err == nil
}

// FoldedPath is the file a case-folding mount reaches for path: at each component, the
// entry beside it whose name matches ignoring case, or the component as written where
// there is none. It is the corpus's definition of the mount property Build cannot stage,
// so the three sites' seams - a shield.FS.SameFile for two of them, the backend's identity
// seam for the third - agree on which names collide without each emulating folding on its
// own.
//
// EVERY component is respelled, because that is what a whole-mount fold does. Folding only
// the last one modelled a host that does not exist and answered false for the pair a
// component-wise containment check asks about most - two spellings differing above the
// leaf - so a shield reachable one directory up read as unreachable and the corpus went
// green over it.
func FoldedPath(path string) string {
	out := "/"
	if !filepath.IsAbs(path) {
		out = ""
	}
	for _, name := range strings.Split(filepath.Clean(path), "/") {
		if name == "" {
			continue
		}
		out = filepath.Join(out, foldedName(out, name))
	}
	return out
}

// foldedName is the entry in dir that name reaches on a folding mount, or name itself.
func foldedName(dir, name string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return name
	}
	for _, e := range entries {
		if strings.EqualFold(e.Name(), name) {
			return e.Name()
		}
	}
	return name
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
		// A git checkout, for the shields the backend derives from one. Nothing else in
		// the layout sits under a .git, so it changes no other case's verdict.
		"checkout/.git/hooks",
		"farm/ssh",
		"farm/keys",
		"gnupg-target",
	} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return "", err
		}
	}
	// farm/keys/id_ed25519 exists and farm/keys/id_absent does not, both inside the same
	// symlinked credential subdirectory. A check whose answer turns on the file being there
	// - EvalSymlinks against the way a write really lands, an isDir gate, Lstat against
	// Stat - answers alike for the two only if it does not, and admitting an absent path
	// that the run then creates is how a hooks directory reached the host once already.
	for _, f := range []string{".ssh/config", "farm/ssh/known_hosts", "farm/keys/id_ed25519", "gnupg-target/notes"} {
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
