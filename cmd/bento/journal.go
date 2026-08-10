package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/trust"
)

// The approval journal is how bento can say what changed. The stamp in the manifest is a
// one-way sha256 over the policy, so on its own it can report drift and nothing more -
// which is what noStampDiff says everywhere a reader is sent back to re-review.
//
// The prior shape deliberately does not live in the manifest. Anything stored there is
// unauthenticated, and for a diff that is worse than no diff: a hostile manifest ships a
// prior-shape record equal to its current policy minus one innocuous line, and approve
// tells the reviewer "only `+ read: /tmp/cache` is new", inviting a skim of a policy
// nobody ever approved. A journal under the user's own state directory is written only by
// this host's approve, so a manifest arriving from elsewhere has no entry at all - which
// is a verdict in its own right rather than a forgeable diff.

// approvalRecord is what one approve stamped, as the reviewer saw it.
type approvalRecord struct {
	// Fingerprint is the policy fingerprint that was written to the manifest. Stored
	// rather than re-derived from Policy below: the point of comparing it against the
	// manifest's own stamp is to catch an entry that describes a different approval, and
	// re-deriving would answer that identically only for as long as Fingerprint never
	// changes.
	Fingerprint string `json:"fingerprint"`
	// Policy is the approved permissions rendered by manifest.Marshal - the same spelling
	// the reviewer read in the manifest, so the diff cannot drift from the file it
	// describes the way a second renderer would.
	Policy string `json:"policy"`
	// ManifestPath is the symlink-resolved location that was stamped, recorded for the
	// reader rather than for lookup: the file name is derived from it.
	ManifestPath string `json:"manifest_path"`
	// StampedAt is when the stamp went on, RFC3339 UTC.
	StampedAt string `json:"stamped_at"`
	// Reviewed records whether a human answered the prompt. A --yes stamp is legitimate
	// and deliberate, but "nobody read this" currently scrolls past in a CI log and is
	// gone; here a later re-approval can still say so.
	Reviewed bool `json:"reviewed"`
}

// journalVerdict is what the journal can say about a manifest's current stamp.
type journalVerdict int

const (
	// journalAbsent: no usable entry. Most often this stamp was written on another host,
	// which is the case approve's docstring warns about in general terms - but a wiped
	// state directory, a corrupt entry or an $XDG_STATE_HOME pointed somewhere else since
	// reach it too, so the wording says what bento knows (it holds no record) rather than
	// accusing a legitimate stamp of being foreign.
	journalAbsent journalVerdict = iota
	// journalUntrusted: a record is there but the journal is not private, so it is not
	// evidence of anything - somebody else could have written it. Distinct from absent
	// because the fix is different: this one names a directory to repair.
	journalUntrusted
	// journalForeign: an entry exists but records a different approval than the manifest
	// claims. Re-stamped elsewhere, or swapped underneath. Say so, do not diff.
	journalForeign
	// journalMatches: the entry describes the approval the manifest carries, so the diff
	// against it is trustworthy.
	journalMatches
)

// journalDir is where this host keeps its approval records. The state home is the seam:
// nothing here takes a filesystem interface, because $XDG_STATE_HOME already selects the
// directory and t.Setenv already controls that.
// A relative base is ignored rather than honored, which the spec asks for and which
// internal/denylist already assumes: homeLocations drops a relative XDG base on the grounds
// that a conforming tool falls back to the default, and it is that default it then shields.
// Honoring one here would put the journal at a cwd-relative path no shield covers, so bento
// would be the tool whose behavior its own deny-list got wrong.
func journalDir() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "bento", "approvals"), nil
}

// journalPath names the entry for a manifest. It is keyed on the symlink-resolved path,
// which is the location approve stamps, so a manifest kept in a dotfiles repo and linked
// into place has one entry rather than one per link. Hashed rather than escaped: the key
// is a whole absolute path, and encoding one into a file name invites the collisions a
// hash does not have.
func journalPath(realPath string) (string, error) {
	dir, err := journalDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(realPath))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json"), nil
}

// readApprovalRecord returns the journal's entry for a manifest and how far it can be
// trusted. No failure is returned as an error: the journal is a convenience over a stamp
// that is authoritative without it, so an unreadable, corrupt or untrustworthy entry must
// degrade to "bento cannot show you the diff" and never to a refusal to approve. A missing
// or unusable entry is absent, worded as bento holding no record - which is what a missing
// entry, a corrupt one and a state home pointed somewhere else have in common. A record
// bento cannot vouch for is untrusted, which says something different and is kept separate.
//
// The entry is read before it is judged, and deliberately: a missing file must reach the
// reader as "no record" rather than as an untrustworthy journal, and only its existence
// distinguishes the two.
func readApprovalRecord(realPath string, doc *manifest.Document) (approvalRecord, journalVerdict) {
	path, err := journalPath(realPath)
	if err != nil {
		return approvalRecord{}, journalAbsent
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return approvalRecord{}, journalAbsent
	}
	// Checked on the way in as well as on the way out, and on the entry as well as the
	// directory holding it. The record is worth reading only because this host's own approve
	// is the only thing that could have written it, and refusing to write into a shared
	// journal does not establish that - a state home somebody else can write is a place to
	// plant a baseline equal to the current policy minus one innocuous line, which is the
	// misleading diff this whole design exists to avoid. The stamp is no defense: it is
	// sitting in the manifest for the forger to copy.
	for _, p := range []string{filepath.Dir(path), path} {
		if err := requirePrivateJournal(p); err != nil {
			return approvalRecord{}, journalUntrusted
		}
	}
	var rec approvalRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return approvalRecord{}, journalAbsent
	}
	// An entry missing either half is not a record of anything: `{}` parses, and would
	// otherwise be reported as a disagreeing record, claiming a host approval that never
	// happened.
	if rec.Fingerprint == "" || rec.Policy == "" {
		return approvalRecord{}, journalAbsent
	}
	// The manifest's own stamp decides whether the entry is about this approval. An entry
	// recording a fingerprint the manifest does not carry describes some other stamp -
	// the file was re-approved somewhere else, or replaced - and diffing against it would
	// name lines that were never in the policy this manifest was approved for.
	if rec.Fingerprint != doc.Provenance.Approves {
		return rec, journalForeign
	}
	return rec, journalMatches
}

// writeApprovalRecord records what approve just stamped. It never fails the approval: the
// stamp is the product and the journal is a convenience over it, so a state home that
// cannot be written warns and the approval stands. This is a deliberate exception to
// letting errors propagate - the alternative is that an unwritable state directory stops
// people approving manifests, which trades a working gate for a diff.
func writeApprovalRecord(realPath string, p *policy.Policy, reviewed bool, warn io.Writer) {
	if err := storeApprovalRecord(realPath, p, reviewed); err != nil {
		fmt.Fprintf(warn, "[bento] the approval is stamped, but bento could not record what it approved (%v), so a later re-approval cannot show you what changed.\n", err)
	}
}

func storeApprovalRecord(realPath string, p *policy.Policy, reviewed bool) error {
	path, err := journalPath(realPath)
	if err != nil {
		return err
	}
	// Rendered with no provenance: the entry records the permissions that were approved,
	// and the stamp and timestamp that would appear here are the entry's own fields.
	shape, err := manifest.Marshal(p, manifest.Provenance{})
	if err != nil {
		return err
	}
	rec := approvalRecord{
		Fingerprint:  p.Fingerprint(),
		Policy:       string(shape),
		ManifestPath: realPath,
		StampedAt:    time.Now().UTC().Format(time.RFC3339),
		Reviewed:     reviewed,
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return writeJournalEntry(path, append(data, '\n'))
}

// writeJournalEntry writes one record through a temporary file in the journal directory
// and a rename, the same shape as writeManifestAtomically and for the same reason - down
// to flushing the content but not the directory: a half-written entry is what the next
// re-approval would read and diff against, while a rename lost to a power loss leaves the
// previous entry, which reads as journalForeign and declines to diff. It is its
// own writer rather than a parameter on that one, whose warning is about a manifest's mode.
//
// The directory is 0700 and the entry 0600. A journal anyone else can write is a forgeable
// diff, which is the whole reason the record is not kept in the manifest.
func writeJournalEntry(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := requirePrivateJournal(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".bento-approval-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once the rename below has moved it away
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// requirePrivateJournal refuses a journal directory, or an entry in one, that somebody else
// could have written.
// The entry is trusted on the grounds that only this host's own approve could have written
// it, so a second writer does not merely weaken that - it inverts it, and a forged entry
// is read as authoritative about what a human approved.
//
// It is asked of the directory and of the entry in it, on the way out and again on the way
// in: refusing to write into a shared journal establishes nothing about a record already
// sitting there.
//
// The mode bits are read raw rather than through the trust walk's shared-write rule, which
// exempts a sticky directory. That exemption is about who can replace an existing file, and the threat
// here is a record planted before bento wrote one - sticky does not stop anybody creating
// their own entry. For the same reason there is no group-membership lookup: bento creates
// this directory 0700, so a group-write bit on it was set deliberately by somebody.
//
// The leaf only, deliberately, where the manifest's own check walks the whole chain: a
// writable ancestor lets someone rename this directory away, but the worst that buys them
// is a journal bento reads as absent, which is already a verdict that declines to diff.
// The stamp is authoritative without any of this, and the cost of being wrong here is a
// lost diff rather than a wrong verdict.
func requirePrivateJournal(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read ownership of %s", path)
	}
	if shared := fi.Mode().Perm() & 0o022; shared != 0 {
		return fmt.Errorf("%s is group/world-writable (%#o), and an approval record someone else can write is a forgeable diff", path, fi.Mode().Perm())
	}
	acl, err := trust.ACLNamedWrite(path)
	if err != nil {
		return err
	}
	if acl {
		return fmt.Errorf("%s grants write to another user or group through an ACL, and an approval record someone else can write is a forgeable diff", path)
	}
	if st.Uid != uint32(os.Geteuid()) && st.Uid != 0 {
		return fmt.Errorf("%s is owned by another user, so bento cannot treat what is in it as its own record of what you approved", path)
	}
	return nil
}

// stampUnrecorded reports a current stamp this host has no record of writing. The stamp is
// unkeyed and travels with the file, so a current one proves the permissions have not
// drifted since SOMEBODY approved them, never that it was you - and the journal is the only
// thing that can tell the two apart.
//
// Only for a current stamp. An unstamped or stale one already gets its own line, which says
// more than this would.
func stampUnrecorded(realPath string, doc *manifest.Document) bool {
	if trust.CheckApproval(doc) != trust.ApprovalCurrent {
		return false
	}
	_, verdict := readApprovalRecord(realPath, doc)
	return verdict == journalAbsent
}

// unrecordedStamp is what both callers say about one, in one string for noStampDiff's
// reason: a reader who meets it at the terminal and again in CI must not have to work out
// whether they are the same claim.
//
// It is a note and never a refusal. A manifest approved on a workstation and run on a
// builder is an ordinary and legitimate shape, and so is a fresh container whose
// $XDG_STATE_HOME has never held anything; refusing either would break working setups over
// a fact the operator may already know. --strict does not fail on it either - it gates
// drift, and nothing here has drifted.
const unrecordedStamp = "this host holds no record of approving it, so its stamp is somebody's review rather than yours - `bento approve` after reading the permissions makes it yours"

// writeJournalDiff names the permissions that changed since the stamp, or says why it
// cannot. It replaces the half-answer writeReapprovalNotice gave on its own - "something
// changed, read the whole thing" - for the case where the journal makes the delta
// knowable, and keeps exactly that wording for the cases where it does not.
//
// None of the three refusals is decoration. No record usually means this stamp was written
// somewhere else, which is the thing a manifest-stored record could never tell anyone.
func writeJournalDiff(w io.Writer, rec approvalRecord, verdict journalVerdict, p *policy.Policy) {
	switch verdict {
	case journalAbsent:
		fmt.Fprintf(w, "\nbento holds no record of this stamp, so it cannot show what changed. Most often that\n")
		fmt.Fprintf(w, "means the stamp was written on another host, and a stamp that came with the manifest\n")
		fmt.Fprintf(w, "is its author's review rather than yours. It also happens when the record was cleared\n")
		fmt.Fprintf(w, "or was written under a different $XDG_STATE_HOME. Either way, read the whole policy\n")
		fmt.Fprintf(w, "above as if it were unapproved.\n")
		return
	case journalUntrusted:
		fmt.Fprintf(w, "\nbento has a record of an approval for this manifest but will not compare against it:\n")
		fmt.Fprintf(w, "the journal under $XDG_STATE_HOME/bento/approvals/ is not yours alone - somebody else\n")
		fmt.Fprintf(w, "can write it, or it belongs to another user - so a record there is no evidence of what\n")
		fmt.Fprintf(w, "you approved. Read the whole policy above as if it were unapproved. Recording this\n")
		fmt.Fprintf(w, "approval replaces the entry with one only you can write; where it is the directory\n")
		fmt.Fprintf(w, "that is shared, that write is refused and reported on stderr instead.\n")
		return
	case journalForeign:
		fmt.Fprintf(w, "\nbento's record for this manifest describes a different approval than the stamp it now\n")
		fmt.Fprintf(w, "carries - it was re-approved somewhere else, or the file was replaced. The record is\n")
		fmt.Fprintf(w, "not a baseline for this stamp, so there is no diff to show: read the whole policy\n")
		fmt.Fprintf(w, "above as if it were unapproved.\n")
		return
	case journalMatches:
		// The only verdict with a baseline to diff against, which is the rest of this
		// function.
	}

	shape, err := manifest.Marshal(p, manifest.Provenance{})
	if err != nil {
		// The one place the reader is waiting for the answer, so it says there isn't one
		// rather than printing nothing after promising a diff two lines up.
		fmt.Fprintf(w, "\nbento has a record of the last approval but could not render the current\n")
		fmt.Fprintf(w, "permissions to compare against it (%v) - read the whole policy above.\n", err)
		return
	}
	changes := diffLines(rec.Policy, string(shape))
	fmt.Fprintf(w, "\nLast approved %s", rec.StampedAt)
	if !rec.Reviewed {
		// The signal is otherwise lost: --yes is how CI stamps, and the one line saying
		// nobody read it went into a log weeks ago. A reviewer re-approving now is the last
		// reader who can act on it.
		fmt.Fprintf(w, ", non-interactively - nobody read it")
	}
	fmt.Fprintf(w, ".\n")
	if len(changes) == 0 {
		// Every field Fingerprint covers is one Marshal renders, so a stale stamp and an
		// identical rendering cannot both hold today. Saying so is still better than the
		// alternative if that ever stops being true: the header below would announce a list
		// of changes and then print none, which reads as "nothing changed" on a manifest
		// whose stamp says otherwise.
		fmt.Fprintf(w, "The permissions differ from what was approved, but not in any line bento renders,\n")
		fmt.Fprintf(w, "which should not happen - read the whole policy above and treat it as unapproved.\n")
		return
	}
	fmt.Fprintf(w, "These permissions changed since then:\n")
	for _, c := range changes {
		// The line keeps the indentation manifest.Marshal gave it: a network rule's `port`
		// sits under its `host`, and flattening that leaves an orphan line naming a port
		// with nothing to say which destination it belongs to.
		fmt.Fprintf(w, "  %c %s\n", c.sign, c.text)
	}
	fmt.Fprintf(w, "The lines above are the delta, not a substitute for the policy: a grant can widen\n")
	fmt.Fprintf(w, "without its line changing shape. Read them first, then the whole policy.\n")
}

// diffLine is one changed line of a policy rendering, '+' for one the current policy has
// and the approved one did not, '-' for the reverse.
type diffLine struct {
	sign rune
	text string
}

// diffLines reports the lines that differ between two renderings of a policy, in the order
// they appear, matching common lines so a reordered list is not reported as a wholesale
// rewrite. Both sides come from manifest.Marshal, so the lines are the manifest's own
// spelling and a removal is namable exactly as an addition is.
//
// Interleaved rather than grouped into all-removals-then-all-additions: a changed grant is
// one line gone and one line arrived, and separating them puts the two halves of a single
// edit at opposite ends of the list.
func diffLines(before, after string) []diffLine {
	old := strings.Split(strings.TrimRight(before, "\n"), "\n")
	cur := strings.Split(strings.TrimRight(after, "\n"), "\n")

	// Longest common subsequence over lines. Policies are tens of lines, so the quadratic
	// table is the right trade against pulling in a diff library for this one caller.
	lcs := make([][]int, len(old)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(cur)+1)
	}
	for i := len(old) - 1; i >= 0; i-- {
		for j := len(cur) - 1; j >= 0; j-- {
			if old[i] == cur[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}
			lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
		}
	}
	var out []diffLine
	i, j := 0, 0
	for i < len(old) && j < len(cur) {
		switch {
		case old[i] == cur[j]:
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, diffLine{'-', old[i]})
			i++
		default:
			out = append(out, diffLine{'+', cur[j]})
			j++
		}
	}
	for ; i < len(old); i++ {
		out = append(out, diffLine{'-', old[i]})
	}
	for ; j < len(cur); j++ {
		out = append(out, diffLine{'+', cur[j]})
	}
	return out
}
