package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/trust"
)

func newApproveCmd() *cobra.Command {
	var assumeYes bool

	cmd := &cobra.Command{
		Use:   "approve <manifest>",
		Short: "Review a manifest's permissions and stamp them as approved",
		Long: "approve records that a human has reviewed the manifest's current permissions.\n\n" +
			"It prints the permissions it is about to stamp, calls out the entries that\n" +
			"deserve a second look, and asks before writing. --yes skips the question for\n" +
			"scripts and CI. A stdin that is not a terminal is refused rather than answered:\n" +
			"a stamp nobody read should be something a caller asked for, not something the\n" +
			"absence of a terminal decided.\n\n" +
			"It writes a provenance fingerprint of the policy into the manifest. `validate`\n" +
			"then reports the manifest as approved until the permissions change; after a\n" +
			"deliberate edit, run approve again to re-stamp it. The fingerprint covers the\n" +
			"permissions, not the script's contents - it attests the policy, not the code.\n\n" +
			"It also records the permissions it stamped under $XDG_STATE_HOME/bento/approvals/,\n" +
			"so re-approving a manifest whose permissions drifted can name the lines that\n" +
			"changed. That record is this host's own: a manifest approved elsewhere has none,\n" +
			"and approve says so rather than showing a diff it cannot vouch for. Losing the\n" +
			"record costs the diff and nothing else - the stamp in the manifest is what run\n" +
			"and validate read.\n\n" +
			"Approval is local drift detection, not a signature: the stamp is unkeyed and\n" +
			"lives in the manifest, so it attests only that the permissions match what was\n" +
			"stamped, not who stamped them. Review a manifest you got from elsewhere before\n" +
			"approving it - a shipped stamp is its author's, not your review.\n\n" +
			"The manifest is rewritten in canonical form (it is machine-owned); review the\n" +
			"diff as you would any change.",
		Args: exactArgs(1, "a manifest path"),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			// approve reports the location facts itself below, as a refusal for what it
			// cannot fix and as the clamp warning for what it can.
			doc, mt, err := loadDocument(path)
			if err != nil {
				return err
			}
			// The trust is reported below rather than by loadDocument, so a manifest
			// approve is about to clamp is not also warned about as if it were staying
			// that way. What approve cannot fix refuses here; the rest it acts on.
			if err := requireApprovableLocation(path, mt); err != nil {
				return err
			}
			warnUntrusted(cmd.ErrOrStderr(), mt.LocationFlaws(uint32(os.Geteuid())))

			// A current stamp is not the whole claim: the fingerprint covers the policy, so
			// a chmod after an approve leaves it reading as current over permissions nobody
			// attested. The rewrite is what clamps those and says so, and it is skipped here,
			// so a manifest still needing the clamp goes through it rather than being
			// reported as already approved for a mode approve never vouched for.
			approval := trust.CheckApproval(doc)
			resolved := resolvedGrants(doc.Policy, path)
			// Before the already-approved shortcut, not after: a manifest stamped by an
			// earlier bento - or by this one on a host whose shields anchor elsewhere -
			// otherwise reports as approved for permissions run refuses outright, which is
			// the disagreement between the gate and the enforcement this check exists to end.
			if err := requireHonorableGrants(os.Stdout, resolved); err != nil {
				return err
			}
			// The stamp is an unkeyed sha256 that travels inside the manifest, so on its own
			// it is satisfied identically by one this host wrote and one that arrived already
			// stamped from anywhere. The journal is what tells those apart - it is written
			// only by this host's approve - so the shortcut is for a re-approval, and a stamp
			// nobody here recorded goes through the whole review rather than exiting green.
			rec, journal := readApprovalRecord(mt.RealPath, doc)
			if approval == trust.ApprovalCurrent && journal == journalMatches && mt.SharedWrite() == 0 {
				fmt.Fprintf(os.Stdout, "%s is already approved for its current permissions.\n", path)
				return nil
			}

			// The judgement approve exists to record lives in reading the policy, and
			// nothing here showed it: a numbered four-step list whose fourth command
			// printed one line made typing it the path of least resistance. The summary
			// is validate's own, so there is one rendering of a policy rather than two
			// that can drift.
			writePolicySummary(os.Stdout, path, doc.Policy, resolved, nil, false)
			writeApprovalCallouts(os.Stdout, mt.RealPath, leafNamePath(path), doc.Policy, resolved, doc.Provenance.BlockedHosts, false)
			// After the callouts, not before: the notice sends the reader back over everything
			// above it, and the callouts are the part of the report a drift most needs reread.
			writeReapprovalNotice(os.Stdout, doc.Policy, approval, rec, journal)
			if err := confirmApproval(cmd.Context(), os.Stdout, assumeYes); err != nil {
				return err
			}

			doc.Provenance = manifest.Provenance{
				GeneratedBy: "bento approve",
				GeneratedAt: time.Now().UTC().Format(time.RFC3339),
				Approves:    doc.Policy.Fingerprint(),
				// Carried, not re-derived: approve observes nothing, and dropping the record
				// here would clear the callout for every later re-approval of the same file.
				BlockedHosts: doc.Provenance.BlockedHosts,
			}
			out, err := manifest.Marshal(doc.Policy, doc.Provenance)
			if err != nil {
				return err
			}
			if err := writeManifestAtomically(mt, out, os.Stderr); err != nil {
				return err
			}
			// After the manifest, and only once it landed: the journal describes an approval
			// that is on disk, and recording one for a stamp that failed to write would give
			// the next re-approval a baseline no manifest ever carried.
			recorded := writeApprovalRecord(mt.RealPath, doc.Policy, !assumeYes, os.Stderr)
			fmt.Fprintf(os.Stdout, "approved %s for its current permissions.\n", path)
			if !recorded {
				// The stamp landed, so the line above is true and stays; the code is what a
				// script reads, and an approval whose record was lost is not a clean one.
				// Bare, because the warning already said what happened - a second rendering
				// of it through main would only repeat it.
				return &exitError{code: bentoFailed}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&assumeYes, "yes", false, "stamp without asking, for scripts and CI")
	return cmd
}

// writeReapprovalNotice tells the reviewer why they are being asked to read a policy that
// already carries a stamp. Two cases reach here. The permissions drifted, and re-approving
// prints the same block as a first approval, so the added grant that sent the reader here -
// `run` refuses a drifted manifest and points at this command - has to be found by memory.
// Or the stamp is current but is not one this host recorded, which is the case the journal
// exists to name: the shortcut above already declined it, and without a line here the
// prompt would arrive with nothing saying why.
//
// The stamp itself cannot say which lines are new - it is a sha256 of the policy, not a
// copy of it - so the delta comes from the approval journal, which is this host's own
// record of what its previous approve stamped. Where the journal has a trustworthy entry
// the notice names the changed lines; where it does not it says which of the two reasons
// applies, both of which are worth knowing on their own. See journal.go.
func writeReapprovalNotice(w io.Writer, p *policy.Policy, approval trust.ApprovalState, rec approvalRecord, verdict journalVerdict) {
	switch {
	case approval == trust.ApprovalStale:
		fmt.Fprintf(w, "\nThis manifest was approved before and its permissions have changed since.\n")
	case approval == trust.ApprovalCurrent && verdict != journalMatches:
		// Worded as what bento cannot confirm rather than as a stamp it never wrote: an
		// untrusted journal can hold this host's own record in a directory somebody widened
		// since, and the paragraph below says so in the next breath.
		fmt.Fprintf(w, "\nThis manifest carries a stamp for the permissions above, and bento cannot confirm it\nwas stamped here.\n")
	default:
		return
	}
	writeJournalDiff(w, rec, verdict, p)
}

// requireHonorableGrants refuses to stamp a policy holding a grant no run will honor - the
// same set validate reports as refusals, since a stamp and a green gate over the same
// manifest have to mean the same thing. The callouts above are for the grants that are a
// judgement call; this is not one - the run refuses these before the script's first
// instruction, so a stamp over them records a review of permissions that do not exist, and
// the stamp is what the CI gate then trusts.
//
// It refuses rather than asks: --yes is the CI shape, and a question there is answered by
// the flag rather than by anyone.
//
// A host that could not resolve the grants, or could not anchor the shields, stamps as
// before. The verdict approve exists to give is a property of the manifest and must not
// start depending on where it is checked. It says so in words instead, and from here
// rather than from the callouts: the stamp is durable and portable, and the already-
// approved shortcut returns before the callouts are ever written - so a re-approval on an
// unanchored host used to exit green with the note nowhere.
//
// An empty set is not a promise that the run honors every grant, and this gate must not be
// read as closed: the run also refuses on a credential alias, which gate.Refusals does not
// answer and cannot, since that refusal turns on `--accept-alias` - a flag of the run,
// which no stamp can attest. So a manifest can stamp here and still be refused at the
// first step by the host it is stamped on. Nothing to do about it from here; what would
// make it worse is a check added to the run's set and not to gate's, which is the drift
// this function exists to catch.
func requireHonorableGrants(w io.Writer, resolved *policy.Policy) error {
	if resolved == nil {
		return nil
	}
	// gate.Refusals answers four of its six classes off the manifest and the filesystem
	// alone, so an unanchored host returns a set that is quietly short of the two shielded
	// ones rather than an empty one - a refusal list that reads as complete. The note is
	// the only thing that tells them apart, and it is said here because this runs on every
	// path through approve.
	if _, err := commandShieldSet(); err != nil {
		fmt.Fprintf(w, "note: bento could not work out where the shields anchor on this host (%v), so the grants were not checked against them - and a run here is refused for the same reason.\n", err)
	}
	problems := gate.Refusals(resolved)
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("not approved: the policy holds a grant run refuses before the script starts - approving it would stamp a permission that does not exist:\n  %s", strings.Join(problems, "\n  "))
}

// writeApprovalCallouts names the entries in a policy that deserve a second look before
// the stamp goes on. Profiling proposes what one run did rather than what a script should
// be allowed to do, so every one of these is something it will hand over unprompted -
// approving the probe example's own proposal grants `exec: all` and a write over the
// directory holding the manifest being approved.
//
// None of them is a refusal: each is a legitimate thing to approve, and a manifest with
// no callouts prints nothing here. The ask is only that approving one be a decision.
//
// blockedHosts is the manifest's own record of the destinations the profiling run's
// egress guard refused (provenance, not permission - see manifest.Provenance). Without
// it the proposal lists a host bento itself would not let the target reach exactly as it
// lists one that worked, and the reader stamps the difference blind.
//
// The manifest is named twice because a grant can reach it under either name and either
// one hands the script the policy that governs it. realPath is the symlink-resolved
// location the stamp is written to - a grant covering it rewrites the file. namedPath is
// the manifest in the namespace the grants themselves live in, since resolvedGrants
// anchors every relative grant to the directory of the name the user typed - a grant
// covering it can unlink the link and drop a self-stamped manifest at that name. For a
// manifest kept in a dotfiles repo and linked into a project the two differ, and
// CoversResolved is a lexical prefix test, so asking with only one of them answers "no"
// exactly where it matters.
// notedBeside says the caller already printed the notes that belong next to a single
// grant - the breadth, shielded-read and blocked-host ones - beside the grant they are
// about, which is what validate's summary does and approve's does not. Those are skipped
// here rather than said twice on one screen; the judgements left are the ones no single
// line of the summary is the place for.
func writeApprovalCallouts(w io.Writer, realPath, namedPath string, p, resolved *policy.Policy, blockedHosts []string, notedBeside bool) {
	var notes []string
	if !notedBeside {
		for _, r := range p.Network {
			// Asked of the rule rather than of the recorded destination's text, so a rule that
			// covers the refusal without being spelled as it - a `.internal` suffix, a `*` - is
			// called out too. Those are the rules where the warning matters most.
			if !grantsAnyBlockedHost(r, blockedHosts) {
				continue
			}
			// Quoted for the same reason profile quotes a host it declines to propose: the
			// name came from the profiled target, and this is a line printed to a terminal.
			notes = append(notes, fmt.Sprintf("network: %q port %q - the profiling run reached a destination this rule covers and bento refused it, because the name resolved to an address a sandbox must not reach (loopback, private space, or cloud metadata). An enforced run refuses it the same way, whatever you approve here.", r.Host, r.Port))
		}
	}
	// Raised as one note over the whole group: individually each is an ordinary grant,
	// and what the reader needs is that the set of them is partly the script's choosing.
	// See tmpGrants.
	// Asked of the resolved policy: the test is prefix-based, so a grant still spelled
	// relative to the manifest would answer no on a manifest that reaches /tmp. Where
	// resolution failed, the note below already tells the reader nothing was checked.
	if g := tmpGrants(resolved); len(g) > 0 {
		notes = append(notes, fmt.Sprintf("%d grant(s) under /tmp (%s) - a path there reaches a profiled proposal by existing on this host, so a script that opens guessed names under /tmp can put them in front of you. Keep only the ones it needs.", len(g), strings.Join(g, ", ")))
	}
	// Raised for any interpreter_args at all rather than for a list of dangerous
	// spellings: "-c" and "-m" make the interpreter read a program from this list and
	// ignore the entrypoint entirely, but every interpreter spells that differently and
	// a blocklist would say the ones it does not name are safe. The field reads as
	// innocuous next to the paths and hosts around it, and it decides what runs.
	if len(p.InterpreterArgs) > 0 {
		notes = append(notes, fmt.Sprintf("interpreter_args: %s - these go to %q before the entrypoint, so they change how it is read and some of them (-c, -m) make the interpreter run a program from this list instead of the entrypoint. Read them as code, not as configuration.", quotedList(p.InterpreterArgs), p.Interpreter))
	}
	if p.Exec == policy.ExecAll {
		notes = append(notes, "exec: all - the script may spawn any subprocess, including ones the profiling run never showed.")
	}
	// Resolution fails only where a grant carries a ~ this host cannot expand, which is
	// the spelling most likely to be a whole home - so the review that exists to catch
	// that must say it could not rather than print a clean-looking block. validate can
	// degrade quietly here because it reports; this is the gate.
	if resolved == nil {
		notes = append(notes, "the grants could not be resolved on this host (an unusable $HOME), so nothing below was checked against what they reach - read them yourself.")
	} else {
		// Taken from the resolved policy rather than re-derived: manifest.Resolve expands a
		// leading ~ against $HOME and anchors the rest to the manifest's directory, and a
		// second implementation of that would answer differently for `entrypoint: ~/bin/x`
		// exactly where CoversResolved's lexical test then reports no coverage.
		// Asked under both its names for the same reason the manifest is: a script kept
		// elsewhere and linked into the project is covered by a grant over that directory
		// under the name the link carries, and replacing the link is how it rewrites its
		// own code.
		entrypoint, linkedEntrypoint := pathresolve.Existing(resolved.Entrypoint), leafNamePath(resolved.Entrypoint)
		for _, g := range resolved.Write {
			g = pathresolve.Existing(g)
			// Two independent tests rather than a switch: one grant over a directory holding
			// both the manifest and the script covers each of them, and reporting only the
			// first would drop a callout that is true.
			if policy.CoversResolved(g, realPath) || policy.CoversResolved(g, namedPath) {
				notes = append(notes, fmt.Sprintf("write: %q covers the manifest itself, so the script can rewrite the policy that governs it - and the stamp you are about to write.", g))
			}
			if policy.CoversResolved(g, entrypoint) || policy.CoversResolved(g, linkedEntrypoint) {
				notes = append(notes, fmt.Sprintf("write: %q covers the entrypoint, so the script can rewrite its own code after this approval.", g))
			}
		}
		// The one callout here that is not merely broad: bento shields these on every
		// run, and a grant naming one exactly is the only way to lift that shield. The
		// run-time warning comes after the target has already printed whatever it read,
		// so this prompt is where the exposure can still be declined.
		// The error arm is requireHonorableGrants', which runs on every path through approve
		// including the already-approved shortcut that returns before these callouts. Said
		// twice it would be a note a reader learns to skim.
		if !notedBeside {
			shieldGrants, _ := explicitShieldGrants(resolved.Read)
			for _, g := range shieldGrants {
				notes = append(notes, fmt.Sprintf("read: %q is a %s bento shields on every run, and this grant names it exactly - which lifts the shield and lets the script %s.", g.Path, g.Holds.Noun(), g.Holds.Exposure()))
			}
		}
		if !notedBeside {
			for kind, grants := range map[string][]string{"read": resolved.Read, "write": resolved.Write} {
				for _, g := range grants {
					if isBroadDir(g) {
						notes = append(notes, broadGrantNote(kind, g))
					}
				}
			}
		}
	}
	// Sorted because the map walk above is not, and an approval prompt that reorders
	// itself between runs of the same manifest cannot be read as a diff.
	slices.Sort(notes)
	if len(notes) == 0 {
		return
	}
	if notedBeside {
		fmt.Fprintf(w, "\nWorth a second look:\n")
	} else {
		fmt.Fprintf(w, "\nWorth a second look before stamping:\n")
	}
	for _, n := range notes {
		fmt.Fprintf(w, "  - %s\n", n)
	}
}

// leafNamePath is a file under the name that reaches it rather than the one it resolves
// to: the directory is resolved the way the grants around it are, and the last component
// is left alone. A grant covering that directory covers this name, and whoever holds it
// can unlink the link and put a file of their own there - which is the same power over the
// manifest or the entrypoint as rewriting the file it points at, and is invisible to a
// comparison against the resolved location alone.
func leafNamePath(path string) string {
	return filepath.Join(pathresolve.Existing(filepath.Dir(path)), filepath.Base(path))
}

// confirmApproval asks before the stamp goes on. A stdin that is not a terminal is
// refused rather than answered: an approval is the record that a human read the
// permissions above, and a pipeline reaching here without --yes would stamp whatever the
// manifest currently holds, with the disclosure landing in a CI log instead of in front
// of anyone. --yes still stamps without asking, which is what a script should say, and
// makes the unreviewed stamp deliberate rather than a side effect of where stdin points.
// examples/supervise gates its own prompts on stdin the same way.
func confirmApproval(ctx context.Context, w io.Writer, assumeYes bool) error {
	if assumeYes {
		return nil
	}
	if !isTerminal(os.Stdin) {
		return fmt.Errorf("not approved: approving is a human reading the permissions above, and stdin is not a terminal, so there is nothing to read an answer from. " +
			"Attach a terminal, or pass --yes to stamp them unreviewed")
	}
	// openTTY only once the gates above have passed: it opens /dev/tty, which a --yes run
	// has no reason to hold.
	tty, closeTTY := openTTY()
	defer closeTTY()
	return readApprovalAnswer(ctx, ttyLines(tty), w)
}

// readApprovalAnswer prompts and reads the verdict, taking the line channel as
// confirmNetworkExfil does - in the same argument order - rather than opening the
// terminal itself, which is what lets the answer handling be exercised without one.
// Anything but an explicit yes declines:
// the question is whether a human affirmed these permissions, so a typo, an empty line and a
// closed stream must all mean no.
func readApprovalAnswer(ctx context.Context, lines <-chan string, w io.Writer) error {
	line, ok := askLine(ctx, lines, w, "\nApprove these permissions? [y/N] > ")
	if !ok && ctx.Err() != nil {
		// Nothing is stamped either way, but a Ctrl-C answered with "edit the manifest"
		// advises a reviewer who did not decline anything.
		return fmt.Errorf("not approved: %w", ctx.Err())
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	default:
		return fmt.Errorf("not approved: edit the manifest, or re-run approve once the permissions above are what you want")
	}
}

// requireApprovableLocation refuses to stamp a manifest whose location leaves someone
// else able to change it. The stamp is unkeyed drift detection, so its whole value is
// that the permissions cannot move without it going stale - which a second writer,
// whether on the manifest or on the directory it can be renamed within, gives away for
// free. Only what approve cannot fix and what is unambiguously shared is fatal; see
// trust.Manifest.Flaws for which is which.
func requireApprovableLocation(path string, mt trust.Manifest) error {
	for _, flaw := range mt.Flaws(uint32(os.Geteuid())) {
		if flaw.Fatal {
			if flaw.Hint != "" {
				return fmt.Errorf("refusing to approve %s: %s; %s", path, flaw.Reason, flaw.Hint)
			}
			return fmt.Errorf("refusing to approve %s: %s", path, flaw.Reason)
		}
	}
	return nil
}

// writeManifestAtomically replaces the manifest through a temporary file in its own
// directory, flushed, and a rename, so an interrupted write cannot leave a truncated
// manifest where a complete one was - os.WriteFile opens the real file for truncation, and
// the half of a manifest it is mid-way through writing is what every other command would
// read. Both approve and profile write through here.
//
// The directory is not flushed after the rename, unlike examples/supervise's store: a
// rename that does not survive a power loss leaves the previous manifest in place, whose
// stamp is stale or absent, and the cost is a re-run of approve. That store fixes the same
// hazard because stale content there silently reverts a deny; here every outcome is one
// approve refuses and asks about again.
//
// It writes at the location the trust was gathered against, which is the symlink-resolved
// one: a manifest kept in a dotfiles repo and linked into place is ordinary here, and
// renaming onto the link itself would replace the link with a regular file and silently
// detach it from its source. Taking the location from the trust rather than resolving the
// name again is what keeps the write and the check talking about the same file. The rename
// still acts on a name, so someone who can write the resolved directory can still choose
// what ends up there. That is a property of the caller, not of this function: approve
// refuses such a location outright, while profile only warns and writes anyway - which is
// sound there because the draft it writes carries no approval stamp, so approve refuses it
// later on the same grounds.
//
// The mode carries forward from the file being replaced (0600 for one that does not exist
// yet), minus group and world write: approval is drift detection whose whole value is that
// the permissions cannot change without the stamp going stale, and a manifest anyone can
// edit gives that away.
func writeManifestAtomically(mt trust.Manifest, data []byte, warn io.Writer) error {
	target := mt.RealPath
	mode := mt.Mode()
	if shared := mode & 0o022; shared != 0 {
		mode &^= 0o022
		fmt.Fprintf(warn, "[bento] %s was group/world-writable (%#o); writing it back as %#o - a manifest others can edit makes its approval stamp meaningless.\n", mt.Path(), mt.Mode(), mode)
	}

	dir := filepath.Dir(target)
	f, err := os.CreateTemp(dir, ".bento-approve-*")
	if err != nil {
		return fmt.Errorf("bento rewrites the manifest through a temporary file in %s, so it needs write and search permission on that directory, not only on the manifest: %w", dir, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once the rename below has moved it away
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
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
	return os.Rename(tmp, target)
}
