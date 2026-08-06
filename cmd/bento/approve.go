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

	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
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
			doc, trust, err := loadDocument(path)
			if err != nil {
				return err
			}
			// The trust is reported below rather than by loadDocument, so a manifest
			// approve is about to clamp is not also warned about as if it were staying
			// that way. What approve cannot fix refuses here; the rest it acts on.
			if err := requireApprovableLocation(path, trust); err != nil {
				return err
			}
			warnUntrusted(cmd.ErrOrStderr(), trust.locationFlaws(uint32(os.Geteuid())))

			// A current stamp is not the whole claim: the fingerprint covers the policy, so
			// a chmod after an approve leaves it reading as current over permissions nobody
			// attested. The rewrite is what clamps those and says so, and it is skipped here,
			// so a manifest still needing the clamp goes through it rather than being
			// reported as already approved for a mode approve never vouched for.
			approval := checkApproval(doc)
			resolved := resolvedGrants(doc.Policy, path)
			// Before the already-approved shortcut, not after: a manifest stamped by an
			// earlier bento - or by this one on a host whose shields anchor elsewhere -
			// otherwise reports as approved for permissions run refuses outright, which is
			// the disagreement between the gate and the enforcement this check exists to end.
			if err := requireHonorableGrants(resolved); err != nil {
				return err
			}
			if approval == approvalCurrent && trust.file.sharedWrite() == 0 {
				fmt.Fprintf(os.Stdout, "%s is already approved for its current permissions.\n", path)
				return nil
			}

			// The judgement approve exists to record lives in reading the policy, and
			// nothing here showed it: a numbered four-step list whose fourth command
			// printed one line made typing it the path of least resistance. The summary
			// is validate's own, so there is one rendering of a policy rather than two
			// that can drift.
			writePolicySummary(os.Stdout, path, doc.Policy, resolved, nil)
			writeApprovalCallouts(os.Stdout, trust.realPath, doc.Policy, resolved, doc.Provenance.BlockedHosts)
			// After the callouts, not before: the notice sends the reader back over everything
			// above it, and the callouts are the part of the report a drift most needs reread.
			writeReapprovalNotice(os.Stdout, trust.realPath, doc, approval)
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
			if err := writeManifestAtomically(trust, out, os.Stderr); err != nil {
				return err
			}
			// After the manifest, and only once it landed: the journal describes an approval
			// that is on disk, and recording one for a stamp that failed to write would give
			// the next re-approval a baseline no manifest ever carried.
			writeApprovalRecord(trust.realPath, doc.Policy, !assumeYes, os.Stderr)
			fmt.Fprintf(os.Stdout, "approved %s for its current permissions.\n", path)
			return nil
		},
	}

	cmd.Flags().BoolVar(&assumeYes, "yes", false, "stamp without asking, for scripts and CI")
	return cmd
}

// writeReapprovalNotice tells the reviewer that the policy above is not the one that was
// stamped. Re-approving a manifest whose permissions drifted prints the same block as a
// first approval, so the added grant that sent the reader here - `run` refuses a drifted
// manifest and points at this command - has to be found by memory.
//
// The stamp itself cannot say which lines are new - it is a sha256 of the policy, not a
// copy of it - so the delta comes from the approval journal, which is this host's own
// record of what its previous approve stamped. Where the journal has a trustworthy entry
// the notice names the changed lines; where it does not it says which of the two reasons
// applies, both of which are worth knowing on their own. See journal.go.
func writeReapprovalNotice(w io.Writer, realPath string, doc *manifest.Document, approval approvalState) {
	if approval != approvalStale {
		return
	}
	fmt.Fprintf(w, "\nThis manifest was approved before and its permissions have changed since.\n")
	rec, verdict := readApprovalRecord(realPath, doc)
	writeJournalDiff(w, rec, verdict, doc.Policy)
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
// start depending on where it is checked - writeApprovalCallouts already says in words
// that nothing was checked there.
func requireHonorableGrants(resolved *policy.Policy) error {
	if resolved == nil {
		return nil
	}
	// A host that could not anchor the shields yields no problems rather than an error,
	// which is the degradation described above.
	problems := grantRefusals(resolved)
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
// manifestPath is the symlink-resolved location the stamp will be written to, and the
// grants are resolved the same way before they are compared - CoversResolved is lexical,
// so an unresolved path is the one input that makes it answer "no" exactly where it
// matters.
func writeApprovalCallouts(w io.Writer, manifestPath string, p, resolved *policy.Policy, blockedHosts []string) {
	var notes []string
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
		entrypoint := pathresolve.Existing(resolved.Entrypoint)
		for _, g := range resolved.Write {
			g = pathresolve.Existing(g)
			switch {
			case policy.CoversResolved(g, manifestPath):
				notes = append(notes, fmt.Sprintf("write: %q covers the manifest itself, so the script can rewrite the policy that governs it - and the stamp you are about to write.", g))
			case policy.CoversResolved(g, entrypoint):
				notes = append(notes, fmt.Sprintf("write: %q covers the entrypoint, so the script can rewrite its own code after this approval.", g))
			}
		}
		// The one callout here that is not merely broad: bento shields these on every
		// run, and a grant naming one exactly is the only way to lift that shield. The
		// run-time warning comes after the target has already printed whatever it read,
		// so this prompt is where the exposure can still be declined.
		shieldGrants, err := explicitShieldGrants(resolved.Read)
		if err != nil {
			notes = append(notes, fmt.Sprintf("bento could not work out where the shields anchor on this host (%v), so the grants above were not checked against them - and a run here is refused for the same reason.", err))
		}
		for _, g := range shieldGrants {
			notes = append(notes, fmt.Sprintf("read: %q is a %s bento shields on every run, and this grant names it exactly - which lifts the shield and lets the script %s.", g.Path, g.Holds.Noun(), g.Holds.Exposure()))
		}
		for kind, grants := range map[string][]string{"read": resolved.Read, "write": resolved.Write} {
			for _, g := range grants {
				if isBroadDir(g) {
					notes = append(notes, fmt.Sprintf("%s: %q is a whole home or top-level directory, far more than a script needs.", kind, g))
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
	fmt.Fprintf(w, "\nWorth a second look before stamping:\n")
	for _, n := range notes {
		fmt.Fprintf(w, "  - %s\n", n)
	}
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
	line, _ := askLine(ctx, lines, w, "\nApprove these permissions? [y/N] > ")
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
// manifestTrust.flaws for which is which.
func requireApprovableLocation(path string, trust manifestTrust) error {
	for _, flaw := range trust.flaws(uint32(os.Geteuid())) {
		if flaw.fatal {
			if flaw.hint != "" {
				return fmt.Errorf("refusing to approve %s: %s; %s", path, flaw.reason, flaw.hint)
			}
			return fmt.Errorf("refusing to approve %s: %s", path, flaw.reason)
		}
	}
	return nil
}

// writeManifestAtomically replaces the manifest through a temporary file in its own
// directory and a rename, so an interrupted write cannot leave a truncated manifest where
// a complete one was - os.WriteFile opens the real file for truncation, and the half of a
// manifest it is mid-way through writing is what every other command would read. Both
// approve and profile write through here.
//
// It writes at the location the trust was gathered against, which is the symlink-resolved
// one: a manifest kept in a dotfiles repo and linked into place is ordinary here, and
// renaming onto the link itself would replace the link with a regular file and silently
// detach it from its source. Taking the location from the trust rather than resolving the
// name again is what keeps the write and the check talking about the same file. The rename
// still acts on a name, so someone who can write the resolved directory can still choose
// what ends up there - but that is fatal in the trust check, so approve never gets here.
//
// The mode carries forward from the file being replaced (0600 for one that does not exist
// yet), minus group and world write: approval is drift detection whose whole value is that
// the permissions cannot change without the stamp going stale, and a manifest anyone can
// edit gives that away.
func writeManifestAtomically(trust manifestTrust, data []byte, warn io.Writer) error {
	target := trust.realPath
	mode := trust.file.mode.Perm()
	if shared := mode & 0o022; shared != 0 {
		mode &^= 0o022
		fmt.Fprintf(warn, "[bento] %s was group/world-writable (%#o); writing it back as %#o - a manifest others can edit makes its approval stamp meaningless.\n", trust.file.path, trust.file.mode.Perm(), mode)
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
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}
