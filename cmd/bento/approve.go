package main

import (
	"bufio"
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
			"scripts; so does a stdin that is not a terminal, which keeps the command usable\n" +
			"from CI - that one says so in its output, so a stamp nobody read does not look\n" +
			"like one somebody did.\n\n" +
			"It writes a provenance fingerprint of the policy into the manifest. `validate`\n" +
			"then reports the manifest as approved until the permissions change; after a\n" +
			"deliberate edit, run approve again to re-stamp it. The fingerprint covers the\n" +
			"permissions, not the script's contents - it attests the policy, not the code.\n\n" +
			"Approval is local drift detection, not a signature: the stamp is unkeyed and\n" +
			"lives in the manifest, so it attests only that the permissions match what was\n" +
			"stamped, not who stamped them. Review a manifest you got from elsewhere before\n" +
			"approving it - a shipped stamp is its author's, not your review.\n\n" +
			"The manifest is rewritten in canonical form (it is machine-owned); review the\n" +
			"diff as you would any change.",
		Args: cobra.ExactArgs(1),
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
			if approval == approvalCurrent && trust.file.sharedWrite() == 0 {
				fmt.Fprintf(os.Stdout, "%s is already approved for its current permissions.\n", path)
				return nil
			}

			// The judgement approve exists to record lives in reading the policy, and
			// nothing here showed it: a numbered four-step list whose fourth command
			// printed one line made typing it the path of least resistance. The summary
			// is validate's own, so there is one rendering of a policy rather than two
			// that can drift.
			resolved := resolvedGrants(doc.Policy, path)
			writePolicySummary(os.Stdout, path, doc.Policy, resolved)
			writeApprovalCallouts(os.Stdout, trust.realPath, doc.Policy, resolved, doc.Provenance.BlockedHosts)
			// After the callouts, not before: the notice sends the reader back over everything
			// above it, and the callouts are the part of the report a drift most needs reread.
			writeReapprovalNotice(os.Stdout, approval)
			if err := confirmApproval(os.Stdout, assumeYes); err != nil {
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
// It cannot mark the added lines: the stamp is a sha256 of the policy, not a copy of it,
// so the shape that was approved is not on disk anywhere. Saying which is which needs the
// previous shape stored, which is a change to the manifest's on-disk contract. Saying that
// it changed at all needs nothing, and is the half a reader most needs before stamping.
func writeReapprovalNotice(w io.Writer, approval approvalState) {
	if approval != approvalStale {
		return
	}
	fmt.Fprintf(w, "\nThis manifest was approved before and its permissions have changed since.\n")
	fmt.Fprintf(w, "The stamp is a hash of the policy, not a copy of it, so bento cannot mark the\n")
	fmt.Fprintf(w, "lines that are new - read the whole policy above as if it were unapproved.\n")
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

// confirmApproval asks before the stamp goes on. A stdin that is not a terminal answers
// yes, matching profiling's own non-interactive contract: there is no human to ask, and
// blocking would hang every wrapper script and CI job that already calls approve. --yes
// says so explicitly, which is what a script should do.
//
// The silent branch is the one that says so out loud, in the prompt's own position and on
// the same stream as the rest of the report: `bento approve m.yaml | tee log` and any
// Makefile recipe redirect stdin, and without the line their unreviewed stamp reads
// exactly like a reviewed one. --yes prints nothing because passing it was already the
// operator saying it.
func confirmApproval(w io.Writer, assumeYes bool) error {
	if assumeYes {
		return nil
	}
	if !isTerminal(os.Stdin) {
		fmt.Fprint(w, "\nstdin is not a terminal, so there was nobody to ask: approving as if --yes\nwere passed. Nothing above was reviewed.\n")
		return nil
	}
	fmt.Fprint(w, "\nApprove these permissions? [y/N] > ")
	line, _ := bufio.NewReader(openTTY()).ReadString('\n')
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
