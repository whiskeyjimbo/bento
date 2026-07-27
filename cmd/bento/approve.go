package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/manifest"
)

func newApproveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "approve <manifest>",
		Short: "Stamp a manifest as approved for its current permissions",
		Long: "approve records that a human has reviewed the manifest's current permissions.\n\n" +
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
			// io.Discard, not stderr: approve reports the same facts itself below, as a
			// refusal for what it cannot fix and as the clamp warning for what it can.
			doc, trust, err := loadDocument(path, io.Discard)
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
			if checkApproval(doc) == approvalCurrent && trust.file.sharedWrite() == 0 {
				fmt.Fprintf(os.Stdout, "%s is already approved for its current permissions.\n", path)
				return nil
			}

			doc.Provenance = manifest.Provenance{
				GeneratedBy: "bento approve",
				GeneratedAt: time.Now().UTC().Format(time.RFC3339),
				Approves:    doc.Policy.Fingerprint(),
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
