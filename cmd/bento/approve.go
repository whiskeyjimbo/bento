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
			doc, err := loadDocument(path)
			if err != nil {
				return err
			}

			if checkApproval(doc) == approvalCurrent {
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
			if err := writeManifestAtomically(path, out, os.Stderr); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "approved %s for its current permissions.\n", path)
			return nil
		},
	}
}

// writeManifestAtomically replaces the manifest through a temporary file in its own
// directory and a rename, so an interrupted approve cannot leave a truncated manifest
// where a complete one was - os.WriteFile opens the real file for truncation, and the
// stamp it is mid-way through writing is the thing every other command reads.
//
// It writes at the symlink-resolved location, since a manifest kept in a dotfiles repo
// and linked into place is ordinary here; renaming onto the link itself would replace
// the link with a regular file and silently detach it from its source.
//
// The mode carries forward from the file being replaced, minus group and world write:
// approval is drift detection whose whole value is that the permissions cannot change
// without the stamp going stale, and a manifest anyone can edit gives that away.
func writeManifestAtomically(path string, data []byte, warn io.Writer) error {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if shared := mode & 0o022; shared != 0 {
		mode &^= 0o022
		fmt.Fprintf(warn, "[bento] %s was group/world-writable (%#o); writing it back as %#o - a manifest others can edit makes its approval stamp meaningless.\n", path, info.Mode().Perm(), mode)
	}

	f, err := os.CreateTemp(filepath.Dir(target), ".bento-approve-*")
	if err != nil {
		return err
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
