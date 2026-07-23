package main

import (
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "bento",
		Short: "Run untrusted scripts under kernel-enforced isolation",
		Long: "bento runs a script under the permissions declared in its manifest:\n" +
			"deny-by-default filesystem access, no network unless allowed, and subprocesses\n" +
			"blocked on the standard exec path unless allowed.\n\n" +
			"What a given host can actually enforce varies. bento reports every gap rather\n" +
			"than quietly substituting a weaker sandbox - run `bento doctor` to see what\n" +
			"this host enforces.",
		Version:       versionInfo(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("bento {{.Version}}\n")
	root.AddCommand(newRunCmd(), newDoctorCmd(), newValidateCmd(), newApproveCmd(), newProfileCmd(), newVersionCmd())
	return root
}
