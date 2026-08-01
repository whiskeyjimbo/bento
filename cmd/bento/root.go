package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// usageError marks the errors that are a mistake in the command line itself - a missing
// or surplus argument, an unknown flag, an unknown command - rather than a failure of the
// work. Only these get the usage line and the --help pointer printed after them:
// SilenceUsage stays on for everything else, where a wall of flags after "this host
// cannot enforce X" buries the answer instead of helping anyone.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// exactArgs and minArgs replace cobra's stock validators so the message names the
// argument the command wanted. "accepts 1 arg(s), received 0" tells a newcomer that a
// count was wrong and nothing about what to type; what is the argument in prose, e.g.
// "a manifest path".
func exactArgs(n int, what string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		switch {
		case len(args) < n:
			return &usageError{fmt.Errorf("%s needs %s", cmd.Name(), what)}
		case len(args) > n:
			return &usageError{fmt.Errorf("%s takes %s and nothing else, but got %d arguments", cmd.Name(), what, len(args))}
		}
		return nil
	}
}

func minArgs(n int, what string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < n {
			return &usageError{fmt.Errorf("%s needs %s", cmd.Name(), what)}
		}
		return nil
	}
}

func noArgs() cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return &usageError{fmt.Errorf("%s takes no arguments, but got %d", cmd.Name(), len(args))}
		}
		return nil
	}
}

// rootArgs answers an unknown subcommand. Cobra raises that one inside its own lookup,
// with no hook and no error type to match on, so the root has to be runnable for the
// unmatched argument to reach code that can mark it - which is why the root carries a
// RunE printing help, the behavior an argument-less `bento` had for free before.
func rootArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	err := fmt.Errorf("there is no %q command", args[0])
	if near := cmd.SuggestionsFor(args[0]); len(near) > 0 {
		err = fmt.Errorf("%w. Did you mean %q?", err, near[0])
	}
	return &usageError{err}
}

// writeUsageHint follows a usage error with how the command should have been called.
// Only the one line, not cobra's full usage block: the message above already named what
// was wrong, and the flag list belongs behind the --help this points at.
func writeUsageHint(w io.Writer, cmd *cobra.Command) {
	// The root's own use line ("bento [flags]") says nothing a reader who just mistyped a
	// command needs; the command list behind --help is the answer there.
	if !cmd.HasParent() {
		fmt.Fprintf(w, "Run `%s --help` to see the commands.\n", cmd.CommandPath())
		return
	}
	fmt.Fprintf(w, "usage: %s\n", cmd.UseLine())
	fmt.Fprintf(w, "Run `%s --help` for what it does and the flags it takes.\n", cmd.CommandPath())
}

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
		Args:          rootArgs,
		// Cobra applies this to its own "unknown command" only, and rootArgs answers that
		// before cobra does, so the threshold has to be set for SuggestionsFor to match.
		SuggestionsMinimumDistance: 2,
		RunE:                       func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	root.SetVersionTemplate("bento {{.Version}}\n")
	// Cobra raises a flag error on the subcommand that owns the flag, and the hook is
	// inherited, so this marks an unknown flag anywhere in the tree.
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error { return &usageError{err} })
	root.AddCommand(newRunCmd(), newDoctorCmd(), newValidateCmd(), newApproveCmd(), newProfileCmd(), newVersionCmd())
	return root
}
