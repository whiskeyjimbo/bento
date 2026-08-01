package main

import (
	"errors"
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

// isUsageMistake reports whether the error that ended the run was a mistake in the
// command line. Most of them say so themselves, being *usageError; an unknown subcommand
// does not, because cobra raises that one inside its own lookup with neither a hook nor a
// type to match on. It is recognized by where it landed instead: the root runs nothing
// itself, so the only errors that can surface against it are that verdict and a flag
// error, and the flag error arrives already marked. Answering it by giving the root an
// Args validator of its own works too, but that is the same field cobra's lookup keys on
// - setting it makes `bento help nosuchthing` print the root help rather than saying the
// topic does not exist.
func isUsageMistake(root, cmd *cobra.Command, err error) bool {
	if err == nil {
		return false
	}
	var ue *usageError
	return errors.As(err, &ue) || cmd == root
}

// writeUsageHint follows a usage error with how the command should have been called.
// Only the one line, not cobra's full usage block: the message above already named what
// was wrong, and the flag list belongs behind the --help this points at.
func writeUsageHint(w io.Writer, cmd *cobra.Command, err error) {
	// The root's own use line ("bento [flags]") says nothing a reader who just mistyped a
	// command needs, so the reader is pointed at what they got wrong instead: a bad flag on
	// the root is the only mistake there that a marked error can be, and every other one is
	// cobra's lookup answering for a command that does not exist.
	if !cmd.HasParent() {
		var ue *usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(w, "Run `%s --help` for the flags it takes.\n", cmd.CommandPath())
			return
		}
		fmt.Fprintf(w, "Run `%s --help` to see the commands.\n", cmd.CommandPath())
		return
	}
	fmt.Fprintf(w, "usage: %s\n", cmd.UseLine())
	fmt.Fprintf(w, "Run `%s --help` for what it does and the flags it takes.\n", cmd.CommandPath())
}

// jsonRefusalAnnotation marks the commands whose --json contract is the refusal
// envelope, so an error raised before their RunE is answered in that shape rather than
// with an empty stdout. It is an opt-in and not "the command has a --json flag":
// validate and doctor answer --json in their own shapes, and a refusalJSON on stdout
// would be a shape their consumers were never told to expect.
const jsonRefusalAnnotation = "bento.json_refusal"

// refuseUsageJSON answers an error that never reached RunE in the refusal envelope that
// command's --json promises. cobra rejects an unknown flag or a bad argument count
// itself, so `bento run --json --bogus` exited with an empty stdout - the case the
// envelope exists to eliminate, and the one a machine gate cannot tell from a crash.
//
// Whether --json was asked for is read from argv rather than from the flag set: cobra
// parses left to right and stops at the error, so Changed("json") answers on where the
// bad flag happened to sit. Everything after a bare -- is the target's, not bento's.
//
// Only errors main would otherwise print: an *exitError is a command that already ran
// and wrote its own envelope.
func refuseUsageJSON(stdout io.Writer, cmd *cobra.Command, args []string, err error) error {
	var ee *exitError
	if cmd == nil || errors.As(err, &ee) || cmd.Annotations[jsonRefusalAnnotation] == "" || !wantsJSON(args) {
		return err
	}
	return refuseJSON(stdout, true, err)
}

func wantsJSON(args []string) bool {
	for _, a := range args {
		switch a {
		case "--":
			return false
		case "--json", "--json=true":
			return true
		}
	}
	return false
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
	}
	root.SetVersionTemplate("bento {{.Version}}\n")
	// Cobra raises a flag error on the subcommand that owns the flag, and the hook is
	// inherited, so this marks an unknown flag anywhere in the tree.
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error { return &usageError{err} })
	root.AddCommand(newRunCmd(), newDoctorCmd(), newValidateCmd(), newApproveCmd(), newProfileCmd(), newVersionCmd())
	return root
}
