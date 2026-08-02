package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

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

// jsonRefusalAnnotation marks the commands whose --json contract answers a refusal, so
// an error raised before their RunE is answered in that shape rather than with an empty
// stdout. It is an opt-in and not "the command has a --json flag": validate and doctor
// answer --json in their own shapes, and a refusal on stdout would be a shape their
// consumers were never told to expect.
//
// Its value names WHICH shape, because the two that opt in do not share one: profile
// answers with a single indented document, run with one object on its event stream. Any
// other value is a construction mistake newRootCmd panics on: treating it as not opted in
// would leave --json the empty stdout the annotation exists to eliminate, on a command
// whose author had asked for the envelope.
const jsonRefusalAnnotation = "bento.json_refusal"

const (
	// jsonRefusalDocument is `bento profile`'s shape: refusalJSON, indented, one document.
	jsonRefusalDocument = "document"
	// jsonRefusalStream is `bento run`'s: one refusal object on the JSON-lines stream its
	// stdout is, so a consumer switches on event whether the run produced output or was
	// refused before it started.
	jsonRefusalStream = "stream"
)

// refuseUsageJSON answers an error that never reached RunE in the refusal envelope that
// command's --json promises. cobra rejects an unknown flag or a bad argument count
// itself, so `bento run --json --bogus` exited with an empty stdout - the case the
// envelope exists to eliminate, and the one a machine gate cannot tell from a crash.
//
// Whether --json was asked for is read from argv rather than from the flag set: cobra
// parses left to right and stops at the error, so Changed("json") answers on where the
// bad flag happened to sit. Everything after a bare -- is the target's, not bento's.
//
// Mistakes in the command line only. An error raised inside RunE is that command's to
// answer - it knows whether the target ran, and calling one refused here would report a
// run bento declined over one it started and could not finish.
func refuseUsageJSON(stdout io.Writer, root, cmd *cobra.Command, args []string, err error) error {
	if cmd == nil || !isUsageMistake(root, cmd, err) || !wantsJSON(cmd, args) {
		return err
	}
	switch cmd.Annotations[jsonRefusalAnnotation] {
	case jsonRefusalDocument:
		return refuseJSON(stdout, true, err)
	case jsonRefusalStream:
		return refuseStreamJSON(stdout, true, err)
	}
	return err
}

// wantsJSON reports whether argv asked cmd for --json.
//
// The value is parsed rather than matched against "true": pflag takes every spelling
// strconv.ParseBool does, so --json=1 asks for the envelope as surely as --json does,
// and a scan that missed it would leave exactly the empty stdout this exists to prevent.
//
// A flag that takes a value has its value stepped over, so `--env --json` is the malformed
// --env it is rather than a request for an envelope - which would answer a typo with JSON
// and swallow the message naming it. Only a flag cmd declares can be told apart that way;
// an unknown one is the error cobra already raised, and its value, if it had one, reads
// as a separate word here.
func wantsJSON(cmd *cobra.Command, args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return false
		}
		if a == "--json" {
			return true
		}
		if v, ok := strings.CutPrefix(a, "--json="); ok {
			on, err := strconv.ParseBool(v)
			return err == nil && on
		}
		// NoOptDefVal is what a flag stands for when it is given bare, so only a flag
		// without one consumes the next word. --name=value carries its own and never does.
		name, ok := strings.CutPrefix(a, "--")
		if !ok || strings.Contains(name, "=") {
			continue
		}
		if f := cmd.Flags().Lookup(name); f != nil && f.NoOptDefVal == "" {
			i++
		}
	}
	return false
}

// The platform refusal is raised inside a RunE rather than by a hook above it, in each of
// the three commands that build or probe a sandbox - run, profile and doctor. All three
// answer --json with a document of their own, and a hook fires before the RunE that knows
// how to write one, so refusing above them would answer a machine consumer with exactly
// the empty stdout the JSON refusal shapes exist to eliminate.
//
// The rest are not gated at all. `help`, `completion`, `version` and the hidden
// `__complete` answer perfectly well on a host that cannot run anything, and `validate`
// and `approve` build no sandbox: both are static operations over a manifest, so what
// they can say off Linux is decided by the trust facts readable there rather than by
// whether a backend exists. See errLocationUnknown.

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
	root.AddCommand(newDoctorCmd(), newValidateCmd(), newApproveCmd())
	root.AddCommand(newRunCmd(), newProfileCmd(), newVersionCmd())
	checkJSONRefusalShapes(root)
	return root
}

// checkJSONRefusalShapes rejects a command that opts into the refusal envelope under a
// shape refuseUsageJSON does not answer. This is the one place that sees every command,
// and the mistake is otherwise invisible: the switch would fall through, and the command
// would ship with the empty stdout on a usage error that its annotation was added to
// prevent. A panic because it is a construction error, reachable on any invocation.
//
// It walks the whole tree rather than the root's own children: refuseUsageJSON reads the
// annotation off whatever command cobra raised the error on, which is at whatever depth
// that command sits.
func checkJSONRefusalShapes(cmd *cobra.Command) {
	switch shape, ok := cmd.Annotations[jsonRefusalAnnotation]; {
	case !ok, shape == jsonRefusalDocument, shape == jsonRefusalStream:
	default:
		panic(fmt.Sprintf("bento: command %q carries %s=%q, which names no refusal shape; want %q or %q",
			cmd.Name(), jsonRefusalAnnotation, shape, jsonRefusalDocument, jsonRefusalStream))
	}
	for _, sub := range cmd.Commands() {
		checkJSONRefusalShapes(sub)
	}
}
