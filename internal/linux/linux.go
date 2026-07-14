// Package linux enforces a policy with bubblewrap.
//
// It is an adapter behind the enforce.Enforcer seam: the core hands it a
// validated policy and it answers with what it actually enforced. Nothing here
// decides policy — that is the core's job — and no type from here appears in the
// core's signatures.
package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// Enforcer applies policies with bubblewrap.
type Enforcer struct{}

// New returns a bubblewrap-backed Enforcer.
func New() *Enforcer { return &Enforcer{} }

var _ enforce.Enforcer = (*Enforcer)(nil)

// Run compiles the policy into a bubblewrap invocation and executes the target
// inside it. A non-zero exit from the target is returned in the Result; err is
// reserved for a failure to build or start the sandbox, so a script that merely
// fails is never confused with a sandbox that did not hold.
func (e *Enforcer) Run(ctx context.Context, p *policy.Policy, proc enforce.Process) (enforce.Result, error) {
	report := e.Probe(ctx)

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return enforce.Result{}, fmt.Errorf("linux: bubblewrap (bwrap) not found: %w", err)
	}
	sb, cleanup, err := newSandbox(p)
	if err != nil {
		return enforce.Result{}, err
	}
	defer cleanup()

	args, err := compile(p, proc, sb)
	if err != nil {
		return enforce.Result{}, err
	}

	cmd := exec.CommandContext(ctx, bwrap, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = proc.Stdin, proc.Stdout, proc.Stderr

	switch err := cmd.Run(); {
	case err == nil:
		return enforce.Result{ExitCode: 0, Report: report}, nil
	case isExitError(err):
		var ee *exec.ExitError
		errors.As(err, &ee)
		return enforce.Result{ExitCode: ee.ExitCode(), Report: report}, nil
	default:
		return enforce.Result{Report: report}, fmt.Errorf("linux: running sandbox: %w", err)
	}
}

func isExitError(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee)
}

// newSandbox resolves the host facts the argv compiler needs, and returns a
// cleanup for the temporary files it creates.
func newSandbox(p *policy.Policy) (sandbox, func(), error) {
	noop := func() {}

	entrypoint, err := resolve(p.Entrypoint)
	if err != nil {
		return sandbox{}, noop, err
	}
	if _, err := os.Stat(entrypoint); err != nil {
		return sandbox{}, noop, fmt.Errorf("linux: entrypoint %q: %w", p.Entrypoint, err)
	}

	// An empty interpreter means the entrypoint runs itself: a compiled binary.
	var interp string
	if p.Interpreter != "" {
		found, err := exec.LookPath(p.Interpreter)
		if err != nil {
			return sandbox{}, noop, fmt.Errorf("linux: interpreter %q not found: %w", p.Interpreter, err)
		}
		if interp, err = resolve(found); err != nil {
			return sandbox{}, noop, err
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return sandbox{}, noop, fmt.Errorf("linux: resolving home directory: %w", err)
	}

	empty, err := newEmptyFile()
	if err != nil {
		return sandbox{}, noop, err
	}

	sb := sandbox{
		home:        home,
		emptyFile:   empty,
		entrypoint:  entrypoint,
		interpreter: interp,
		exists:      hostExists,
	}
	return sb, func() { os.Remove(empty) }, nil
}

// newEmptyFile creates the empty file the deny-list binds over paths that must
// be shielded even though they do not exist on the host yet.
func newEmptyFile() (string, error) {
	f, err := os.CreateTemp("", "bento-shield-")
	if err != nil {
		return "", fmt.Errorf("linux: creating deny-list shield: %w", err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("linux: creating deny-list shield: %w", err)
	}
	if err := os.Chmod(name, 0o444); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("linux: creating deny-list shield: %w", err)
	}
	return name, nil
}

// ResolveInterpreter guesses the interpreter for a script from its extension or
// shebang, so a policy need not spell out what a `.py` file runs with. An empty
// result means the file is its own interpreter (a compiled binary).
func ResolveInterpreter(path string) string {
	switch filepath.Ext(path) {
	case ".py":
		return "python3"
	case ".sh", ".bash":
		return "bash"
	case ".js":
		return "node"
	case ".rb":
		return "ruby"
	}
	return shebang(path)
}

func shebang(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var buf [256]byte
	n, _ := f.Read(buf[:])
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	if !strings.HasPrefix(line, "#!") {
		return ""
	}
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return ""
	}
	// "#!/usr/bin/env python3" names the interpreter in the second field.
	if filepath.Base(fields[0]) == "env" && len(fields) > 1 {
		return fields[1]
	}
	return fields[0]
}
