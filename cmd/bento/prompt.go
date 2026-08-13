package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

type grantChoice int

const (
	grantNo   grantChoice = iota // n / blank / unrecognized: decline, do not mount
	grantYes                     // y: mount this path next round
	grantAll                     // a: accept this and every remaining path this session
	grantQuit                    // q / EOF: stop the loop, keep what was accepted so far
)

// newGrantPrompter reads one single-line answer per call from in, mapping it to a
// grant choice. EOF returns grantQuit so a closed input ends the loop rather than
// erroring or looping forever.
func newGrantPrompter(ctx context.Context, lines <-chan string, out io.Writer) func(kind, path string) (grantChoice, error) {
	return func(kind, path string) (grantChoice, error) {
		// exec carries no path, so it is named by what it permits rather than left with
		// a dangling argument.
		what := kind + " " + path
		if path == "" {
			what = kind + " (let the target spawn subprocesses)"
		}
		line, ok := askLine(ctx, lines, out, fmt.Sprintf("[bento]   grant %s? [y]es / [n]o / [a]ll / [q]uit > ", what))
		if !ok {
			// Cancelled, not answered: quit would write the proposal as a session the user
			// ended deliberately, where a Ctrl-C must leave no manifest behind - which is
			// what the non-interactive path does with the same cancellation.
			if err := ctx.Err(); err != nil {
				return grantNo, err
			}
			return grantQuit, nil
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return grantYes, nil
		case "a", "all":
			return grantAll, nil
		case "q", "quit":
			return grantQuit, nil
		default:
			return grantNo, nil
		}
	}
}

// confirmNetworkExfil warns that --allow-network forwards egress while real granted
// content is mounted - a compromised target could exfiltrate the credentials being
// granted - and refuses the run unless the user confirms.
func confirmNetworkExfil(ctx context.Context, lines <-chan string, out io.Writer) error {
	fmt.Fprintln(out, "[bento] WARNING: --allow-network forwards the target's egress WHILE the content you grant is")
	fmt.Fprintln(out, "[bento] mounted with real data. A compromised target could exfiltrate those credentials.")
	line, ok := askLine(ctx, lines, out, "[bento] Continue with network forwarding? [y/N] > ")
	if !ok && ctx.Err() != nil {
		return ctx.Err()
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	default:
		return fmt.Errorf("aborted: re-run without --allow-network to profile with egress recorded but not forwarded")
	}
}

// interactiveStdin reports whether stdin is a terminal, so profiling drives the
// interactive convergence loop only when there is a human to answer its prompts; a
// pipe or CI run falls back to a single non-interactive pass.
func interactiveStdin() bool {
	return isTerminal(os.Stdin)
}

// openTTY returns the controlling terminal for reading the convergence prompts, kept
// separate from the target's own stdin, and a cleanup to release it. It falls back to
// os.Stdin where /dev/tty is unavailable; the cleanup is a no-op there, because closing
// that reader would close the process's stdin rather than a handle this opened.
func openTTY() (io.Reader, func()) {
	if f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0); err == nil {
		return f, func() { f.Close() }
	}
	return os.Stdin, func() {}
}

// profilePrompts is where the profiling session gets its answers: the line stream, whether
// there is a human to answer at all, and the release. One seam rather than the two calls it
// replaces, so a caller cannot end up holding a terminal it has no answer stream for.
//
// A var because the convergence loop is only reachable through it, and a test cannot get
// there otherwise: a pty on stdin satisfies the terminal check but openTTY prefers
// /dev/tty, so the answers would go to whatever terminal the `go test` invocation
// inherited - or to none in CI. Everything downstream, including which paths the loop
// mounts, is real.
var profilePrompts = func() (answers <-chan string, interactive bool, done func()) {
	if !interactiveStdin() {
		return nil, false, func() {}
	}
	tty, closeTTY := openTTY()
	return ttyLines(tty), true, closeTTY
}

// ttyLines reads the terminal a line at a time on its own goroutine, so a prompt can
// give up on an answer that is not coming. A read of /dev/tty is not interruptible and
// the CLI's SIGINT handler is released after the first Ctrl-C, so a prompt parked in
// Read would sit there looking like bento ignored it until a second Ctrl-C killed the
// process. One channel serves every prompt of a session: a second reader over the same
// terminal would hold a line the first had already buffered past.
//
// The goroutine leaks when the session ends with the reader still blocked, which is
// fine - there is one per run and the process is on its way out.
func ttyLines(in io.Reader) <-chan string {
	lines := make(chan string)
	go func() {
		defer close(lines)
		r := bufio.NewReader(in)
		for {
			// A final line with no trailing newline is still an answer; only an empty read
			// ends the stream.
			line, err := r.ReadString('\n')
			if line != "" {
				lines <- line
			}
			if err != nil {
				return
			}
		}
	}()
	return lines
}

// askLine prints a prompt and waits for one answer, reporting false when none can come:
// the terminal closed, or the run was cancelled - which the caller tells apart by
// ctx.Err(), because the two mean different things for what gets written.
func askLine(ctx context.Context, lines <-chan string, out io.Writer, prompt string) (string, bool) {
	fmt.Fprint(out, prompt)
	select {
	case <-ctx.Done():
		fmt.Fprintln(out)
		return "", false
	case line, ok := <-lines:
		// Both were ready: a Ctrl-C landing on the same keystroke as the answer must not
		// let the session proceed, or a cancelled run still writes a manifest.
		if ctx.Err() != nil {
			return "", false
		}
		return line, ok
	}
}
