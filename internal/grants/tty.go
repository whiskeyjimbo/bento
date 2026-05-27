package grants

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// TTYOption configures a TTY-backed prompt Callback.
type TTYOption func(*ttyOpts)

type ttyOpts struct {
	output         io.Writer // defaults to /dev/tty
	promptTemplate string    // override default prompt text
	input          io.Reader // custom input source (for mock/tests)
}

// WithTTYOutput redirects prompt logs/text to w. Defaults to /dev/tty.
func WithTTYOutput(w io.Writer) TTYOption {
	return func(o *ttyOpts) { o.output = w }
}

// WithPromptTemplate overrides the prompt display template.
func WithPromptTemplate(t string) TTYOption {
	return func(o *ttyOpts) { o.promptTemplate = t }
}

// WithTTYInput configures an alternative reader for confirmation inputs (for tests).
func WithTTYInput(r io.Reader) TTYOption {
	return func(o *ttyOpts) { o.input = r }
}

// TTYCallback returns a Callback that prompts the user on /dev/tty.
// Errors if /dev/tty isn't available. "y"/"yes" → Allow; anything else → Deny.
func TTYCallback(opts ...TTYOption) (Callback, error) {
	to := &ttyOpts{}
	for _, opt := range opts {
		opt(to)
	}

	var reader io.Reader
	var writer io.Writer

	if to.input != nil {
		reader = to.input
		if to.output != nil {
			writer = to.output
		} else {
			writer = io.Discard
		}
	} else {
		var tty io.ReadWriter
		if to.output != nil {
			if rw, ok := to.output.(io.ReadWriter); ok {
				tty = rw
			} else {
				// fallback if output isn't readable: must still open /dev/tty for reads
				f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
				if err != nil {
					return nil, errors.New("interactive prompts require a TTY (open /dev/tty failed); pass an explicit manifest or library callback")
				}
				tty = &readWriteStub{Reader: f, Writer: to.output}
			}
		} else {
			f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				return nil, errors.New("interactive prompts require a TTY (open /dev/tty failed); pass an explicit manifest or library callback")
			}
			tty = f
		}
		reader = tty
		writer = tty
	}

	bufReader := bufio.NewReader(reader)
	return func(r Request) Decision {
		fmt.Fprintf(writer, "[bento] script wants to connect to %s:%d. allow? [y/N] ", r.Host, r.Port)
		line, _ := bufReader.ReadString('\n')
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "y" || line == "yes" {
			fmt.Fprintln(writer, "[bento] → allow (remembered for this run)")
			return DecisionAllow
		}
		fmt.Fprintln(writer, "[bento] → deny (remembered for this run)")
		return DecisionDeny
	}, nil
}

type readWriteStub struct {
	io.Reader
	io.Writer
}
