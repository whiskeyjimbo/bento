package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// A mistake in the command line is the one error class where bento knows the right
// answer and can print it, so every shape of it has to be marked as one: the hint below
// is attached to *usageError and nothing else, and an unmarked shape reverts to the bare
// cobra line that names neither the argument nor where to look.
func TestUsageErrorsAreMarkedAndNamed(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"missing manifest", []string{"run"}, "run needs a manifest path"},
		{"surplus manifest", []string{"validate", "a.yaml", "b.yaml"}, "validate takes a manifest path and nothing else, but got 2 arguments"},
		{"missing script", []string{"profile"}, "profile needs a script path"},
		{"doctor takes none", []string{"doctor", "x"}, "doctor takes no arguments, but got 1"},
		{"unknown flag", []string{"run", "--nosuchflag", "m.yaml"}, "unknown flag: --nosuchflag"},
		{"unknown command", []string{"badcmd"}, `there is no "badcmd" command`},
		{"a near miss is suggested", []string{"runn"}, `Did you mean "run"?`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			root.SetArgs(tc.argv)
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)

			cmd, err := root.ExecuteC()
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Fatalf("err = %v (%T), want a *usageError", err, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to contain %q", err, tc.want)
			}

			// The hint is only worth anything if it names the command the user was
			// reaching for rather than whatever cobra last touched.
			var b bytes.Buffer
			writeUsageHint(&b, cmd)
			if !strings.Contains(b.String(), "--help") {
				t.Errorf("hint = %q, want a --help pointer", b.String())
			}
			if cmd.HasParent() && !strings.Contains(b.String(), "usage: "+cmd.UseLine()) {
				t.Errorf("hint = %q, want the use line of %q", b.String(), cmd.CommandPath())
			}
		})
	}
}

// Making the root runnable is what lets an unknown command reach code that can mark it,
// and the argument-less invocation it displaced has to keep printing help - exiting 125
// with a usage error at someone who typed `bento` to find out what bento is would be a
// worse dead end than the one this replaced.
func TestBareInvocationStillPrintsHelp(t *testing.T) {
	root := newRootCmd()
	root.SetArgs(nil)
	var b bytes.Buffer
	root.SetOut(&b)
	root.SetErr(&b)

	if err := root.Execute(); err != nil {
		t.Fatalf("bare `bento` must not fail: %v", err)
	}
	for _, want := range []string{"Available Commands:", "run", "doctor"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("bare `bento` must print help naming %q; got:\n%s", want, b.String())
		}
	}
}
