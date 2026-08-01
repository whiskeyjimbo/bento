package main

import (
	"bytes"
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
		{"unknown command", []string{"badcmd"}, `unknown command "badcmd"`},
		{"a near miss is suggested", []string{"runn"}, "Did you mean this?"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			root.SetArgs(tc.argv)
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)

			cmd, err := root.ExecuteC()
			if err == nil || !isUsageMistake(root, cmd, err) {
				t.Fatalf("err = %v (%T), want it recognized as a usage mistake", err, err)
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

// The invocations that are NOT mistakes have to stay that way. Recognizing an unknown
// command by the command it landed on rather than by an error type is what keeps the
// root's Args field free, and cobra's own lookup keys on that field: setting it makes an
// unknown help topic resolve to the root and print its help as though the topic existed.
func TestNonMistakesAreNotTreatedAsUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{"bare invocation prints help", nil, []string{"Available Commands:", "run", "doctor"}},
		{"an unknown help topic says so", []string{"help", "badcmd"}, []string{"Unknown help topic"}},
		{"a known help topic is the command's own help", []string{"help", "run"}, []string{"run enforces the manifest's policy"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			root.SetArgs(tc.argv)
			var b bytes.Buffer
			root.SetOut(&b)
			root.SetErr(&b)

			cmd, err := root.ExecuteC()
			if err != nil {
				t.Fatalf("must not fail: %v", err)
			}
			if isUsageMistake(root, cmd, err) {
				t.Errorf("a nil error must never read as a usage mistake")
			}
			for _, want := range tc.want {
				if !strings.Contains(b.String(), want) {
					t.Errorf("output must name %q; got:\n%s", want, b.String())
				}
			}
		})
	}
}
