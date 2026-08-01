package main

import (
	"bytes"
	"encoding/json"
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
		// hint is what the hint line must point the reader at. A mistake on the root has no
		// use line worth printing, so what is left has to name the right thing to go read.
		hint string
	}{
		{"missing manifest", []string{"run"}, "run needs a manifest path", "`bento run --help`"},
		{"surplus manifest", []string{"validate", "a.yaml", "b.yaml"}, "validate takes a manifest path and nothing else, but got 2 arguments", "`bento validate --help`"},
		{"missing script", []string{"profile"}, "profile needs a script path", "`bento profile --help`"},
		{"doctor takes none", []string{"doctor", "x"}, "doctor takes no arguments, but got 1", "`bento doctor --help`"},
		{"unknown flag", []string{"run", "--nosuchflag", "m.yaml"}, "unknown flag: --nosuchflag", "`bento run --help`"},
		{"unknown command", []string{"badcmd"}, `unknown command "badcmd"`, "to see the commands"},
		{"a near miss is suggested", []string{"runn"}, "Did you mean this?", "to see the commands"},
		{"a bad flag on the root itself", []string{"--nosuchflag"}, "unknown flag: --nosuchflag", "for the flags it takes"},
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
			writeUsageHint(&b, cmd, err)
			if !strings.Contains(b.String(), tc.hint) {
				t.Errorf("hint = %q, want it to point at %q", b.String(), tc.hint)
			}
			if cmd.HasParent() && !strings.Contains(b.String(), "usage: "+cmd.UseLine()) {
				t.Errorf("hint = %q, want the use line of %q", b.String(), cmd.CommandPath())
			}
		})
	}
}

// A usage error is raised before RunE, so the command that promised a refusal envelope
// on stdout never got to write one - and an empty stdout is the case the envelope exists
// to eliminate, indistinguishable from a crash to the machine gate `run --help` sends
// there. The commands that answer --json in their own shapes must not gain this one.
func TestUsageErrorUnderJSONStillLeavesARefusalEnvelope(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"an unknown flag on run", []string{"run", "--json", "--nosuchflag", "m.yaml"}, true},
		{"--json after the bad flag", []string{"run", "--nosuchflag", "--json", "m.yaml"}, true},
		{"a missing script on profile", []string{"profile", "--json"}, true},
		{"--json=true spells the same thing", []string{"run", "--json=true", "--nosuchflag"}, true},
		{"--json=false asked for no envelope", []string{"run", "--json=false", "--nosuchflag"}, false},
		{"without --json nothing is written", []string{"run", "--nosuchflag", "m.yaml"}, false},
		// validate answers --json in its own shape; a refusalJSON there would be a shape
		// its consumers were never told to expect.
		{"validate keeps its own contract", []string{"validate", "--json", "a.yaml", "b.yaml"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			root.SetArgs(tc.argv)
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			cmd, err := root.ExecuteC()
			if err == nil {
				t.Fatalf("argv %v must fail", tc.argv)
			}

			var stdout bytes.Buffer
			got := refuseUsageJSON(&stdout, cmd, tc.argv, err)
			if !tc.refused {
				if stdout.Len() != 0 {
					t.Fatalf("stdout = %q, want nothing written", stdout.String())
				}
				if !errors.Is(got, err) {
					t.Errorf("err = %v, want the error returned untouched for main to print", got)
				}
				return
			}
			if code := asExitError(t, got).code; code != bentoFailed {
				t.Errorf("exit code = %d, want %d, as a refusal raised inside RunE", code, bentoFailed)
			}
			var env refusalJSON
			if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
				t.Fatalf("envelope is not valid JSON: %v\n%s", err, stdout.String())
			}
			if !env.Refused || env.Reason == "" {
				t.Errorf("envelope = %+v, want refused with the usage error as its reason", env)
			}
			if env.Report.FullyEnforced || env.Report.Layers == nil {
				t.Errorf("report = %+v, want the empty report of a run that built no sandbox", env.Report)
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
		// A stray "--" puts the command name past cobra's lookup. Answering it as a
		// mistyped command produced the one message that cannot be true - that there is no
		// "run" command, followed by a suggestion to type "run".
		{"a stray -- is not a mistyped command", []string{"--", "run"}, []string{"Available Commands:"}},
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
