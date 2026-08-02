package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
	// shape is what the command promised: "stream" for run, whose stdout is one JSON
	// object per line, "document" for profile's single indented envelope. Asserting the
	// specific one is the point - a test that accepted either would pass with the two
	// commands' annotations swapped, which is the regression the split exists to prevent.
	cases := []struct {
		name  string
		argv  []string
		shape string
	}{
		{"an unknown flag on run", []string{"run", "--json", "--nosuchflag", "m.yaml"}, "stream"},
		{"--json after the bad flag", []string{"run", "--nosuchflag", "--json", "m.yaml"}, "stream"},
		{"a missing script on profile", []string{"profile", "--json"}, "document"},
		{"--json=true spells the same thing", []string{"run", "--json=true", "--nosuchflag"}, "stream"},
		{"--json=1 spells it too", []string{"run", "--json=1", "--nosuchflag"}, "stream"},
		{"--json=false asked for no envelope", []string{"run", "--json=false", "--nosuchflag"}, ""},
		{"--json=0 asked for no envelope", []string{"run", "--json=0", "--nosuchflag"}, ""},
		{"without --json nothing is written", []string{"run", "--nosuchflag", "m.yaml"}, ""},
		// --env takes a value, so this is a malformed --env and not a request for an
		// envelope; answering it with JSON would swallow the message naming the mistake.
		{"a --json eaten as another flag's value", []string{"run", "--env", "--json", "--nosuchflag"}, ""},
		// validate answers --json in its own shape; a refusal there would be a shape its
		// consumers were never told to expect.
		{"validate keeps its own contract", []string{"validate", "--json", "a.yaml", "b.yaml"}, ""},
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
			got := refuseUsageJSON(&stdout, root, cmd, tc.argv, err)
			if tc.shape == "" {
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
			var env struct {
				Refused bool       `json:"refused"`
				Event   string     `json:"event"`
				Reason  string     `json:"reason"`
				Report  reportJSON `json:"report"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
				t.Fatalf("envelope is not valid JSON: %v\n%s", err, stdout.String())
			}
			if env.Reason == "" {
				t.Errorf("envelope = %+v, want the usage error as its reason", env)
			}
			switch tc.shape {
			case "stream":
				if env.Event != "refusal" || env.Refused {
					t.Errorf("envelope = %+v, want run's refusal event and no refused field", env)
				}
				// One object per line, so a consumer parsing the stream reads it like any
				// other. An indented document here would be several lines that each fail.
				if strings.Count(strings.TrimSuffix(stdout.String(), "\n"), "\n") != 0 {
					t.Errorf("run's refusal spans lines; its stdout is one object per line:\n%s", stdout.String())
				}
			case "document":
				if !env.Refused || env.Event != "" {
					t.Errorf("envelope = %+v, want profile's refused:true and no event field", env)
				}
			}
			if env.Report.FullyEnforced || env.Report.Layers == nil {
				t.Errorf("report = %+v, want the empty report of a run that built no sandbox", env.Report)
			}
		})
	}
}

// A shape refuseUsageJSON does not answer has to be caught where the commands are
// assembled. It is the failure mode with no other symptom: the switch falls through, and
// the command ships with exactly the empty stdout its annotation was added to prevent.
func TestAnUnknownRefusalShapeIsRejectedAtConstruction(t *testing.T) {
	// A nested command is checked too: refuseUsageJSON reads the annotation off whatever
	// command cobra raised the error on, at whatever depth it sits.
	for _, depth := range []int{1, 2} {
		t.Run(fmt.Sprintf("a typo'd shape %d level(s) down panics", depth), func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("a command annotated with an unknown shape must not be assembled")
				}
				if msg, _ := r.(string); !strings.Contains(msg, "streem") {
					t.Errorf("panic = %v, want the offending value named", r)
				}
			}()
			cmd := &cobra.Command{
				Use:         "typo",
				Annotations: map[string]string{jsonRefusalAnnotation: "streem"},
			}
			root := &cobra.Command{Use: "bento"}
			parent := root
			for range depth - 1 {
				sub := &cobra.Command{Use: "mid"}
				parent.AddCommand(sub)
				parent = sub
			}
			parent.AddCommand(cmd)
			checkJSONRefusalShapes(root)
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

// The platform refusal is raised inside a RunE and never by a hook above one. What is
// pinned here is the second half of that: no hook exists to raise it, whatever the three
// commands do inside their own RunE (which platform_linux_test.go covers). run, profile
// and doctor each answer --json with a document of their own, and a hook fires before the
// RunE that writes one, so a gate attached here would leave --json the empty stdout on a
// host with no backend. On the root it would be worse,
// inheriting onto cobra's `help`, `completion` and hidden `__complete`, which answer fine
// on a host bento cannot run on.
func TestNoCommandRefusesOnPlatformBeforeItsRunE(t *testing.T) {
	root := newRootCmd()
	if root.PersistentPreRunE != nil {
		t.Error("the root must not carry a gate; cobra's help and completion commands inherit it")
	}
	for _, cmd := range root.Commands() {
		if cmd.PersistentPreRunE != nil {
			t.Errorf("%s: a hook before the RunE answers --json with an empty stdout", cmd.Name())
		}
	}
}
