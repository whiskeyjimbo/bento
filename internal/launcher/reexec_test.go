//go:build linux

package launcher

import (
	"reflect"
	"testing"
)

// The launch invocation is a wire contract between the linux backend (encode) and
// the re-exec dispatcher (decode) that ship in the same binary; a round-trip test
// pins them together without a 4-second sandbox run. It also covers the two spots
// stdlib flag makes easy to get wrong: the repeatable --rw and the -- before the
// target, whose args must survive verbatim (including a leading dash).
func TestLaunchCodecRoundTrip(t *testing.T) {
	cases := map[string]Config{
		"exec none, no egress": {
			Block:  true,
			Target: []string{"/usr/bin/python3", "/w/app.py"},
		},
		"exec none-strict with egress and observe": {
			Socket:           "/proxy.sock",
			BridgeLivenessFD: 4,
			Block:            true,
			StrictBlock:      true,
			ObserveFD:        3,
			Writable:         []string{"/tmp", "/dev", "/proc", "/w/out"},
			Target:           []string{"/bin/sh", "/w/run.sh", "-x"},
		},
		"exec all keeps target flags after --": {
			Block:  false,
			Target: []string{"/bin/echo", "--not-a-launch-flag", "-n"},
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeLaunch(EncodeLaunch(cfg))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(got, cfg) {
				t.Errorf("round-trip mismatch\n got %+v\nwant %+v", got, cfg)
			}
		})
	}
}

// The degraded-launch invocation is the same encode/decode wire contract, but for the
// tier where Landlock is the sole filesystem fence, so an asymmetry (a dropped --x, a
// --ro/--rw swap) silently over- or under-grants with no bwrap behind it. Round-trip it
// like the bwrap codec, covering a repeated --ro/--rw, an --x exec path, the scratch
// flag, and a leading-dash target arg after --.
func TestLaunchDegradedCodecRoundTrip(t *testing.T) {
	cases := map[string]DegradedConfig{
		"exec none with grants and scratch": {
			Readable:  []string{"/usr", "/lib", "/w/in"},
			Writable:  []string{"/w/out", "/scratch"},
			ExecPaths: []string{"/usr/bin/python3", "/w/app.py"},
			Block:     true,
			Scratch:   "/scratch",
			StripEnv:  []string{"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"},
			Target:    []string{"/usr/bin/python3", "/w/app.py"},
		},
		"exec none-strict keeps target flags after --": {
			Readable:    []string{"/usr"},
			Block:       true,
			StrictBlock: true,
			Target:      []string{"/bin/echo", "--not-a-launch-flag", "-n"},
		},
		"exec all no grants": {
			Block:  false,
			Target: []string{"/bin/sh", "/w/run.sh"},
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeLaunchDegraded(EncodeLaunchDegraded(cfg))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(got, cfg) {
				t.Errorf("round-trip mismatch\n got %+v\nwant %+v", got, cfg)
			}
		})
	}
}

func TestDecodeLaunchRejectsUnknownExecMode(t *testing.T) {
	if _, err := DecodeLaunch([]string{SentinelLaunch, "--exec", "sometimes", "--"}); err == nil {
		t.Fatal("expected an error for an unknown exec mode")
	}
}

// {Block:false, StrictBlock:true} is out of contract (StrictBlock is meaningful only
// with Block). It has no wire representation, and falling through to "all" would arm
// no filter at all - the weakest outcome for a config that asked for a strict block -
// so encoding it must fail loudly.
func TestExecModeStringPanicsOnStrictWithoutBlock(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for StrictBlock without Block")
		}
	}()
	execModeString(Config{Block: false, StrictBlock: true})
}

// The enforcer adds the session-bus variables systemd-run needs to create the limit
// scope; the target must not see them. Their removal is a plain env filter, but a
// regression here leaks the host's bus address into a sandboxed target.
func TestDropEnvRemovesOnlyNamedVars(t *testing.T) {
	env := []string{"PATH=/bin", "XDG_RUNTIME_DIR=/run/user/1000", "HOME=/home/a", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"}
	got := dropEnv(env, "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR")
	want := []string{"PATH=/bin", "HOME=/home/a"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dropEnv = %v, want %v", got, want)
	}
}
