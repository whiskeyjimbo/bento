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
			Socket:      "/proxy.sock",
			Block:       true,
			StrictBlock: true,
			ObserveFD:   3,
			Writable:    []string{"/tmp", "/dev", "/proc", "/w/out"},
			Target:      []string{"/bin/sh", "/w/run.sh", "-x"},
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

func TestDecodeLaunchRejectsUnknownExecMode(t *testing.T) {
	if _, err := DecodeLaunch([]string{SentinelLaunch, "--exec", "sometimes", "--"}); err == nil {
		t.Fatal("expected an error for an unknown exec mode")
	}
}
