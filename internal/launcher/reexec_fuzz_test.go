//go:build linux

package launcher

import (
	"slices"
	"strings"
	"testing"
)

// fuzzList turns one fuzzed string into a repeated flag's values. Empty means the
// flag was never passed, which is the case that separates nil from []string{} on
// the way back - see the slices.Equal comparisons below.
func fuzzList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// FuzzLaunchCodecRoundTrip generalizes TestLaunchCodecRoundTrip's table: every
// in-contract Config survives EncodeLaunch followed by DecodeLaunch unchanged.
// The codec is a private wire contract between the linux backend and the re-exec
// dispatcher, so a value that encodes to something the other end reads differently
// - a path that looks like a flag, an empty grant, a target arg leading with a
// dash - silently launches under a config nobody chose.
//
// Block is derived from StrictBlock rather than fuzzed independently: Config's doc
// makes StrictBlock imply Block, and execModeString panics on the out-of-contract
// pair rather than encode it as the weakest mode.
func FuzzLaunchCodecRoundTrip(f *testing.F) {
	f.Add("/proxy.sock", 4, 3, 5, "/tmp\n/w/out", "/bin/sh\n/w/run.sh\n-x", uint8(0b11111))
	f.Add("", 0, 0, 0, "", "/bin/echo\n--not-a-launch-flag\n-n", uint8(0))
	f.Add("--socket", 0, 0, 0, "--rw\n\n--", "--\n--exec\nall", uint8(0b00011))

	f.Fuzz(func(t *testing.T, socket string, livenessFD, observeFD, appliedFD int, writable, target string, bits uint8) {
		cfg := Config{
			Socket:            socket,
			BridgeLivenessFD:  livenessFD,
			StrictBlock:       bits&1 != 0,
			Block:             bits&1 != 0 || bits&2 != 0,
			RecordExec:        bits&4 != 0,
			AllowNetworkStdio: bits&8 != 0,
			ObserveFD:         observeFD,
			AppliedFD:         appliedFD,
			Writable:          fuzzList(writable),
			Target:            fuzzList(target),
		}
		got, err := DecodeLaunch(EncodeLaunch(cfg))
		if err != nil {
			t.Fatalf("decode of %+v: %v", cfg, err)
		}
		// The descriptors and the socket are the fields a mis-decode hands to Run as
		// something it will act on; the exec bits are the ones that disarm a fence.
		// Non-positive descriptors are never encoded, so they come back zero, which is
		// the same "no channel" the encoder was told.
		if got.Socket != cfg.Socket || got.AllowNetworkStdio != cfg.AllowNetworkStdio || got.RecordExec != cfg.RecordExec {
			t.Fatalf("round-trip mismatch\n got %+v\nwant %+v", got, cfg)
		}
		if got.Block != cfg.Block || got.StrictBlock != cfg.StrictBlock {
			t.Fatalf("exec mode did not round-trip\n got %+v\nwant %+v", got, cfg)
		}
		if got.BridgeLivenessFD != max(cfg.BridgeLivenessFD, 0) ||
			got.ObserveFD != max(cfg.ObserveFD, 0) || got.AppliedFD != max(cfg.AppliedFD, 0) {
			t.Fatalf("descriptors did not round-trip\n got %+v\nwant %+v", got, cfg)
		}
		// slices.Equal, not reflect.DeepEqual: an absent repeated flag and an absent
		// target both decode to an empty non-nil slice, which DeepEqual calls unequal
		// to the nil it was handed.
		if !slices.Equal(got.Writable, cfg.Writable) || !slices.Equal(got.Target, cfg.Target) {
			t.Fatalf("paths did not round-trip\n got %+v\nwant %+v", got, cfg)
		}
	})
}

// FuzzLaunchDegradedCodecRoundTrip is the same contract for the tier where Landlock
// is the sole filesystem fence, so an asymmetry between the two ends over- or
// under-grants with no bwrap behind it. Four repeated flags share one namespace
// here, which is the shape --ro/--rw/--x can come apart on.
func FuzzLaunchDegradedCodecRoundTrip(f *testing.F) {
	f.Add("/usr\n/lib", "/w/out\n/scratch", "/usr/bin/python3", "XDG_RUNTIME_DIR", "/scratch", 5, "/usr/bin/python3\n/w/app.py", uint8(0b11))
	f.Add("", "", "", "", "", 0, "/bin/echo\n-n", uint8(0))
	f.Add("--x\n--", "--ro", "--strip-env", "--\n", "--rw", 0, "--exec\nall", uint8(0b10))

	f.Fuzz(func(t *testing.T, readable, writable, execPaths, stripEnv, scratch string, appliedFD int, target string, bits uint8) {
		cfg := DegradedConfig{
			Readable:    fuzzList(readable),
			Writable:    fuzzList(writable),
			ExecPaths:   fuzzList(execPaths),
			StrictBlock: bits&1 != 0,
			Block:       bits&1 != 0 || bits&2 != 0,
			Scratch:     scratch,
			StripEnv:    fuzzList(stripEnv),
			AppliedFD:   appliedFD,
			Target:      fuzzList(target),
		}
		got, err := DecodeLaunchDegraded(EncodeLaunchDegraded(cfg))
		if err != nil {
			t.Fatalf("decode of %+v: %v", cfg, err)
		}
		if got.Scratch != cfg.Scratch || got.AppliedFD != max(cfg.AppliedFD, 0) {
			t.Fatalf("round-trip mismatch\n got %+v\nwant %+v", got, cfg)
		}
		if got.Block != cfg.Block || got.StrictBlock != cfg.StrictBlock {
			t.Fatalf("exec mode did not round-trip\n got %+v\nwant %+v", got, cfg)
		}
		if !slices.Equal(got.Readable, cfg.Readable) || !slices.Equal(got.Writable, cfg.Writable) ||
			!slices.Equal(got.ExecPaths, cfg.ExecPaths) || !slices.Equal(got.StripEnv, cfg.StripEnv) ||
			!slices.Equal(got.Target, cfg.Target) {
			t.Fatalf("grants did not round-trip\n got %+v\nwant %+v", got, cfg)
		}
	})
}

// FuzzDecodeLaunchNarrowsExec holds the decoder to the safe default over argv it did
// not write. The launch invocation is not attacker-controlled today - both ends ship
// in one binary - but Block is the field that decides whether the exec-block filter
// is installed at all, and "none" is the flag's default precisely so that anything
// short of an explicit "all" leaves the filter armed. Nothing pins that: dropping
// the default, or adding an --exec spelling that parses to an unblocked run, would
// pass every table test.
//
// The oracle: over arbitrary argv, DecodeLaunch either errors or returns Block=true,
// unless the word "all" is literally present as an --exec value.
func FuzzDecodeLaunchNarrowsExec(f *testing.F) {
	f.Add("--exec\nall\n--\n/bin/sh")
	f.Add("--exec=all")
	f.Add("--exec\nnone-strict\n--\n/bin/sh")
	f.Add("--rw\n/tmp\n--\n--exec\nall")
	f.Add("-exec\nall")
	f.Add("")

	f.Fuzz(func(t *testing.T, argv string) {
		cfg, err := DecodeLaunch(append([]string{SentinelLaunch}, fuzzList(argv)...))
		if err != nil || cfg.Block {
			return
		}
		// Either spelling the flag package accepts for a value: a separate word, or
		// joined with "=". A target arg after "--" can also be the bare word "all",
		// which is why this is a necessary rather than a sufficient condition - it
		// still fails the moment an unblocked run needs no "all" anywhere.
		if !slices.ContainsFunc(fuzzList(argv), func(a string) bool {
			return a == "all" || strings.HasSuffix(a, "=all")
		}) {
			t.Fatalf("DecodeLaunch left the exec filter disarmed with no --exec all in %q: %+v", argv, cfg)
		}
	})
}
