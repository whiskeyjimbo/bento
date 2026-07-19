package launcher

import (
	"flag"
	"fmt"
	"io"
	"strconv"
)

// Sentinel argv[0]-after values that mark bento's in-sandbox re-exec stages. They
// are namespaced (not bare "launch"/"bridge") because an embedder calls
// DispatchReexec before its own flag parsing: a plain word could collide with the
// host program's own first argument. Encode and decode always ship in the same
// binary, so these are a private wire contract, not a stable public interface.
const (
	SentinelLaunch = "__bento_launch"
	SentinelBridge = "__bento_bridge"
)

// EncodeLaunch renders the in-sandbox launch invocation for cfg: the launch
// sentinel, the flags that carry cfg, a "--" separator, and the target. The
// caller prepends argv[0] (the path the bento binary is bound at inside the
// sandbox), which only it knows.
//
// This is the encode half of the wire contract DecodeLaunch parses; the two must
// change together. Kept out of the argv builder in the linux backend so both ends
// read from one place and cannot drift.
func EncodeLaunch(cfg Config) []string {
	args := []string{SentinelLaunch, "--exec", execModeString(cfg)}
	if cfg.Socket != "" {
		args = append(args, "--socket", cfg.Socket)
	}
	if cfg.ObserveFD > 0 {
		args = append(args, "--observe-fd", strconv.Itoa(cfg.ObserveFD))
	}
	for _, w := range cfg.Writable {
		args = append(args, "--rw", w)
	}
	args = append(args, "--")
	return append(args, cfg.Target...)
}

// DecodeLaunch parses a launch invocation (args[0] is SentinelLaunch) back into a
// Config. It is the inverse of EncodeLaunch. Errors are returned, not printed:
// this runs inside the sandbox where the flag package's default output would land
// on the target's stderr.
func DecodeLaunch(args []string) (Config, error) {
	if len(args) == 0 || args[0] != SentinelLaunch {
		return Config{}, fmt.Errorf("launcher: not a launch invocation")
	}
	fs := flag.NewFlagSet(SentinelLaunch, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		socket    string
		execMode  string
		observeFD int
		writable  stringList
	)
	fs.StringVar(&execMode, "exec", "none", "")
	fs.StringVar(&socket, "socket", "", "")
	fs.IntVar(&observeFD, "observe-fd", 0, "")
	fs.Var(&writable, "rw", "")
	if err := fs.Parse(args[1:]); err != nil {
		return Config{}, fmt.Errorf("launcher: parsing launch invocation: %w", err)
	}
	block, strict, err := parseExecMode(execMode)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Socket:      socket,
		Block:       block,
		StrictBlock: strict,
		Writable:    writable,
		ObserveFD:   observeFD,
		Target:      fs.Args(),
	}, nil
}

// The exec mode is carried on the wire as a string so the codec stays free of the
// policy package (which would pull a domain import into the launcher). The mapping
// round-trips every valid Config (StrictBlock implies Block, per Config's doc). The
// out-of-contract {Block:false, StrictBlock:true} has no representation and would
// otherwise fall through to "all" - the weakest outcome for a config that named a
// strict block - so it panics rather than silently disarm the filter.
func execModeString(cfg Config) string {
	if !cfg.Block && cfg.StrictBlock {
		panic("launcher: StrictBlock set without Block; no exec mode encodes it")
	}
	switch {
	case !cfg.Block:
		return "all"
	case cfg.StrictBlock:
		return "none-strict"
	default:
		return "none"
	}
}

func parseExecMode(mode string) (block, strict bool, err error) {
	switch mode {
	case "all":
		return false, false, nil
	case "none":
		return true, false, nil
	case "none-strict":
		return true, true, nil
	default:
		return false, false, fmt.Errorf("launcher: unknown exec mode %q", mode)
	}
}

// stringList is a repeatable string flag; the flag package has no built-in for it.
type stringList []string

func (s *stringList) String() string { return fmt.Sprint([]string(*s)) }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
