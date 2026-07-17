// Command embed hosts bento's enforcement backend in-process, using only bento's
// public packages - backend, enforce, manifest - and nothing under internal/. It
// takes a manifest path, runs the script it describes under the sandbox, prints
// any enforcement shortfall from the structured Result, and passes the target's
// exit code through.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/whiskeyjimbo/bento-v2/backend"
	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/manifest"
)

func main() {
	// To confine a target the backend re-executes THIS binary inside the sandbox
	// as a hidden stage, so dispatch that before anything else in main - any
	// earlier flag parsing or side effect would run in the wrong context, and a
	// normal invocation falls straight through. Because the whole binary re-runs
	// inside the sandbox under a cleared environment, keep package init cheap and
	// free of environment or other side-effect dependencies.
	backend.DispatchReexec()

	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: embed <manifest.yaml>")
		os.Exit(2)
	}
	os.Exit(run(os.Args[1]))
}

func run(manifestPath string) int {
	f, err := os.Open(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}
	defer f.Close()

	// manifest.Load -> a validated *policy.Policy. The whole enforcement API takes
	// domain values like this; a library embedder never shells out or parses CLI
	// text.
	policy, err := manifest.Load(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}

	// The policy names which env vars may pass through; resolving those names
	// against the host is the core's job, exposed here so the values a target sees
	// are explicit.
	env, _, err := enforce.ResolveEnv(policy, nil, os.LookupEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}

	e, err := backend.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}

	proc := enforce.Process{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Env: env}
	res, err := enforce.Run(context.Background(), e, policy, proc, enforce.Options{})

	var refusal *enforce.Refusal
	switch {
	case errors.As(err, &refusal):
		// The host cannot enforce a guarantee the policy needs; Refusal names which.
		fmt.Fprintf(os.Stderr, "embed: refused: %s\n", refusal.Reason)
		return 125
	case err != nil:
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 125
	}

	// A structured Result, not scraped output: report what the host could only
	// partially enforce, then pass the target's own exit code through.
	for _, d := range res.Report.Degradations() {
		fmt.Fprintf(os.Stderr, "embed: degraded: %s (%s): %s\n", d.Layer, d.State, d.Reason)
	}
	return res.ExitCode
}
