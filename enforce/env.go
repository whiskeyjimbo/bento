package enforce

import (
	"fmt"
	"slices"

	"github.com/whiskeyjimbo/bento/policy"
)

// Lookup reads a variable from the host environment. It is a seam so env
// resolution can be tested without touching the real environment.
type Lookup func(name string) (string, bool)

// SandboxHome is the HOME a target sees when the policy does not pass one through: the
// sandbox's own tmpfs, never the caller's home, so a script that writes dotfiles cannot
// reach the real one. It lives here rather than in the backend that sets it because a
// frontend has to be able to state it before a run - `~` in the target's own code means
// this, and a reader who has to learn that from a traceback naming a path they never
// wrote is debugging the wrong thing.
const SandboxHome = "/tmp"

// ResolveEnv turns the policy's allowlist of variable NAMES into the concrete
// values the target will see.
//
// This is core policy work, not a backend detail: a backend receives a finished
// map and decides nothing about it. Values come from the host only for names the
// policy allowed through; overrides supplied at invocation (--env NAME=VALUE) win
// over the host, so a caller can inject a value without exporting it. An
// override for a name the policy did not allow is an error rather than a silent
// pass-through - otherwise the manifest would no longer describe what the script
// can see.
//
// A name that is allowed but unset on the host is reported in `unset` rather than
// passed as an empty string, so a frontend can tell the user why their script saw
// nothing instead of letting it fail obscurely.
func ResolveEnv(p *policy.Policy, overrides map[string]string, lookup Lookup) (env map[string]string, unset []string, err error) {
	// Reported rather than defaulted to an always-missing lookup: that would resolve
	// every allowed name to unset and hand the target an empty environment, which reads
	// to the caller as "the host has none of these" instead of "you passed no seam".
	if lookup == nil {
		return nil, nil, fmt.Errorf("enforce: nil Lookup; pass os.LookupEnv to read the host environment")
	}
	// Refused rather than read as an empty allowlist: that would resolve to an empty
	// environment and no override error, so a caller who lost their policy would get a
	// plausible-looking result instead of being told.
	if p == nil {
		return nil, nil, fmt.Errorf("enforce: nil Policy; env resolution has no allowlist to work from")
	}
	for name := range overrides {
		if !slices.Contains(p.Env, name) {
			return nil, nil, fmt.Errorf("--env %s: %q is not in the manifest's env allowlist; add it to `env:` so the manifest still describes what the script can see", name, name)
		}
	}

	env = make(map[string]string, len(p.Env))
	for _, name := range p.Env {
		if v, ok := overrides[name]; ok {
			env[name] = v
			continue
		}
		if v, ok := lookup(name); ok {
			env[name] = v
			continue
		}
		unset = append(unset, name)
	}
	slices.Sort(unset)
	return env, unset, nil
}
