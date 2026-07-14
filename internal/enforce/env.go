package enforce

import (
	"fmt"
	"sort"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// Lookup reads a variable from the host environment. It is a seam so env
// resolution can be tested without touching the real environment.
type Lookup func(name string) (string, bool)

// ResolveEnv turns the policy's allowlist of variable NAMES into the concrete
// values the target will see.
//
// This is core policy work, not a backend detail: a backend receives a finished
// map and decides nothing about it. Values come from the host only for names the
// policy allowed through; overrides supplied at invocation (--env NAME=VALUE) win
// over the host, so a caller can inject a value without exporting it. An
// override for a name the policy did not allow is an error rather than a silent
// pass-through — otherwise the manifest would no longer describe what the script
// can see.
//
// A name that is allowed but unset on the host is reported in `unset` rather than
// passed as an empty string, so a frontend can tell the user why their script saw
// nothing instead of letting it fail obscurely.
func ResolveEnv(p *policy.Policy, overrides map[string]string, lookup Lookup) (env map[string]string, unset []string, err error) {
	allowed := make(map[string]bool, len(p.Env))
	for _, name := range p.Env {
		allowed[name] = true
	}
	for name := range overrides {
		if !allowed[name] {
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
	sort.Strings(unset)
	return env, unset, nil
}
