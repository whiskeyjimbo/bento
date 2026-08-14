package enforce

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/whiskeyjimbo/bento/policy"
)

// Lookup reads a variable from the host environment. It is a seam so env
// resolution can be tested without touching the real environment.
type Lookup func(name string) (string, bool)

// SandboxHome is the HOME a target sees under a full-isolation run when the policy does
// not pass one through: the sandbox's own tmpfs, never the caller's home, so a script that
// writes dotfiles cannot reach the real one. It lives here rather than in the backend that
// sets it because a frontend has to be able to state it before a run - `~` in the target's
// own code means this, and a reader who has to learn that from a traceback naming a path
// they never wrote is debugging the wrong thing.
//
// The literal holds on a tier with a mount namespace and nowhere else. A backend without
// one cannot make /tmp the sandbox's own, so it substitutes a private scratch directory of
// its own choosing and HOME is that instead: what carries across the tiers is that HOME is
// writable and is not the caller's, which is what a manifest depends on. A frontend
// speaking ahead of a run therefore leads with this and says the fallback exists.
const SandboxHome = "/tmp"

// SandboxPath is the PATH a target sees when the policy does not pass one through. It
// is fixed rather than inherited so a manifest resolves the same commands on every
// machine, which is the whole point of one - but it also means a tool the caller's
// shell finds outside these two directories is simply not there, and a bare-name
// invocation of it fails the way a missing file does. Exported for the same reason
// SandboxHome is: a frontend has to be able to say so before a run, because the shell's
// own "not found" names the command and never the search path that lost it.
const SandboxPath = "/usr/bin:/bin"

// BaseImageDirs are the host directories every sandbox carries whatever the tier - the
// bwrap tier ro-binds them, the degraded tier grants them to Landlock - so an interpreter
// finds its runtime and its CA bundle without the manifest naming any of it. They are the
// host's own trees rather than an image's, so a command found under one of them resolves
// inside the box to the exact binary the caller resolves.
//
// Exported for the reason SandboxPath is, and it is the same answer read from the other
// side: a frontend saying what the box does NOT carry has to know what it does, and the
// alternative is a second list that drifts from the mounts. The backend's read set adds
// the individual /etc loader and CA files to these; nothing on PATH lives there.
var BaseImageDirs = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}

// InBaseImage reports whether path is carried into the box by BaseImageDirs, and so needs
// no grant to be reachable there.
func InBaseImage(path string) bool {
	for _, dir := range BaseImageDirs {
		if path == dir || strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}

// InterpreterPrefix returns the install root of an interpreter that lives outside the
// system paths (e.g. ~/.pyenv/versions/3.12/bin/python3 → ~/.pyenv/versions/3.12), so its
// stdlib comes along. System interpreters are already covered by the backend's system read
// paths and return "".
//
// Here rather than in the backend that binds it, for the reason SandboxPath is: a frontend
// has to be able to state what the box carries before and after a run. A run naming its
// interpreter under the caller's home gets that prefix bound with no grant naming it, so a
// frontend warning about an ungranted directory has to know not to warn about this one -
// and answering that with a second copy of this rule is how the warning and the bind come
// to disagree. The backend still decides whether to bind it (a prefix too broad to hand
// over gets the file alone); this answers only where the interpreter's install root is.
func InterpreterPrefix(interp string) string {
	if interp == "" {
		return ""
	}
	if InBaseImage(interp) {
		return ""
	}
	// .../bin/python3 → ...
	dir := filepath.Dir(interp)
	if filepath.Base(dir) == "bin" {
		return filepath.Dir(dir)
	}
	return dir
}

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
