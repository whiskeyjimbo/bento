package denylist

import (
	"path/filepath"
	"testing"
)

// relocationEnvs is every variable Relocated consults, gathered from the tables rather
// than listed, so a variable added to one of them is driven by the assertions below
// without anyone remembering to add it here.
func relocationEnvs() []string {
	var out []string
	for _, b := range xdgBases {
		out = append(out, b.env)
	}
	for _, d := range dirEnvs {
		out = append(out, d.env)
	}
	for _, d := range dirFileEnvs {
		out = append(out, d.env)
	}
	for _, f := range fileEnvs {
		out = append(out, f.env)
	}
	for _, f := range fileDenyAllEnvs {
		out = append(out, f.env)
	}
	out = append(out, startupFileEnvs...)
	for _, s := range startupDefaultEnvs {
		out = append(out, s.env)
	}
	for _, d := range dirSubEnvs {
		out = append(out, d.env)
	}
	for _, d := range writeOnlyDirEnvs {
		out = append(out, d.env)
	}
	return append(out, "HGRCPATH", "ZDOTDIR", "GIT_CONFIG_GLOBAL", "PIP_CONFIG_FILE",
		"MAILCAPS", "CARGO_HOME", "COMPOSER_HOME", "GOBIN", "GOPATH")
}

// Every relocation a variable can name is absolute, shieldable, not a restatement of a
// default, and not interior to a default DenyAll tree - asserted per variable rather
// than per emitter block, because the blocks share these four guards and a new block
// that forgets one would otherwise only be caught by whoever reads it.
func TestEveryRelocationTargetIsAbsoluteShieldableAndNotADefault(t *testing.T) {
	const home = "/home/u"
	anchors := []string{home}
	defaults := Home(home)
	defaultPath := map[string]bool{}
	for _, r := range defaults {
		defaultPath[r.Path] = true
	}

	envs := relocationEnvs()
	for _, e := range envs {
		t.Setenv(e, "")
	}

	values := map[string]string{
		"relative":       "relocated/store",
		"bare":           "store",
		"dotted":         "./store",
		"parent":         "../store",
		"root":           "/",
		"anchor":         home,
		"anchor-trailer": home + "/",
	}

	for _, e := range envs {
		for name, v := range values {
			t.Run(e+"/"+name, func(t *testing.T) {
				t.Setenv(e, v)
				for _, r := range Relocated(defaults, anchors) {
					if !filepath.IsAbs(r.Path) {
						t.Errorf("IsAbs: %s=%q emitted relative rule %q (source %s); a bwrap bind cannot shield it", e, v, r.Path, r.Source)
					}
					if !Shieldable(r.Path, anchors) {
						t.Errorf("shieldable: %s=%q emitted unshieldable rule %q (source %s)", e, v, r.Path, r.Source)
					}
					if defaultPath[r.Path] {
						t.Errorf("isDefault: %s=%q restated default rule %q (source %s)", e, v, r.Path, r.Source)
					}
					if underDenyAll(r.Path, defaults) {
						t.Errorf("interior rule: %s=%q emitted %q inside a default DenyAll tree (source %s)", e, v, r.Path, r.Source)
					}
				}
			})
		}
	}
}
