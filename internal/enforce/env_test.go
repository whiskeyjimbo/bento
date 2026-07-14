package enforce

import (
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// fakeHost is an in-memory stand-in for the host environment.
func fakeHost(vars map[string]string) Lookup {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

func TestResolveEnvPassesOnlyAllowlistedNames(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Env: []string{"LANG"}}
	host := fakeHost(map[string]string{"LANG": "C", "AWS_SECRET_ACCESS_KEY": "shhh"})

	env, unset, err := ResolveEnv(p, nil, host)
	if err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}
	if env["LANG"] != "C" {
		t.Errorf("LANG = %q, want C", env["LANG"])
	}
	if _, leaked := env["AWS_SECRET_ACCESS_KEY"]; leaked {
		t.Error("a host variable the policy never allowed was passed to the sandbox")
	}
	if len(unset) != 0 {
		t.Errorf("unset = %v, want none", unset)
	}
}

func TestResolveEnvOverrideBeatsHost(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Env: []string{"TOKEN"}}
	host := fakeHost(map[string]string{"TOKEN": "from-host"})

	env, _, err := ResolveEnv(p, map[string]string{"TOKEN": "from-flag"}, host)
	if err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}
	if env["TOKEN"] != "from-flag" {
		t.Errorf("TOKEN = %q, want the invocation override to win", env["TOKEN"])
	}
}

// An override for a name the manifest does not allow must be refused: accepting
// it would mean the manifest no longer describes what the script can see.
func TestResolveEnvRejectsOverrideOutsideAllowlist(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Env: []string{"LANG"}}

	_, _, err := ResolveEnv(p, map[string]string{"SECRET": "v"}, fakeHost(nil))
	if err == nil {
		t.Fatal("expected an override outside the allowlist to be refused")
	}
}

// An allowed-but-unset name is reported, not silently passed as "". A script
// reading an empty string fails obscurely; the user needs to be told.
func TestResolveEnvReportsUnsetNames(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Env: []string{"LANG", "MISSING"}}
	host := fakeHost(map[string]string{"LANG": "C"})

	env, unset, err := ResolveEnv(p, nil, host)
	if err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}
	if _, present := env["MISSING"]; present {
		t.Error("an unset name should not be passed as an empty string")
	}
	if len(unset) != 1 || unset[0] != "MISSING" {
		t.Errorf("unset = %v, want [MISSING]", unset)
	}
}
