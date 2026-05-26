package spec

import (
	"strings"
	"testing"
)

func TestManifestValidate(t *testing.T) {
	good := &Manifest{Interpreter: "python3", Script: "./s.py"}
	if err := good.Validate(); err != nil {
		t.Errorf("minimal good manifest should pass, got %v", err)
	}

	cases := []struct {
		name string
		m    *Manifest
		want string // substring of error
	}{
		{"nil", nil, "cannot be nil"},
		{"missing interpreter", &Manifest{Script: "./s.py"}, "interpreter: required"},
		{"missing script", &Manifest{Interpreter: "python3"}, "script: required"},
		{
			"bad port",
			&Manifest{
				Interpreter: "python3", Script: "s.py",
				Network: &NetworkPerm{Rules: []NetworkRule{{Host: "x", Port: "abc"}}},
			},
			"port: \"abc\" is not a valid TCP port",
		},
		{
			"port out of range",
			&Manifest{
				Interpreter: "python3", Script: "s.py",
				Network: &NetworkPerm{Rules: []NetworkRule{{Host: "x", Port: "99999"}}},
			},
			"not a valid TCP port",
		},
		{
			"bad port range",
			&Manifest{
				Interpreter: "python3", Script: "s.py",
				Network: &NetworkPerm{Rules: []NetworkRule{{Host: "x", Port: "9000-100"}}},
			},
			"inverted",
		},
		{
			"missing host",
			&Manifest{
				Interpreter: "python3", Script: "s.py",
				Network: &NetworkPerm{Rules: []NetworkRule{{Port: "443"}}},
			},
			"host: required",
		},
		{
			"bad memory",
			&Manifest{
				Interpreter: "python3", Script: "s.py",
				Limits: &Limits{Memory: "abc"},
			},
			"memory:",
		},
		{
			"bad CPU (no %)",
			&Manifest{
				Interpreter: "python3", Script: "s.py",
				Limits: &Limits{CPU: "100"},
			},
			"cpu:",
		},
		{
			"negative tasks",
			&Manifest{
				Interpreter: "python3", Script: "s.py",
				Limits: &Limits{Tasks: -1},
			},
			"tasks:",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.m.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("expected error containing %q, got %q", c.want, err.Error())
			}
		})
	}
}
