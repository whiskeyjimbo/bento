package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveInterpreterExtension(t *testing.T) {
	cases := []struct {
		path, want string
	}{
		{"script.py", "python3"},
		{"script.js", "node"},
		{"script.sh", "bash"},
		{"script.rb", "ruby"},
		{"script.pl", "perl"},
		{"SCRIPT.PY", "python3"}, // case-insensitive
	}
	for _, c := range cases {
		got, err := ResolveInterpreter(c.path)
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.path, err)
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.path, got, c.want)
		}
	}
}

func TestResolveInterpreterShebang(t *testing.T) {
	dir := t.TempDir()

	t.Run("env shebang strips /usr/bin/env", func(t *testing.T) {
		p := filepath.Join(dir, "noext-env")
		os.WriteFile(p, []byte("#!/usr/bin/env python3\nprint('hi')\n"), 0o644)
		got, err := ResolveInterpreter(p)
		if err != nil {
			t.Fatal(err)
		}
		if got != "python3" {
			t.Errorf("got %q, want python3", got)
		}
	})

	t.Run("direct shebang preserved", func(t *testing.T) {
		p := filepath.Join(dir, "noext-direct")
		os.WriteFile(p, []byte("#!/bin/sh\necho hi\n"), 0o644)
		got, err := ResolveInterpreter(p)
		if err != nil {
			t.Fatal(err)
		}
		if got != "/bin/sh" {
			t.Errorf("got %q, want /bin/sh", got)
		}
	})

	t.Run("no shebang, no extension errors", func(t *testing.T) {
		p := filepath.Join(dir, "noext-no-shebang")
		os.WriteFile(p, []byte("just some content\n"), 0o644)
		_, err := ResolveInterpreter(p)
		if err == nil || !strings.Contains(err.Error(), "no extension") {
			t.Errorf("expected 'no extension' error, got %v", err)
		}
	})
}

func TestResolveInterpreterUnknownExtension(t *testing.T) {
	_, err := ResolveInterpreter("script.xyz")
	if err == nil {
		t.Fatal("unknown extension should error")
	}
	if !strings.Contains(err.Error(), ".xyz") {
		t.Errorf("error should mention .xyz, got %v", err)
	}
}

func TestPracticalStrictManifest(t *testing.T) {
	m, err := PracticalStrictManifest("./tests/script.py", "python3")
	if err != nil {
		t.Fatal(err)
	}
	if m.Interpreter != "python3" {
		t.Errorf("interpreter: got %q", m.Interpreter)
	}
	if !filepath.IsAbs(m.Script) {
		t.Errorf("script should be absolute, got %q", m.Script)
	}
	if len(m.Read) != 1 || !strings.HasSuffix(m.Read[0], "/tests") {
		t.Errorf("read should be script's dir, got %v", m.Read)
	}
	if len(m.Write) != 0 {
		t.Error("write should be empty (strict)")
	}
	if m.Network != nil {
		t.Error("network should be nil (strict)")
	}
	if len(m.Exec) != 0 {
		t.Error("exec should be empty (strict — blocks subprocesses)")
	}
}

func TestPracticalStrictManifestRequiresInterpreter(t *testing.T) {
	if _, err := PracticalStrictManifest("script.py", ""); err == nil {
		t.Error("empty interpreter should error")
	}
}
