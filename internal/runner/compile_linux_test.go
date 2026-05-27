//go:build linux

package runner

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

func TestAppendBaseFlags(t *testing.T) {
	args := appendBaseFlags(nil, nil)
	// Must include the unshare flags + tmpfs + chdir; order matters less than presence.
	required := []string{
		"--die-with-parent",
		"--unshare-user",
		"--unshare-pid",
		"--tmpfs",
		spec.SandboxRoot,
		"--clearenv",
	}
	for _, want := range required {
		if !slices.Contains(args, want) {
			t.Errorf("appendBaseFlags missing %q in %v", want, args)
		}
	}
}

func TestAppendNetworkNamespace(t *testing.T) {
	t.Run("nil network unshares", func(t *testing.T) {
		args := appendNetworkNamespace(nil, &spec.Manifest{}, &auxiliary{networkMode: spec.NetworkModeLandlock})
		if !slices.Contains(args, "--unshare-net") {
			t.Errorf("nil Network should emit --unshare-net, got %v", args)
		}
	})
	t.Run("network set does not unshare in landlock mode", func(t *testing.T) {
		args := appendNetworkNamespace(nil, &spec.Manifest{Network: &spec.NetworkPerm{}}, &auxiliary{networkMode: spec.NetworkModeLandlock})
		if slices.Contains(args, "--unshare-net") {
			t.Errorf("non-nil Network in landlock should NOT emit --unshare-net, got %v", args)
		}
	})
	t.Run("network set DOES unshare in bridge mode", func(t *testing.T) {
		args := appendNetworkNamespace(nil, &spec.Manifest{Network: &spec.NetworkPerm{}}, &auxiliary{networkMode: spec.NetworkModeBridge})
		if !slices.Contains(args, "--unshare-net") {
			t.Errorf("bridge mode should always emit --unshare-net, got %v", args)
		}
	})
}

func TestAppendUserReadPaths(t *testing.T) {
	args := appendUserReadPaths(nil, []string{"/etc/hostname", "/tmp/data"})
	// Each path should appear as --ro-bind-try ABS ABS.
	if countOccurrences(args, "--ro-bind-try") != 2 {
		t.Errorf("expected 2 --ro-bind-try entries, got %d in %v", countOccurrences(args, "--ro-bind-try"), args)
	}
	if !slices.Contains(args, "/etc/hostname") {
		t.Errorf("missing /etc/hostname in %v", args)
	}
}

func TestAppendUserWritePaths(t *testing.T) {
	args := appendUserWritePaths(nil, []string{"/tmp/out"})
	if countOccurrences(args, "--bind-try") != 1 {
		t.Errorf("expected 1 --bind-try entry, got %d in %v", countOccurrences(args, "--bind-try"), args)
	}
}

func TestAppendUserEnv(t *testing.T) {
	t.Setenv("BENTO_TEST_VAR", "yes")
	args := appendUserEnv(nil, []string{"BENTO_TEST_VAR", "BENTO_MISSING_VAR"})
	// Only the set one should propagate.
	if !containsAdjacent(args, "--setenv", "BENTO_TEST_VAR", "yes") {
		t.Errorf("expected BENTO_TEST_VAR=yes, got %v", args)
	}
	if slices.Contains(args, "BENTO_MISSING_VAR") {
		t.Errorf("BENTO_MISSING_VAR was not set on host; should not appear; got %v", args)
	}
}

func TestAppendExtraEnv(t *testing.T) {
	args := appendExtraEnv(nil, map[string]string{"KEY": "value"})
	if !containsAdjacent(args, "--setenv", "KEY", "value") {
		t.Errorf("expected KEY=value, got %v", args)
	}
	// Nil and empty maps should be no-ops.
	if len(appendExtraEnv(nil, nil)) != 0 {
		t.Error("appendExtraEnv with nil map should be a no-op")
	}
	if len(appendExtraEnv(nil, map[string]string{})) != 0 {
		t.Error("appendExtraEnv with empty map should be a no-op")
	}
}

func TestAppendScriptBinding(t *testing.T) {
	args := appendScriptBinding(nil, "/home/user/script.py")
	if !containsAdjacent(args, "--ro-bind", "/home/user/script.py", spec.SandboxScriptPath) {
		t.Errorf("expected script bind, got %v", args)
	}
}

func TestAppendEntrypointWithLauncher(t *testing.T) {
	aux := &auxiliary{launcherPath: "/tmp/launcher"}
	args := appendEntrypoint(nil, "/usr/bin/python3", "/tmp/s.py", aux, nil)
	// Launcher path: bwrap exec's launcher, which exec's interpreter.
	if !containsAdjacent(args, "--", spec.SandboxLauncherPath, "/usr/bin/python3", spec.SandboxScriptPath) {
		t.Errorf("expected launcher entrypoint, got %v", args)
	}
}

func TestAppendEntrypointWithoutLauncher(t *testing.T) {
	aux := &auxiliary{} // no launcher
	args := appendEntrypoint(nil, "/usr/bin/python3", "/tmp/s.py", aux, nil)
	if !containsAdjacent(args, "--", "/usr/bin/python3", spec.SandboxScriptPath) {
		t.Errorf("expected direct entrypoint, got %v", args)
	}
}

func TestAppendEntrypointELFBinaryDoesNotInjectScriptArg(t *testing.T) {
	// ELF mode: interp == scriptAbs (binary is its own interpreter). The
	// launcher must receive only the sandbox script path so argv[0] is
	// /sandbox/script and no spurious argv[1] is injected.
	aux := &auxiliary{launcherPath: "/tmp/launcher"}
	args := appendEntrypoint(nil, "/tmp/hello-go", "/tmp/hello-go", aux, []string{"a", "b"})
	if !containsAdjacent(args, "--", spec.SandboxLauncherPath, spec.SandboxScriptPath, "a") {
		t.Errorf("ELF launcher entrypoint should be `-- launcher /sandbox/script a b`, got %v", args)
	}
	for _, a := range args {
		if a == "/tmp/hello-go" {
			t.Errorf("ELF entrypoint should not pass the host binary path, got %v", args)
		}
	}
}

func TestAppendEntrypointELFBinaryNoLauncher(t *testing.T) {
	aux := &auxiliary{} // no launcher
	args := appendEntrypoint(nil, "/tmp/hello-go", "/tmp/hello-go", aux, []string{"a"})
	if !containsAdjacent(args, "--", spec.SandboxScriptPath, "a") {
		t.Errorf("ELF no-launcher entrypoint should be `-- /sandbox/script a`, got %v", args)
	}
	for _, a := range args {
		if a == "/tmp/hello-go" {
			t.Errorf("ELF entrypoint should not pass the host binary path, got %v", args)
		}
	}
}

func TestCompileBwrapArgsOrdering(t *testing.T) {
	// Smoke test: full pipeline produces a coherent argv.
	c := compileCtx{
		manifest: &spec.Manifest{
			Interpreter: "python3",
			Script:      "/tmp/s.py",
			Args:        []string{"--flag", "value"},
		},
		interp:    "/usr/bin/python3",
		scriptAbs: "/tmp/s.py",
		aux:       &auxiliary{}, // no proxies, no launcher
		extraEnv:  map[string]string{"X": "1"},
	}
	args, _ := compileBwrapArgs(c)
	if !strings.HasPrefix(args[0], "--") {
		t.Errorf("first arg should be a bwrap flag, got %q", args[0])
	}
	// Manifest.Args should be at the very end.
	if !reflect.DeepEqual(args[len(args)-2:], []string{"--flag", "value"}) {
		t.Errorf("manifest Args should be at end, got %v", args[len(args)-2:])
	}
	// extraEnv must appear.
	if !containsAdjacent(args, "--setenv", "X", "1") {
		t.Error("extraEnv X=1 not present")
	}
	// Network is nil → unshare-net.
	if !slices.Contains(args, "--unshare-net") {
		t.Error("nil Network should emit --unshare-net")
	}
}

func TestWrapWithLimitsNoOp(t *testing.T) {
	exe, args := wrapWithLimits(nil, "bwrap", []string{"--proc", "/proc"}, &Config{})
	if exe != "bwrap" {
		t.Errorf("nil Limits should not wrap, got exe=%q", exe)
	}
	if len(args) != 2 {
		t.Errorf("nil Limits should preserve args, got %v", args)
	}
}

func TestInterpreterPrefix(t *testing.T) {
	cases := []struct {
		name, interp, want string
	}{
		{"system path returns empty", "/usr/bin/python3", ""},
		{"bin path returns empty", "/bin/sh", ""},
		// Non-system paths walk up two levels. EvalSymlinks may fail for
		// fake paths; the function returns "" in that case, which is the
		// only behavior we can test portably without setting up real
		// directory trees.
		{"nonexistent returns empty", "/nonexistent/path/bin/foo", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := interpreterPrefix(c.interp); got != c.want {
				t.Errorf("interpreterPrefix(%q) = %q, want %q", c.interp, got, c.want)
			}
		})
	}
}

// --- helpers ---

func countOccurrences(args []string, want string) int {
	n := 0
	for _, a := range args {
		if a == want {
			n++
		}
	}
	return n
}

func containsAdjacent(args []string, seq ...string) bool {
	if len(seq) == 0 {
		return true
	}
	for i := 0; i <= len(args)-len(seq); i++ {
		match := true
		for j, s := range seq {
			if args[i+j] != s {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
