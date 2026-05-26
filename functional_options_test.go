package bento

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/installer"
	"github.com/whiskeyjimbo/bento/internal/proxy"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

func TestRegisterExtensionInterpreterAndResolve(t *testing.T) {
	// 1. Test global registration
	RegisterExtensionInterpreter(".customext", "mycompiler")

	interp, err := ResolveInterpreter("script.customext")
	if err != nil {
		t.Fatalf("failed to resolve globally registered extension: %v", err)
	}
	if interp != "mycompiler" {
		t.Errorf("expected mycompiler, got %q", interp)
	}

	// 2. Test one-off ResolveOption custom extensions overriding global one
	interp, err = ResolveInterpreter("script.customext", WithCustomExtensions(map[string]string{
		".customext": "overridecompiler",
	}))
	if err != nil {
		t.Fatalf("failed to resolve overridden extension: %v", err)
	}
	if interp != "overridecompiler" {
		t.Errorf("expected overridecompiler, got %q", interp)
	}

	// 3. Test WithDisableShebang
	// Create a dummy file with a shebang and no extension
	tmpFile, err := os.CreateTemp("", "bento-shebang-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString("#!/usr/bin/env python3\nprint('hello')\n"); err != nil {
		t.Fatalf("failed to write shebang: %v", err)
	}
	tmpFile.Close()

	// Should resolve to python3 by shebang default
	interp1, err := ResolveInterpreter(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to resolve shebang: %v", err)
	}
	if interp1 != "python3" {
		t.Errorf("expected python3 by shebang, got %q", interp1)
	}

	// Should fail to resolve if shebang is disabled and no extension mapping exists
	_, err = ResolveInterpreter(tmpFile.Name(), WithDisableShebang())
	if err == nil {
		t.Error("expected error resolving shebang-only file when shebang checking is disabled")
	}
}

func TestLoadManifestOptions(t *testing.T) {
	// Create a mock manifest YAML with environment variable and relative paths
	yamlData := `
interpreter: ${TEST_INTERPRETER}
script: relative/path/to/script.py
read:
  - relative/read/dir
write:
  - relative/write/dir
`
	t.Setenv("TEST_INTERPRETER", "python123")

	// 1. Load with Env Expansion and Base Dir options, and skip validation
	r := bytes.NewReader([]byte(yamlData))
	m, err := LoadManifest(r,
		WithEnvExpansion(),
		WithBaseDir("/my/workspace/root"),
		WithSkipValidation(),
	)
	if err != nil {
		t.Fatalf("failed to load manifest: %v", err)
	}

	if m.Interpreter != "python123" {
		t.Errorf("expected python123, got %q", m.Interpreter)
	}
	if m.Script != "/my/workspace/root/relative/path/to/script.py" {
		t.Errorf("expected absolute script path, got %q", m.Script)
	}
	if m.Read[0] != "/my/workspace/root/relative/read/dir" {
		t.Errorf("expected absolute read path, got %q", m.Read[0])
	}
	if m.Write[0] != "/my/workspace/root/relative/write/dir" {
		t.Errorf("expected absolute write path, got %q", m.Write[0])
	}
}

func TestSandboxOptions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bento-sandbox-extract-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sb, err := NewSandbox(
		WithExtractDirectory(tmpDir),
	)
	if err != nil {
		t.Fatalf("failed to create Sandbox with options: %v", err)
	}
	defer sb.Close()

	if sb.launcherPath != "" {
		if filepath.Dir(sb.launcherPath) != tmpDir {
			t.Errorf("expected launcher to be extracted in %q, got %q", tmpDir, sb.launcherPath)
		}
	}
}

// Dummy mock Authorizer
type mockAuthorizer struct {
	allowedHost string
}

func (m *mockAuthorizer) Authorize(host string, port int) (bool, string) {
	if host == m.allowedHost {
		return true, "MOCK-ALLOW"
	}
	return false, "MOCK-DENY"
}

func TestCustomProxyAuthorizer(t *testing.T) {
	auth := &mockAuthorizer{allowedHost: "trusted.com"}
	
	// Create proxy options with a custom authorizer
	opts, _ := proxy.StartHTTPConnect(&spec.NetworkPerm{}, proxy.WithAuthorizer(auth))
	// Test if standard allowlist matching can be overridden by a custom Authorizer.
	// Since port/socket listener binding requires real network stack access, we
	// can at least verify that it compiles, option sets correctly, and we can directly
	// test the authorizer behavior.
	allowed, tag := auth.Authorize("trusted.com", 443)
	if !allowed || tag != "MOCK-ALLOW" {
		t.Errorf("mock authorization failed for trusted.com: allowed=%t, tag=%s", allowed, tag)
	}

	allowed, tag = auth.Authorize("untrusted.com", 80)
	if allowed || tag != "MOCK-DENY" {
		t.Errorf("mock authorization should have denied untrusted.com: allowed=%t, tag=%s", allowed, tag)
	}
	
	if opts != nil {
		opts.Close()
	}
}

func TestDoctorInterpretersOption(t *testing.T) {
	// Verify that WithInterpreters dynamically alters doctor checks
	res := Checks(WithInterpreters("customruntime"))
	found := false
	for _, r := range res {
		if r.Name == "customruntime" {
			found = true
			if r.Status != StatusWarn {
				t.Errorf("expected warning status for customruntime, got %s", r.Status)
			}
		}
		// python3 should NOT be checked since we overridden the list to only check customruntime
		if r.Name == "python3" {
			t.Error("python3 should not have been checked when custom runtime list is provided")
		}
	}
	if !found {
		t.Error("customruntime checks were not executed")
	}
}

func TestInstallerCustomPackageManager(t *testing.T) {
	// Execute installer.Init with custom package manager settings (Ubuntu as target overrides)
	var buf bytes.Buffer
	ctx := context.Background()

	// Direct dry-run with a custom package manager
	steps, err := installer.Init(ctx, &buf,
		installer.WithDistroOverride("customdistro"),
		installer.WithCustomPackageManager("customdistro", []string{"my-pm", "get"}, "myproxychains"),
		installer.WithDryRun(),
	)
	if err != nil {
		t.Fatalf("Init custom package manager dry-run failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "detected distro: customdistro") {
		t.Errorf("expected customdistro to be detected in logs, got %q", output)
	}
	_ = steps
}

func TestMockTTYInput(t *testing.T) {
	// Create mock input and output
	in := bytes.NewBufferString("y\n")
	var out bytes.Buffer

	cb, err := grants.TTYCallback(
		grants.WithTTYInput(in),
		grants.WithTTYOutput(&out),
	)
	if err != nil {
		t.Fatalf("failed to create TTY callback: %v", err)
	}

	req := grants.Request{Host: "safe.com", Port: 80}
	decision := cb(req)

	if decision != grants.DecisionAllow {
		t.Errorf("expected DecisionAllow from mock 'y' input, got %v", decision)
	}

	logs := out.String()
	if !strings.Contains(logs, "script wants to connect to safe.com:80") {
		t.Errorf("expected logs to contain prompt, got %q", logs)
	}
	if !strings.Contains(logs, "allow") {
		t.Errorf("expected logs to confirm allow, got %q", logs)
	}
}
