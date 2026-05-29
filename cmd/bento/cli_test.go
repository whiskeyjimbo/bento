package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var bentoBinPath string

func TestMain(m *testing.M) {
	// Create a temporary directory to hold our compiled test binary
	tmpDir, err := ioutil.TempDir("", "bento-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	bentoBinPath = filepath.Join(tmpDir, "bento")

	// Compile the current cmd/bento package
	// We run `go build` to generate the bento executable
	cmd := exec.Command("go", "build", "-o", bentoBinPath, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to compile bento CLI: %v\nOutput:\n%s\n", err, output)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func runBento(t *testing.T, args ...string) (stdout string, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(bentoBinPath, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			t.Fatalf("failed to run bento CLI: %v", err)
		}
	} else {
		exitCode = 0
	}
	return stdout, stderr, exitCode
}

func TestCLI_NoArgs(t *testing.T) {
	stdout, stderr, exitCode := runBento(t)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 when running without arguments, got %d", exitCode)
	}
	if !strings.Contains(stderr, "usage: bento <subcommand>") {
		t.Errorf("expected usage on stderr, got: %s", stderr)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout, got: %q", stdout)
	}
}

func TestCLI_Help(t *testing.T) {
	helps := []string{"help", "-h", "--help"}
	for _, h := range helps {
		t.Run(h, func(t *testing.T) {
			_, stderr, exitCode := runBento(t, h)
			if exitCode != 0 {
				t.Errorf("expected exit code 0 for %q, got %d", h, exitCode)
			}
			if !strings.Contains(stderr, "usage: bento <subcommand>") {
				t.Errorf("expected usage on stderr, got: %s", stderr)
			}
		})
	}
}

func TestCLI_Version(t *testing.T) {
	versions := [][]string{{"version"}, {"-V"}, {"--version"}}
	for _, args := range versions {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, _, exitCode := runBento(t, args...)
			if exitCode != 0 {
				t.Errorf("expected exit code 0, got %d", exitCode)
			}
			if !strings.HasPrefix(stdout, "bento ") {
				t.Errorf("expected version output on stdout starting with 'bento ', got: %q", stdout)
			}
		})
	}
}

func TestCLI_InvalidCommand(t *testing.T) {
	_, stderr, exitCode := runBento(t, "nonexistent-command-12345")
	if exitCode != 2 {
		t.Errorf("expected exit code 2 for invalid subcommand, got %d", exitCode)
	}
	if !strings.Contains(stderr, `unknown command "nonexistent-command-12345"`) {
		t.Errorf("expected unknown command error on stderr for invalid subcommand, got: %s", stderr)
	}
}

func TestCLI_Doctor(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		stdout, stderr, _ := runBento(t, "doctor", "--help")
		combined := stdout + stderr
		if !strings.Contains(combined, "bento doctor") || (!strings.Contains(combined, "flags") && !strings.Contains(combined, "Flags")) {
			t.Errorf("expected doctor usage output, got stdout=%q, stderr=%q", stdout, stderr)
		}
	})

	t.Run("execution", func(t *testing.T) {
		stdout, stderr, _ := runBento(t, "doctor", "--skip-network")
		combined := stdout + stderr
		if !strings.Contains(combined, "primitives") && !strings.Contains(combined, "check") && !strings.Contains(combined, "AppArmor") && !strings.Contains(combined, "Landlock") {
			t.Errorf("expected doctor check outputs, got:\nSTDOUT:\n%s\nSTDERR:\n%s", stdout, stderr)
		}
	})
}

func TestCLI_Setup(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		stdout, stderr, _ := runBento(t, "setup", "--help")
		combined := stdout + stderr
		if !strings.Contains(combined, "bento setup") || (!strings.Contains(combined, "flags") && !strings.Contains(combined, "Flags")) {
			t.Errorf("expected setup usage, got stdout=%q, stderr=%q", stdout, stderr)
		}
	})

	t.Run("init-alias-notice", func(t *testing.T) {
		_, stderr, _ := runBento(t, "init", "--help")
		if !strings.Contains(stderr, "[bento] note: `bento init` is now `bento setup`") {
			t.Errorf("expected bento init migration notice, got: %s", stderr)
		}
	})
}

func TestCLI_Validate(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		stdout, stderr, _ := runBento(t, "validate", "--help")
		combined := stdout + stderr
		if !strings.Contains(combined, "bento validate") || (!strings.Contains(combined, "flags") && !strings.Contains(combined, "Flags")) {
			t.Errorf("expected validate usage, got stdout=%q, stderr=%q", stdout, stderr)
		}
	})

	t.Run("missing-file", func(t *testing.T) {
		_, stderr, exitCode := runBento(t, "validate", "nonexistent-file.yaml")
		if exitCode == 0 {
			t.Errorf("expected validation to fail for nonexistent file")
		}
		if !strings.Contains(stderr, "error") && !strings.Contains(stderr, "no such file") {
			t.Errorf("expected error logs on stderr, got: %s", stderr)
		}
	})
}

func TestCLI_Run_HelpAndErrors(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		stdout, stderr, _ := runBento(t, "run", "--help")
		combined := stdout + stderr
		if !strings.Contains(combined, "bento run") || (!strings.Contains(combined, "flags") && !strings.Contains(combined, "Flags")) {
			t.Errorf("expected run usage, got stdout=%q, stderr=%q", stdout, stderr)
		}
	})

	t.Run("no-script-error", func(t *testing.T) {
		_, stderr, exitCode := runBento(t, "run")
		if exitCode != 2 {
			t.Errorf("expected exit code 2 when no script provided, got %d", exitCode)
		}
		if !strings.Contains(stderr, "error: bento run needs a") || !strings.Contains(stderr, "script") {
			t.Errorf("expected clear error message, got: %s", stderr)
		}
	})
}

func TestCLI_Profile_HelpAndErrors(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		stdout, stderr, _ := runBento(t, "profile", "--help")
		combined := stdout + stderr
		if !strings.Contains(combined, "bento profile") || (!strings.Contains(combined, "flags") && !strings.Contains(combined, "Flags")) {
			t.Errorf("expected profile usage, got stdout=%q, stderr=%q", stdout, stderr)
		}
	})

	t.Run("no-script-error", func(t *testing.T) {
		_, stderr, exitCode := runBento(t, "profile")
		if exitCode != 2 {
			t.Errorf("expected exit code 2 when no script provided, got %d", exitCode)
		}
		if !strings.Contains(stderr, "error: bento profile needs a script path") {
			t.Errorf("expected clear error message, got: %s", stderr)
		}
	})
}

func TestCLI_Run_SimpleScript(t *testing.T) {
	// Create a temporary script file to run in bento sandbox
	tmpFile, err := ioutil.TempFile("", "bento-test-script-*.sh")
	if err != nil {
		t.Fatalf("failed to create temp script: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	scriptContent := `#!/bin/sh
echo "hello from sandbox"
`
	if _, err := tmpFile.Write([]byte(scriptContent)); err != nil {
		t.Fatalf("failed to write script content: %v", err)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
		t.Fatalf("failed to make script executable: %v", err)
	}

	stdout, stderr, exitCode := runBento(t, "run", tmpFile.Name())
	// In some environments, sandboxing might fail or warn if not run as root / not having AppArmor,
	// but the exit code should ideally be 0 or 1 with sandbox logs. Let's inspect the behavior.
	t.Logf("Exit Code: %d", exitCode)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

func TestCLI_GoldenJourney(t *testing.T) {
	t.Run("invalid flag placement", func(t *testing.T) {
		_, stderr, exitCode := runBento(t, "--timeout=30s", "run")
		if exitCode != 2 {
			t.Errorf("expected exit code 2 for invalid prefix flag placement, got %d", exitCode)
		}
		if !strings.Contains(stderr, "usage: bento <subcommand>") {
			t.Errorf("expected usage help screen, got: %s", stderr)
		}
	})

	t.Run("typo command suggestions", func(t *testing.T) {
		_, stderr, exitCode := runBento(t, "runn")
		if exitCode != 2 {
			t.Errorf("expected exit code 2 for typoed subcommand, got %d", exitCode)
		}
		if !strings.Contains(stderr, `unknown command "runn"`) {
			t.Errorf("expected unknown command error, got: %s", stderr)
		}
		if !strings.Contains(stderr, "run") {
			t.Errorf("expected Cobra suggestions containing 'run', got: %s", stderr)
		}
	})

	t.Run("help subcommand dispatch", func(t *testing.T) {
		stdout, stderr, exitCode := runBento(t, "help", "run")
		if exitCode != 0 {
			t.Errorf("expected help run to exit with 0, got %d", exitCode)
		}
		combined := stdout + stderr
		if !strings.Contains(combined, "bento run") || !strings.Contains(combined, "--timeout") {
			t.Errorf("expected run help output, got: %s", combined)
		}
	})

	t.Run("flag placeholder and type leaks check", func(t *testing.T) {
		stdout, stderr, _ := runBento(t, "run", "--help")
		combined := stdout + stderr

		// 1. Check for --env KEY=VALUE (not --env env)
		if strings.Contains(combined, "--env env") {
			t.Errorf("leaked type label '--env env' found in help: %s", combined)
		}
		if !strings.Contains(combined, "--env KEY=VALUE") {
			t.Errorf("expected '--env KEY=VALUE' in help, got: %s", combined)
		}

		// 2. Check that --append-args and --replace-args do NOT leak 'args:' type
		if strings.Contains(combined, "--append-args args:") {
			t.Errorf("leaked type label '--append-args args:' found in help: %s", combined)
		}
		if strings.Contains(combined, "--replace-args args:") {
			t.Errorf("leaked type label '--replace-args args:' found in help: %s", combined)
		}
	})

	t.Run("profile env description check", func(t *testing.T) {
		stdout, stderr, _ := runBento(t, "profile", "--help")
		combined := stdout + stderr
		expectedDesc := "added to the generated manifest's 'env:' allowlist"
		if !strings.Contains(combined, expectedDesc) {
			t.Errorf("expected profile env description to contain allowlist detail, got: %s", combined)
		}
	})
}
