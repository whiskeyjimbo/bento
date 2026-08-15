package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// buildsBento matches a README shell line that builds or installs the bento command. The
// binary such a line produces routes the credential shields' passwd lookup through the
// host's NSS modules unless CGO_ENABLED=0 is on the line, and doctor says so on the
// reader's next command - so a recipe without it teaches that the warning is normal.
var buildsBento = regexp.MustCompile(`go (?:build|install)\b[^\n]*(?:\./cmd/bento|/cmd/bento@)`)

func TestReadmeBuildRecipesDisableCgo(t *testing.T) {
	// Every README a reader can follow, not only the root one: the probe example carries
	// its own quick start, and the fix for this landed in the root README alone twice.
	readmes, err := filepath.Glob("../../examples/*/README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range append(readmes, "../../README.md") {
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(text), "\n") {
			if !buildsBento.MatchString(line) {
				continue
			}
			if !strings.Contains(line, "CGO_ENABLED=0") {
				t.Errorf("%s:%d builds bento without CGO_ENABLED=0, so the binary it produces warns in doctor: %q", strings.TrimPrefix(path, "../../"), i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestExampleBinariesIgnored covers the binaries the README's own commands leave behind.
// Each example builds one, and an untracked 11 MB file after following the docs exactly
// reads as a mistake the reader made rather than one the repo left.
func TestExampleBinariesIgnored(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git to ask about ignore rules")
	}
	for _, path := range []string{"examples/probe/bento", "examples/embed/bentoembed", "examples/supervise/bentosupervise"} {
		// check-ignore answers from the rules alone, so this does not need the binary built.
		cmd := exec.Command(git, "check-ignore", "-q", path)
		cmd.Dir = "../.."
		if err := cmd.Run(); err != nil {
			t.Errorf("%s is not ignored, so a build following the docs leaves it untracked: %v", path, err)
		}
	}
}
