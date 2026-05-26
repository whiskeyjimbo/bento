package spec

import (
	"slices"
	"strings"
	"testing"
)

func TestExpandDangerousPaths(t *testing.T) {
	t.Run("empty home returns nil", func(t *testing.T) {
		if got := ExpandDangerousPaths(""); got != nil {
			t.Errorf("empty home should return nil, got %v", got)
		}
	})

	t.Run("tildes expanded", func(t *testing.T) {
		paths := ExpandDangerousPaths("/home/alice")
		if len(paths) != len(DangerousFiles) {
			t.Fatalf("expected %d paths, got %d", len(DangerousFiles), len(paths))
		}
		for _, p := range paths {
			if strings.HasPrefix(p, "~") {
				t.Errorf("unexpanded tilde in %q", p)
			}
			if !strings.HasPrefix(p, "/home/alice/") {
				t.Errorf("path %q not under home", p)
			}
		}
	})

	t.Run("known credentials covered", func(t *testing.T) {
		paths := ExpandDangerousPaths("/h")
		expected := []string{
			"/h/.ssh/id_rsa",
			"/h/.aws/credentials",
			"/h/.kube/config",
			"/h/.netrc",
		}
		for _, want := range expected {
			if !contains(paths, want) {
				t.Errorf("expected %q in expansion, got %v", want, paths)
			}
		}
	})
}

func TestExpandDangerousWritePaths(t *testing.T) {
	paths := ExpandDangerousWritePaths("/h")
	for _, want := range []string{"/h/.bashrc", "/h/.zshrc", "/h/.gitconfig", "/h/.mcp.json"} {
		if !contains(paths, want) {
			t.Errorf("expected %q in write list, got %v", want, paths)
		}
	}
	if ExpandDangerousWritePaths("") != nil {
		t.Error("empty home should return nil")
	}
}

func TestWorkspaceWriteProtectionFor(t *testing.T) {
	got := WorkspaceWriteProtectionFor("/work/proj")
	if !contains(got.ReadOnlyDirs, "/work/proj/.git/hooks") {
		t.Errorf(".git/hooks should be in ReadOnlyDirs, got %v", got.ReadOnlyDirs)
	}
	requiredFiles := []string{
		"/work/proj/.git/config",
		"/work/proj/.vscode/tasks.json",
		"/work/proj/.vscode/launch.json",
		"/work/proj/.idea/workspace.xml",
	}
	for _, want := range requiredFiles {
		if !contains(got.ShadowFiles, want) {
			t.Errorf("expected %q in ShadowFiles, got %v", want, got.ShadowFiles)
		}
	}
}

func contains(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}
