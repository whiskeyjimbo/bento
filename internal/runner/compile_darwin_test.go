//go:build darwin

package runner

import (
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

func TestCompileSBPLHeader(t *testing.T) {
	profile := compileSBPL(darwinCompileCtx{
		manifest:  &spec.Manifest{},
		scriptAbs: "/tmp/script.py",
	})
	if !strings.HasPrefix(profile, "(version 1)\n(deny default)\n") {
		t.Errorf("profile must start with version + deny-default, got prefix: %q", profile[:50])
	}
}

func TestCompileSBPLNetwork(t *testing.T) {
	t.Run("no socks address → no network-outbound", func(t *testing.T) {
		profile := compileSBPL(darwinCompileCtx{manifest: &spec.Manifest{}, scriptAbs: "/tmp/s.py"})
		if strings.Contains(profile, "network-outbound") {
			t.Errorf("empty socksAddr should emit no network-outbound rule, got:\n%s", profile)
		}
	})
	t.Run("socks address → allow only that port on loopback", func(t *testing.T) {
		profile := compileSBPL(darwinCompileCtx{
			manifest:  &spec.Manifest{},
			scriptAbs: "/tmp/s.py",
			socksAddr: "127.0.0.1:54321",
		})
		want := `(allow network-outbound (remote ip "localhost:54321"))`
		if !strings.Contains(profile, want) {
			t.Errorf("expected %q in profile, got:\n%s", want, profile)
		}
	})
}

func TestCompileSBPLUserPaths(t *testing.T) {
	profile := compileSBPL(darwinCompileCtx{
		manifest: &spec.Manifest{
			Read:  []string{"/etc/hostname"},
			Write: []string{"/tmp/out"},
		},
		scriptAbs: "/tmp/s.py",
	})
	if !strings.Contains(profile, `(allow file-read* (subpath "/etc/hostname"))`) {
		t.Errorf("expected read rule for /etc/hostname, got:\n%s", profile)
	}
	if !strings.Contains(profile, `(allow file-read* file-write* (subpath "/tmp/out"))`) {
		t.Errorf("expected write rule for /tmp/out, got:\n%s", profile)
	}
}
