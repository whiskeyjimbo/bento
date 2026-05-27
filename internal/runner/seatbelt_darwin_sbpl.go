//go:build darwin

package runner

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

type darwinCompileCtx struct {
	manifest          *spec.Manifest
	scriptAbs         string
	socksAddr         string
	interpreterPrefix string // "" if system path, else mise/asdf/pyenv/homebrew install root
}

// compileSBPL assembles the Seatbelt profile via small appendXxx helpers.
func compileSBPL(c darwinCompileCtx) string {
	var b strings.Builder
	appendSBPLHeader(&b)
	appendSBPLSystemAllowances(&b)
	appendSBPLInterpreterPrefix(&b, c.interpreterPrefix)
	appendSBPLScriptRead(&b, c.scriptAbs)
	appendSBPLUserReads(&b, c.manifest.Read)
	appendSBPLUserWrites(&b, c.manifest.Write)
	appendSBPLMandatoryDeny(&b)
	appendSBPLMandatoryDenyWrite(&b)
	appendSBPLWorkspaceWriteProtection(&b, c.manifest.Write)
	appendSBPLNetwork(&b, c.socksAddr)
	return b.String()
}

func appendSBPLHeader(b *strings.Builder) {
	b.WriteString("(version 1)\n(deny default)\n")
}

func appendSBPLSystemAllowances(b *strings.Builder) {
	b.WriteString("(allow process-fork)\n")
	b.WriteString("(allow process-exec (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/System\"))\n")
	b.WriteString("(allow file-read* (subpath \"/usr\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/private/etc\") (literal \"/dev/null\") (literal \"/dev/urandom\") (literal \"/dev/random\"))\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow mach-lookup)\n")
}

// appendSBPLInterpreterPrefix authorizes reads under the interpreter's install root
// (mise/asdf/pyenv/homebrew). Empty: system allowances already cover it.
func appendSBPLInterpreterPrefix(b *strings.Builder, prefix string) {
	if prefix == "" {
		return
	}
	fmt.Fprintf(b, "(allow file-read* process-exec (subpath %q))\n", prefix)
}

func appendSBPLScriptRead(b *strings.Builder, scriptAbs string) {
	if abs, err := filepath.Abs(scriptAbs); err == nil {
		fmt.Fprintf(b, "(allow file-read* (literal %q))\n", abs)
	}
}

func appendSBPLUserReads(b *strings.Builder, read []string) {
	for _, r := range read {
		if abs, err := filepath.Abs(r); err == nil {
			fmt.Fprintf(b, "(allow file-read* (subpath %q))\n", abs)
		}
	}
}

func appendSBPLUserWrites(b *strings.Builder, write []string) {
	for _, w := range write {
		if abs, err := filepath.Abs(w); err == nil {
			fmt.Fprintf(b, "(allow file-read* file-write* (subpath %q))\n", abs)
		}
	}
}

// appendSBPLMandatoryDeny emits explicit deny rules for the always-block list.
// SBPL is last-match-wins; literal matchers prevent subpath shadowing.
func appendSBPLMandatoryDeny(b *strings.Builder) {
	home, _ := os.UserHomeDir()
	for _, p := range spec.ExpandDangerousPaths(home) {
		fmt.Fprintf(b, "(deny file-read* file-write* (literal %q))\n", p)
	}
}

// appendSBPLMandatoryDenyWrite denies writes to persistence/RCE targets.
// Reads stay allowed (.gitconfig, .bashrc are often legitimately read).
func appendSBPLMandatoryDenyWrite(b *strings.Builder) {
	home, _ := os.UserHomeDir()
	for _, p := range spec.ExpandDangerousWritePaths(home) {
		fmt.Fprintf(b, "(deny file-write* (literal %q))\n", p)
	}
}

// appendSBPLWorkspaceWriteProtection denies writes inside protected subpaths
// (e.g. .git/hooks/) and IDE config files. subpath covers unborn files too.
func appendSBPLWorkspaceWriteProtection(b *strings.Builder, writes []string) {
	for _, w := range writes {
		abs, err := filepath.Abs(w)
		if err != nil {
			continue
		}
		protection := spec.WorkspaceWriteProtectionFor(abs)
		for _, dir := range protection.ReadOnlyDirs {
			fmt.Fprintf(b, "(deny file-write* (subpath %q))\n", dir)
		}
		for _, p := range protection.ShadowFiles {
			fmt.Fprintf(b, "(deny file-write* (literal %q))\n", p)
		}
	}
}

func appendSBPLNetwork(b *strings.Builder, socksAddr string) {
	if socksAddr == "" {
		return // denied by default
	}
	// Allow only loopback to the proxy port; proxy enforces per-host.
	if _, port, err := net.SplitHostPort(socksAddr); err == nil {
		fmt.Fprintf(b, "(allow network-outbound (remote ip \"localhost:%s\"))\n", port)
	}
}
