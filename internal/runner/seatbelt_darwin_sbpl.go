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

// darwinCompileCtx mirrors compileCtx (Linux). Bundled so compileSBPL's
// signature doesn't grow as new inputs are added.
type darwinCompileCtx struct {
	manifest          *spec.Manifest
	scriptAbs         string
	socksAddr         string // "" if no network
	interpreterPrefix string // "" if system path, else mise/asdf/pyenv/homebrew install root
}

// compileSBPL assembles the Seatbelt profile by composing small
// appendXxx helpers. Same shape as Linux compileBwrapArgs.
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

// appendSBPLInterpreterPrefix authorizes reads under the interpreter's
// install root (e.g. mise's ~/.local/share/mise/installs/python/3.14.4)
// so the interpreter can find its stdlib and shared libs. Empty prefix
// means the system allowances above already cover it.
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

// appendSBPLMandatoryDeny emits explicit deny rules for the always-block
// list. SBPL evaluates last-match-wins, so these override any (allow
// file-read*) rule the user's manifest expanded into. Use literal
// matchers so a subpath rule on the parent dir doesn't silently shadow
// this.
func appendSBPLMandatoryDeny(b *strings.Builder) {
	home, _ := os.UserHomeDir()
	for _, p := range spec.ExpandDangerousPaths(home) {
		fmt.Fprintf(b, "(deny file-read* file-write* (literal %q))\n", p)
	}
}

// appendSBPLMandatoryDenyWrite shadows persistence/RCE targets. Read
// is allowed (these are sometimes legitimately read by scripts —
// .gitconfig, .bashrc); writes are denied.
func appendSBPLMandatoryDenyWrite(b *strings.Builder) {
	home, _ := os.UserHomeDir()
	for _, p := range spec.ExpandDangerousWritePaths(home) {
		fmt.Fprintf(b, "(deny file-write* (literal %q))\n", p)
	}
}

// appendSBPLWorkspaceWriteProtection denies writes inside .git/hooks/
// (subpath catches all current AND future hook files), plus specific
// IDE config files. SBPL's subpath matcher does the same thing Linux's
// ro-rebind does — covers unborn files inside the protected dir.
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
		return // no network rules → denied by default
	}
	// Allow only loopback to the proxy port; proxy enforces per-host.
	if _, port, err := net.SplitHostPort(socksAddr); err == nil {
		fmt.Fprintf(b, "(allow network-outbound (remote ip \"localhost:%s\"))\n", port)
	}
}
