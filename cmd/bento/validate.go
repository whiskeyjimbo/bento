package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/whiskeyjimbo/bento"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

var (
	validateQuiet bool
)

var validateCmd = &cobra.Command{
	Use:   "validate <manifest.yaml>",
	Short: "Load a manifest and print the resolved interpreter, paths, and posture",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		path := args[0]
		abs, _ := filepath.Abs(path)
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer f.Close()
		m, err := bento.LoadManifest(f, bento.WithBaseDir(filepath.Dir(abs)))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if m.LegacyExecField {
			fmt.Fprintln(os.Stderr, "[bento] warning: `exec: [...]` is deprecated; use `allow_exec: true` instead.")
		}
		issues, notes := collectManifestIssues(m, abs)
		if validateQuiet {
			if len(issues) > 0 {
				for _, s := range issues {
					fmt.Fprintln(os.Stderr, "issue:", s)
				}
				os.Exit(1)
			}
			fmt.Println("ok")
			os.Exit(0)
		}
		printResolvedManifest(os.Stdout, m, abs, issues, notes)
		if len(issues) > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	},
}

func init() {
	validateCmd.Flags().BoolVarP(&validateQuiet, "quiet", "q", false, "print only 'ok' or the error (script-friendly)")
}

func collectManifestIssues(m *bento.Manifest, manifestPath string) (issues, notes []string) {
	script := m.Script
	if !filepath.IsAbs(script) && manifestPath != "" {
		script = filepath.Join(filepath.Dir(manifestPath), script)
	}
	if _, err := os.Stat(script); err != nil {
		issues = append(issues, fmt.Sprintf("script not found on disk: %s", script))
	}
	if interp := m.Interpreter; interp != "" && interp != script {
		if _, err := exec.LookPath(interp); err != nil {
			issues = append(issues, fmt.Sprintf("interpreter %q not found on $PATH", interp))
		}
	}
	for _, p := range m.Read {
		if !filepath.IsAbs(p) && manifestPath != "" {
			p = filepath.Join(filepath.Dir(manifestPath), p)
		}
		if _, err := os.Stat(p); err != nil {
			issues = append(issues, fmt.Sprintf("read path not found on disk: %s", p))
		}
	}
	// Write paths may legitimately not exist yet (script creates them);
	// only flag if the parent directory is missing.
	for _, p := range m.Write {
		if !filepath.IsAbs(p) && manifestPath != "" {
			p = filepath.Join(filepath.Dir(manifestPath), p)
		}
		if _, err := os.Stat(filepath.Dir(p)); err != nil {
			issues = append(issues, fmt.Sprintf("write path's parent directory does not exist: %s", p))
		}
	}
	for _, name := range m.Env {
		if _, ok := os.LookupEnv(name); !ok {
			notes = append(notes, fmt.Sprintf("env: %s is in allowlist but not set in current shell — pass `--env %s=VALUE` to `bento run`, or export it before running", name, name))
		}
	}
	return issues, notes
}

func printResolvedManifest(w io.Writer, m *bento.Manifest, manifestPath string, issues, notes []string) {
	status := "ok"
	switch {
	case len(issues) > 0:
		status = fmt.Sprintf("%d %s FOUND — see end of output", len(issues), pluralize(len(issues), "ISSUE", "ISSUES"))
	case len(notes) > 0:
		status = fmt.Sprintf("ok (%d %s — see end of output)", len(notes), pluralize(len(notes), "note", "notes"))
	}
	fmt.Fprintf(w, "manifest: %s — %s\n\n", manifestPath, status)

	interp := m.Interpreter
	script := m.Script
	if !filepath.IsAbs(script) && manifestPath != "" {
		script = filepath.Join(filepath.Dir(manifestPath), script)
	}
	switch {
	case interp == "" || interp == script:
		fmt.Fprintln(w, "interpreter: (none — script is run directly)")
	default:
		if resolved, err := exec.LookPath(interp); err == nil {
			fmt.Fprintf(w, "interpreter: %s  →  %s\n", interp, resolved)
			if !filepath.IsAbs(interp) {
				fmt.Fprintln(w, "             (resolved via $PATH at run time — teammates with a different")
				fmt.Fprintln(w, "              python/bash on $PATH will get a different binary. Pin by replacing")
				fmt.Fprintf(w, "              `interpreter: %s` with `interpreter: %s` in the manifest.)\n", interp, resolved)
			}
		} else {
			fmt.Fprintf(w, "interpreter: %s  (NOT FOUND on $PATH)\n", interp)
		}
	}
	if _, err := os.Stat(script); err == nil {
		fmt.Fprintf(w, "script:      %s\n", script)
	} else {
		fmt.Fprintf(w, "script:      %s  (NOT FOUND)\n", script)
	}
	fmt.Fprintln(w, "             (bind-mounted inside the sandbox at /sandbox/script; tracebacks, $0,")
	fmt.Fprintln(w, "              and __file__ reference that path, not the host path above.)")

	if len(m.Args) > 0 {
		fmt.Fprintf(w, "args:        %v\n", m.Args)
	}

	// Surface commented `# env:` entries from the manifest file as "pending":
	// the YAML parser ignores them, but the user wrote them in writing, often
	// as bento profile's nudge "uncomment names you want inherited". Without
	// this section, `validate` says "env: (none)" while the YAML right above
	// it lists CITY — a stark disagreement between two views of the manifest.
	pendingEnv, optionalEnv := readCommentedEnvBuckets(manifestPath)
	// Filter out names already active in m.Env (in either bucket): when the
	// user follows the Quick-apply recipe (add a name to the live env: block)
	// the header comment that originally listed it remains, so the same name
	// would appear under both "active" and "pending/optional" — a
	// contradictory reading of the same manifest.
	if len(m.Env) > 0 {
		active := make(map[string]bool, len(m.Env))
		for _, name := range m.Env {
			active[name] = true
		}
		dropActive := func(names []string) []string {
			out := names[:0]
			for _, name := range names {
				if !active[name] {
					out = append(out, name)
				}
			}
			return out
		}
		pendingEnv = dropActive(pendingEnv)
		optionalEnv = dropActive(optionalEnv)
	}
	fmt.Fprintln(w)
	if len(m.Env) == 0 && len(pendingEnv) == 0 && len(optionalEnv) == 0 {
		fmt.Fprintln(w, "env:         (none — host env is fully stripped)")
	} else {
		if len(m.Env) == 0 {
			fmt.Fprintln(w, "env:         (none active — host env is stripped)")
		} else {
			fmt.Fprintln(w, "env:         (allowlist — passed through from host when set)")
			for _, name := range m.Env {
				if v, ok := os.LookupEnv(name); ok {
					fmt.Fprintf(w, "  - %s = %s\n", name, shellQuote(v))
				} else {
					fmt.Fprintf(w, "  - %s (NOT SET on host — script will see empty string)\n", name)
				}
			}
		}
		if len(pendingEnv) > 0 {
			fmt.Fprintln(w, "             pending (commented in manifest — uncomment to activate):")
			for _, name := range pendingEnv {
				fmt.Fprintf(w, "             - %s\n", name)
			}
		}
		// Optional candidates: env names the script reads that the profile
		// captured as "other candidates, optional" — they didn't break the
		// trial run. Surface them so a user configuring the script (e.g.
		// pointing it at a different repo) discovers them in `validate`
		// instead of having to grep the manifest source.
		if len(optionalEnv) > 0 {
			fmt.Fprintln(w, "             also observed by profile, not in allowlist:")
			for _, name := range optionalEnv {
				fmt.Fprintf(w, "             - %s (pass `--env %s=...` ad-hoc, or add to env: to inherit $%s from your shell)\n", name, name, name)
			}
		}
	}

	fmt.Fprintln(w)
	if len(m.Read) == 0 {
		fmt.Fprintln(w, "read:        (none)")
	} else {
		fmt.Fprintln(w, "read:")
		for _, p := range m.Read {
			if note := runtimeReadPathNote(p); note != "" {
				fmt.Fprintf(w, "  - %s   (%s)\n", p, note)
			} else {
				fmt.Fprintf(w, "  - %s\n", p)
			}
		}
	}
	if len(m.Write) == 0 {
		fmt.Fprintln(w, "write:       (none)")
	} else {
		fmt.Fprintln(w, "write:")
		for _, p := range m.Write {
			fmt.Fprintf(w, "  - %s\n", p)
		}
	}
	if manifestHasRelativePathEntries(manifestPath) {
		fmt.Fprintf(w, "             (relative entries in the manifest were resolved against %s)\n", filepath.Dir(manifestPath))
	}

	fmt.Fprintln(w)
	if m.Network == nil {
		fmt.Fprintln(w, "network:     blocked (no network at all)")
	} else if len(m.Network.Rules) == 0 {
		fmt.Fprintln(w, "network:     blocked (empty rules list)")
	} else {
		fmt.Fprintln(w, "network:")
		for _, r := range m.Network.Rules {
			fmt.Fprintf(w, "  - %s:%s\n", r.Host, r.Port)
		}
	}

	if m.AllowExec {
		fmt.Fprintln(w, "exec:        ALL subprocesses permitted (allow_exec: true)")
		fmt.Fprintln(w, "             (allow_exec is binary on/off — per-binary allowlisting is not")
		fmt.Fprintln(w, "              supported; any subprocess the script forks is permitted.)")
	} else {
		fmt.Fprintln(w, "exec:        blocked (no subprocesses)")
	}

	if m.Limits != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "limits:")
		if m.Limits.Memory != "" {
			fmt.Fprintf(w, "  memory: %s\n", m.Limits.Memory)
		}
		if m.Limits.CPU != "" {
			fmt.Fprintf(w, "  cpu:    %s\n", m.Limits.CPU)
		}
		if m.Limits.Tasks != 0 {
			fmt.Fprintf(w, "  tasks:  %d\n", m.Limits.Tasks)
		}
		if m.Limits.FDs != 0 {
			fmt.Fprintf(w, "  fds:    %d\n", m.Limits.FDs)
		}
		if m.Limits.Tmpfs != "" {
			fmt.Fprintf(w, "  tmpfs:  %s\n", m.Limits.Tmpfs)
		}
	}

	fmt.Fprintln(w)
	printImplicitMounts(w)

	if len(issues) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ISSUES:")
		for _, s := range issues {
			fmt.Fprintf(w, "  - %s\n", s)
		}
	}
	if len(notes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "NOTES:")
		for _, s := range notes {
			fmt.Fprintf(w, "  - %s\n", s)
		}
	}
}

func readCommentedEnvBuckets(manifestPath string) (required, optional []string) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, nil
	}
	const (
		bucketNone     = 0
		bucketRequired = 1
		bucketOptional = 2
		bucketSkip     = 3 // scaffold example/placeholder block — parsed but not surfaced
	)
	bucket := bucketNone
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			bucket = bucketNone
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		switch {
		case body == "env:":
			bucket = bucketRequired
			continue
		case strings.HasPrefix(body, "env (example") || strings.HasPrefix(body, "env (placeholder"):
			bucket = bucketSkip
			continue
		case strings.HasPrefix(body, "env (") || strings.HasPrefix(body, "env(") || strings.HasPrefix(body, "Other candidates"):
			bucket = bucketOptional
			continue
		}
		if bucket == bucketNone {
			continue
		}
		if !strings.HasPrefix(body, "- ") {
			bucket = bucketNone
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(body, "-"))
		if i := strings.IndexAny(name, " \t"); i >= 0 {
			name = name[:i]
		}
		if name == "" || !isEnvVarName(name) {
			continue
		}
		switch bucket {
		case bucketRequired:
			required = append(required, name)
		case bucketOptional:
			optional = append(optional, name)
		}
	}
	return required, optional
}

func printImplicitMounts(w io.Writer) {
	home, _ := os.UserHomeDir()
	fmt.Fprintln(w, "implicit mounts (always present, not in the manifest):")
	fmt.Fprintln(w, "  /proc          procfs (read-only) — runtime introspection")
	fmt.Fprintln(w, "  /sys           sysfs (read-only) — limited kernel info")
	fmt.Fprintln(w, "  /tmp           fresh tmpfs (writable, ephemeral — lost on exit)")
	fmt.Fprintln(w, "  /sandbox       script bind-mount + cwd ($HOME inside the sandbox)")
	fmt.Fprintln(w, "  /etc/{resolv.conf,hosts,passwd,group,ssl,...}  network/identity bits the runtime needs")
	if home != "" {
		fmt.Fprintln(w, "mandatory-deny shadows (always shadowed with /dev/null, cannot be granted):")
		shadows := spec.ExpandDangerousPaths(home)
		shown := 0
		for _, p := range shadows {
			if shown >= 6 {
				fmt.Fprintf(w, "  ... and %d more\n", len(shadows)-shown)
				break
			}
			fmt.Fprintf(w, "  %s\n", p)
			shown++
		}
	} else {
		fmt.Fprintln(w, "mandatory-deny shadows: SSH keys, cloud creds, shell rc files (always shadowed)")
	}
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func runtimeReadPathNote(p string) string {
	switch p {
	case "/etc/services":
		return "runtime: TCP/UDP port-name lookup (libc) — safe to keep"
	case "/etc/resolv.conf":
		return "runtime: DNS resolver config — safe to keep"
	case "/etc/nsswitch.conf":
		return "runtime: name-service switch (libc) — safe to keep"
	case "/etc/hosts":
		return "runtime: static hostname → IP map — safe to keep"
	case "/etc/host.conf":
		return "runtime: resolver options (libc) — safe to keep"
	case "/etc/gai.conf":
		return "runtime: getaddrinfo policy (libc) — safe to keep"
	case "/etc/protocols":
		return "runtime: IP protocol name lookup (libc) — safe to keep"
	}
	return ""
}

func manifestHasRelativePathEntries(manifestPath string) bool {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	section := ""
	for _, line := range lines {
		stripped := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(stripped, "#") || stripped == "" {
			continue
		}
		// Top-level keys reset the section context. A line at column 0 that
		// ends with ":" names the section we're inside.
		if line == stripped && strings.HasSuffix(stripped, ":") {
			section = strings.TrimSuffix(stripped, ":")
			continue
		}
		if section != "read" && section != "write" {
			continue
		}
		if !strings.HasPrefix(stripped, "- ") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(stripped, "-"))
		val = strings.Trim(val, `"'`)
		if val == "" {
			continue
		}
		if !filepath.IsAbs(val) {
			return true
		}
	}
	return false
}

func isEnvVarName(s string) bool {
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
