package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
)

// bentoVersionTag returns a short identifier for the running binary, used in
// generated manifest headers. Returns "(dev)" when no module info is embedded.
func bentoVersionTag() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(dev)"
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	var rev, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 7 {
				rev = s.Value[:7]
			}
		case "vcs.modified":
			if s.Value == "true" {
				modified = "+dirty"
			}
		}
	}
	if rev != "" {
		return rev + modified
	}
	return "(dev)"
}

// stringSliceFlag collects repeated values from a flag (e.g. `--read PATH`).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	if v == "" {
		return fmt.Errorf("value must not be empty")
	}
	*s = append(*s, v)
	return nil
}
func (s *stringSliceFlag) Type() string { return "stringSlice" }

// envFlag collects repeated --env KEY=VALUE pairs.
type envFlag map[string]string

func (e envFlag) String() string {
	var parts []string
	for k, v := range e {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func (e envFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok {
		return fmt.Errorf("expected KEY=VALUE, got %q", s)
	}
	e[k] = v
	return nil
}
func (e envFlag) Type() string { return "KEY=VALUE" }


// warnEmptyEnv flags `--env KEY=` with no value — almost always a shell
// quoting bug.
func warnEmptyEnv(w io.Writer, env envFlag) {
	var empty []string
	for k, v := range env {
		if v == "" {
			empty = append(empty, k)
		}
	}
	if len(empty) == 0 {
		return
	}
	sort.Strings(empty)
	fmt.Fprintln(w, "[bento] ──────────────── warning ────────────────")
	for _, k := range empty {
		fmt.Fprintf(w, "[bento] --env %s= has an empty value — the script will see %s=\"\".\n", k, k)
	}
	fmt.Fprintln(w, "[bento]   common cause: `VAR=value bento run --env VAR=$VAR ...` — the inline assignment")
	fmt.Fprintln(w, "[bento]   isn't exported, so $VAR expands to empty before bento sees the flag.")
	fmt.Fprintln(w, "[bento]   fix: `export VAR=value` first, or pass the value literally: `--env VAR=value`.")
	fmt.Fprintln(w, "[bento] ─────────────────────────────────────────")
}

func isManifestPath(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

func misplacedBentoFlag(scriptArgs []string) string {
	if len(scriptArgs) == 0 {
		return ""
	}
	tok := scriptArgs[0]
	if !strings.HasPrefix(tok, "-") || tok == "-" {
		return ""
	}
	name := strings.TrimLeft(tok, "-")
	if eq := strings.IndexByte(name, '='); eq >= 0 {
		name = name[:eq]
	}
	if !knownBentoFlag(name) {
		return ""
	}
	return fmt.Sprintf("error: `%s` looks like a bento flag but appeared after the script/manifest path,\n  so it was silently treated as an argument to the script. Move the flag BEFORE the path:", tok)
}

func knownBentoFlag(name string) bool {
	switch name {
	case "env", "timeout", "network-mode", "interpreter", "verbose", "v",
		"prompt", "i", "telemetry-out", "out", "force", "allow-exec":
		return true
	}
	return false
}

// noteForwardedFlags warns when scriptArgs contains a token that *looks* like
// a flag but isn't a known bento flag — it's being silently forwarded to the
// script as argv.
func noteForwardedFlags(scriptArgs []string) string {
	if len(scriptArgs) == 0 {
		return ""
	}
	var flags []string
	for _, tok := range scriptArgs {
		if tok == "--" {
			break
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			continue
		}
		name := strings.TrimLeft(tok, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if knownBentoFlag(name) {
			// misplacedBentoFlag handles this as a hard error upstream.
			continue
		}
		flags = append(flags, tok)
	}
	if len(flags) == 0 {
		return ""
	}
	return fmt.Sprintf("[bento] note: forwarding flag-shaped argv to the script: %s\n[bento]   if these were meant for bento, move them BEFORE the script/manifest path.\n[bento]   if they're for the script, prefix the list with `--` to silence this note.",
		strings.Join(flags, " "))
}

// shellQuote returns s wrapped in single quotes for safe display in a shell
// command suggestion. Embedded single quotes are escaped via the standard
// '"'"' construction so the suggestion is paste-safe.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	// If the value is shell-safe as-is (alnum, plus a few benign chars), skip
	// quoting for readability.
	safe := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '-', c == '.', c == '/', c == ':', c == ',', c == '=':
		default:
			safe = false
		}
	}
	if safe {
		return s
	}
	// Escape single quotes inside single quotes.
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bento <subcommand> [flags] [args]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "subcommands:")
	fmt.Fprintln(os.Stderr, "  run       run a script (zero-config) or a manifest")
	fmt.Fprintln(os.Stderr, "  profile   record one trial run and emit <script>.manifest.yaml — start here")
	fmt.Fprintln(os.Stderr, "  validate  load a manifest and print the resolved interpreter, paths, and posture")
	fmt.Fprintln(os.Stderr, "  doctor    check the host for required and optional sandboxing primitives")
	fmt.Fprintln(os.Stderr, "  setup     install/configure host bits (AppArmor profile, etc.) where needed")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "common patterns:")
	fmt.Fprintln(os.Stderr, "  bento run script.py                         # zero-config, no network, no exec")
	fmt.Fprintln(os.Stderr, "  bento run ./my-binary arg1 arg2             # ELF binary with script args")
	fmt.Fprintln(os.Stderr, "  bento run check.yaml                        # under a hand-written manifest")
	fmt.Fprintln(os.Stderr, "  bento run --env API=$API check.yaml arg     # extra env + script args")
	fmt.Fprintln(os.Stderr, "  bento profile ./fetch.py                    # generate fetch.manifest.yaml")
	fmt.Fprintln(os.Stderr, "  bento profile --allow-exec ./deploy.sh      # bash/build scripts that fork")
	fmt.Fprintln(os.Stderr, "  bento profile --scaffold ./prod-only.py     # commented skeleton, no live run")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  bento <subcommand> --help    flags for one subcommand")
	fmt.Fprintln(os.Stderr, "  bento --help                 this help screen")
	fmt.Fprintln(os.Stderr, "  bento --version              print the version")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "flag placement: flags belong AFTER the subcommand.")
	fmt.Fprintln(os.Stderr, "  bento run --timeout=30s script.py     # correct")
	fmt.Fprintln(os.Stderr, "  bento --timeout=30s run script.py     # NOT a valid flag")
}

// tailBuffer keeps the last N bytes written to it, dropping older bytes
// once the cap is reached. Safe for concurrent Write.
type tailBuffer struct {
	max int
	buf []byte
}

func newTailBuffer(max int) *tailBuffer { return &tailBuffer{max: max} }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-t.max:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.buf) }

func isShellInterpreter(interp string) bool {
	base := filepath.Base(interp)
	return base == "bash" || base == "sh" || base == "zsh"
}

func isPythonInterpreter(interp string) bool {
	base := filepath.Base(interp)
	return base == "python" || base == "python3" || base == "py"
}

func appendUniqueStr(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}



