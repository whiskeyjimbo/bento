package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	// $NAME or ${NAME (no trailing brace operator) — capture group is the bare
	// identifier. Used only for "plain reference" matches; defaulted forms
	// (${NAME:-foo}, ${NAME-foo}, etc.) are matched separately by reShellVarOp
	// so we can skip them — the script is *handling* the unset case there.
	reShellVar = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`)
	// ${NAME<op>...}: any of :-, :=, :?, :+, -, =, ?, + — these all either
	// provide a default value or detect-and-error explicitly. Either way the
	// script knows the var might be unset and bento's "you forgot to allowlist
	// this" note is misleading. Names matched here are removed from the
	// reference set.
	reShellVarDefaulted = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-=?+])`)
	// ${NAME:-default} / ${NAME-default} / ${NAME:=default} / ${NAME=default}:
	// captures the name and the literal default value. Only these four operators
	// supply a usable value; `:?` errors and `:+` substitutes only when set.
	// Used by shellEnvDefaults to correlate a script's env-var defaults with
	// observed lost-write basenames, so the Quick-apply scaffold can name the
	// var that actually controls the lost path.
	reShellVarDefaultValue = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):?[-=]([^}]*)\}`)
	// Local assignments / declarations / loop targets. A name assigned in the
	// script body is local to the script — it is not consumed from the host
	// env, so the env-strip note is a false positive.
	//   NAME=value                  (bare assignment)
	//   export NAME=value           (exported assignment — still local-scope)
	//   readonly NAME=value
	//   declare NAME / declare -x NAME=value
	//   local NAME / local NAME=value
	//   typeset / let
	//   read NAME [NAME2 ...]       (read from stdin)
	//   for NAME in ...; do
	//   select NAME in ...; do
	// All anchored to start-of-line (or after `;`, `then`, `do`, `&&`, `||`)
	// so a comment containing `FOO=bar` mid-line isn't matched.
	reShellAssign = regexp.MustCompile(
		`(?m)(?:^|[;&|]|\bthen\b|\bdo\b|\belse\b)\s*` +
			`(?:export\s+|readonly\s+|declare(?:\s+-[-a-zA-Z]+)*\s+|typeset(?:\s+-[-a-zA-Z]+)*\s+|local\s+|let\s+)?` +
			`([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|\+=)`)
	reShellRead = regexp.MustCompile(
		`(?m)(?:^|[;&|]|\bthen\b|\bdo\b|\belse\b)\s*read\s+(?:-[-a-zA-Z]+\s+)*([A-Za-z_][A-Za-z0-9_ ]*)`)
	reShellForIn = regexp.MustCompile(
		`(?m)(?:^|[;&|]|\bthen\b|\bdo\b|\belse\b)\s*(?:for|select)\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b`)
	// Single-quoted strings and # comments suppress shell expansion; strip
	// them before scanning so `echo '$FOO'` and `# uses $FOO` don't count.
	reShellSingleQuoted = regexp.MustCompile(`'[^']*'`)
	reShellLineComment  = regexp.MustCompile(`(?m)(^|[^\\])#[^\n]*`)

	// Python env access. Two reference styles:
	//   os.environ["NAME"]            — always a read (KeyError if unset)
	//   os.environ.get("NAME", ...)   — caller is providing a default
	//   os.getenv("NAME", ...)        — caller is providing a default
	// Capture groups:
	//   1: name in the no-default styles
	//   2: name in the get/getenv styles
	//   3: a non-empty arg list tail starting with `,` (default supplied)
	rePyEnvVar = regexp.MustCompile(
		`(?:os\.environ\[['"]([A-Za-z_][A-Za-z0-9_]*)['"]\])` +
			`|(?:os\.environ\.get\(['"]([A-Za-z_][A-Za-z0-9_]*)['"]([^)]*)\))` +
			`|(?:os\.getenv\(['"]([A-Za-z_][A-Za-z0-9_]*)['"]([^)]*)\))`)
	// Broader identity-leak detection for shell scripts: anything that
	// resolves the current user via libc / /etc/passwd / numeric uid lookup
	// rather than the host login name.
	reShellIdentity = regexp.MustCompile(`(?m)(?:^|[\s;|&$(` + "`" + `])(whoami|id(?:\s+-[un]+)?|logname|groups|getent\s+passwd)\b`)

	// Python identity-leak APIs. All of these return bento's synthetic
	// /etc/passwd identity ("sandbox") or the sandbox numeric uid, not the
	// host login name.
	rePyIdentity = regexp.MustCompile(
		`\b(os\.getlogin|getpass\.getuser|pwd\.getpwuid|os\.getuid|os\.geteuid)\s*\(`)

	// Matches a relative path token in script output. Anchored on `./` followed
	// by a filename-ish run (letters/digits/_/-/./). Captures the whole `./X`.
	reRelativePathInOutput = regexp.MustCompile(`(\./[A-Za-z0-9_./-]+)`)

	reShellCwdAssumption = regexp.MustCompile(`\$0\b|\$\{?BASH_SOURCE\b`)
)

func shellEnvDefaults(src []byte) map[string]string {
	scrub := reShellSingleQuoted.ReplaceAll(src, []byte(`''`))
	scrub = reShellLineComment.ReplaceAllFunc(scrub, func(b []byte) []byte {
		if len(b) > 0 && b[0] != '#' {
			return b[:1]
		}
		return nil
	})
	out := make(map[string]string)
	for _, m := range reShellVarDefaultValue.FindAllSubmatch(scrub, -1) {
		name := string(m[1])
		val := strings.TrimSpace(string(m[2]))
		// Strip surrounding quotes if present — `${X:-"foo"}` and `${X:-'foo'}`.
		if len(val) >= 2 {
			first, last := val[0], val[len(val)-1]
			if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if val == "" {
			continue
		}
		if _, exists := out[name]; !exists {
			out[name] = val
		}
	}
	return out
}

func pythonEnvDefaults(src []byte) map[string]string {
	out := make(map[string]string)
	for _, m := range rePyEnvVar.FindAllSubmatch(src, -1) {
		var name string
		var tail []byte
		switch {
		case len(m[2]) > 0 && len(m[3]) > 0:
			name = string(m[2])
			tail = m[3]
		case len(m[4]) > 0 && len(m[5]) > 0:
			name = string(m[4])
			tail = m[5]
		default:
			continue
		}
		if v, ok := firstQuotedString(tail); ok {
			if _, exists := out[name]; !exists {
				out[name] = v
			}
		}
	}
	return out
}

func scriptEnvDefaults(scriptPath, interp string) map[string]string {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil
	}
	switch {
	case isShellInterpreter(interp):
		return shellEnvDefaults(src)
	case isPythonInterpreter(interp):
		return pythonEnvDefaults(src)
	}
	return nil
}

func envVarForLostPath(lost string, defaults map[string]string) string {
	lostBase := filepath.Base(lost)
	for name, defVal := range defaults {
		defBase := filepath.Base(defVal)
		if defBase == "" || defBase == "." || defBase == "/" {
			continue
		}
		if defBase == lostBase {
			return name
		}
	}
	return ""
}

func pickEnvForLostWrite(lostWrites []string, defaults map[string]string, referenced []string) string {
	for _, lost := range lostWrites {
		lostBase := filepath.Base(lost)
		for name, defVal := range defaults {
			defBase := filepath.Base(defVal)
			if defBase == "" || defBase == "." || defBase == "/" {
				continue
			}
			if defBase == lostBase {
				return name
			}
		}
	}
	return pickOutputEnvName(referenced)
}

func pickOutputEnvName(referenced []string) string {
	outShaped := []string{"OUT", "OUTPUT", "DEST", "DESTINATION", "FILE", "OUTFILE", "TARGET"}
	contains := func(s, sub string) bool { return strings.Contains(strings.ToUpper(s), sub) }
	for _, want := range outShaped {
		for _, name := range referenced {
			if strings.EqualFold(name, want) {
				return name
			}
		}
	}
	for _, name := range referenced {
		if contains(name, "OUT") || contains(name, "DEST") || strings.HasSuffix(strings.ToUpper(name), "_FILE") || strings.HasSuffix(strings.ToUpper(name), "_PATH") {
			return name
		}
	}
	if len(referenced) > 0 {
		return referenced[0]
	}
	return "OUT"
}

func reprofileCmd(scriptPath string, scriptArgs []string, env envFlag, preMountReads []string, allowExec bool, extras []string) string {
	hasAllowExec := allowExec
	for _, e := range extras {
		if e == "--allow-exec" {
			hasAllowExec = true
		}
	}
	var parts []string
	if hasAllowExec {
		parts = append(parts, "--allow-exec")
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, "--env", shellQuote(k+"="+env[k]))
	}
	for _, p := range preMountReads {
		parts = append(parts, "--read", shellQuote(p))
	}
	for _, e := range extras {
		if e == "--allow-exec" {
			continue
		}
		parts = append(parts, e)
	}
	parts = append(parts, shellQuote(scriptPath))
	for _, a := range scriptArgs {
		parts = append(parts, shellQuote(a))
	}
	return "bento profile " + strings.Join(parts, " ")
}

func referencedEnvVarsInScript(scriptPath, interp string) []string {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil
	}
	var names []string
	switch {
	case isShellInterpreter(interp):
		names = referencedShellVarsAll(src)
	case isPythonInterpreter(interp):
		names = referencedPythonEnvVarsAll(src)
	default:
		return nil
	}
	out := names[:0]
	for _, n := range names {
		switch n {
		case "USER", "LOGNAME":
			continue
		}
		out = append(out, n)
	}
	return out
}

func referencedIdentityEnvVarsInScript(scriptPath, interp string) []string {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil
	}
	var names []string
	var tokens []string
	switch {
	case isShellInterpreter(interp):
		names = referencedShellVarsAll(src)
		tokens = identityShellTokens(src)
	case isPythonInterpreter(interp):
		names = referencedPythonEnvVarsAll(src)
		tokens = identityPythonTokens(src)
	default:
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, n := range names {
		switch n {
		case "USER", "LOGNAME", "HOME":
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	for _, t := range tokens {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func isShellOrLibcIdentityCall(name string) bool {
	switch name {
	case "USER", "LOGNAME", "HOME":
		return false
	}
	return true
}

func identityShellTokens(src []byte) []string {
	var out []string
	for _, m := range reShellIdentity.FindAllSubmatch(src, -1) {
		tok := strings.TrimSpace(string(m[1]))
		if strings.HasPrefix(tok, "id") {
			tok = "id"
		}
		out = appendUniqueStr(out, tok)
	}
	return out
}

func identityPythonTokens(src []byte) []string {
	var out []string
	for _, m := range rePyIdentity.FindAllSubmatch(src, -1) {
		out = appendUniqueStr(out, string(m[1]))
	}
	return out
}

func templatedBasename(name string) bool {
	if reTemplatedBasename.MatchString(name) {
		return true
	}
	if reLikelyPID.MatchString(name) {
		return true
	}
	for _, m := range reMktempRun.FindAllString(name, -1) {
		body := m[1:]
		var hasD, hasL bool
		for _, c := range body {
			switch {
			case c >= '0' && c <= '9':
				hasD = true
			case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
				hasL = true
			}
		}
		if hasD && hasL {
			return true
		}
	}
	return false
}

func referencedShellVarsAll(src []byte) []string {
	scrub := reShellSingleQuoted.ReplaceAll(src, []byte(`''`))
	scrub = reShellLineComment.ReplaceAllFunc(scrub, func(b []byte) []byte {
		if len(b) > 0 && b[0] != '#' {
			return b[:1]
		}
		return nil
	})
	all := uniqueEnvNames(reShellVar.FindAllSubmatch(scrub, -1))
	assigned := shellAssignedNames(scrub)
	defaulted := make(map[string]bool)
	for _, m := range reShellVarDefaulted.FindAllSubmatch(scrub, -1) {
		defaulted[string(m[1])] = true
	}
	out := all[:0]
	for _, n := range all {
		if assigned[n] && !defaulted[n] {
			continue
		}
		out = append(out, n)
	}
	return out
}

func referencedShellVars(src []byte) []string {
	scrub := reShellSingleQuoted.ReplaceAll(src, []byte(`''`))
	scrub = reShellLineComment.ReplaceAllFunc(scrub, func(b []byte) []byte {
		if len(b) > 0 && b[0] != '#' {
			return b[:1]
		}
		return nil
	})

	all := uniqueEnvNames(reShellVar.FindAllSubmatch(scrub, -1))
	defaulted := make(map[string]bool)
	for _, m := range reShellVarDefaulted.FindAllSubmatch(scrub, -1) {
		defaulted[string(m[1])] = true
	}
	assigned := shellAssignedNames(scrub)

	out := all[:0]
	for _, n := range all {
		if assigned[n] || defaulted[n] {
			continue
		}
		out = append(out, n)
	}
	return out
}

func shellAssignedNames(src []byte) map[string]bool {
	set := make(map[string]bool)
	for _, m := range reShellAssign.FindAllSubmatch(src, -1) {
		set[string(m[1])] = true
	}
	for _, m := range reShellRead.FindAllSubmatch(src, -1) {
		for _, w := range strings.Fields(string(m[1])) {
			set[w] = true
		}
	}
	for _, m := range reShellForIn.FindAllSubmatch(src, -1) {
		set[string(m[1])] = true
	}
	return set
}

func pythonEnvDefaultStrings(src []byte) []string {
	var out []string
	for _, m := range rePyEnvVar.FindAllSubmatch(src, -1) {
		var tail []byte
		switch {
		case len(m[3]) > 0:
			tail = m[3]
		case len(m[5]) > 0:
			tail = m[5]
		default:
			continue
		}
		if v, ok := firstQuotedString(tail); ok {
			out = append(out, v)
		}
	}
	return out
}

func firstQuotedString(s []byte) (string, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\'' {
			for j := i + 1; j < len(s); j++ {
				if s[j] == c {
					return string(s[i+1 : j]), true
				}
			}
			return "", false
		}
	}
	return "", false
}

func referencedPythonEnvVarsAll(src []byte) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(name string) {
		if seen[name] || name == "" || shellInternalVar(name) {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, m := range rePyEnvVar.FindAllSubmatch(src, -1) {
		switch {
		case len(m[1]) > 0:
			add(string(m[1]))
		case len(m[2]) > 0:
			add(string(m[2]))
		case len(m[4]) > 0:
			add(string(m[4]))
		}
	}
	return out
}

func referencedPythonEnvVars(src []byte) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(name string) {
		if seen[name] || name == "" {
			return
		}
		if shellInternalVar(name) {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, m := range rePyEnvVar.FindAllSubmatch(src, -1) {
		switch {
		case len(m[1]) > 0:
			add(string(m[1]))
		case len(m[2]) > 0:
			if !pyCallHasSecondArg(m[3]) {
				add(string(m[2]))
			}
		case len(m[4]) > 0:
			if !pyCallHasSecondArg(m[5]) {
				add(string(m[4]))
			}
		}
	}
	return out
}

func pyCallHasSecondArg(rest []byte) bool {
	depth := 0
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				for j := i + 1; j < len(rest); j++ {
					if rest[j] != ' ' && rest[j] != '\t' && rest[j] != '\n' {
						return true
					}
				}
				return false
			}
		}
	}
	return false
}

func uniqueEnvNames(matches [][][]byte) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		name := string(m[1])
		if shellInternalVar(name) {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func shellInternalVar(name string) bool {
	switch name {
	case "HOME", "PATH", "LANG", "PWD", "BENTO_HOST_HOME", "BENTO_SCRIPT_DIR":
		return true
	case "IFS", "PS1", "PS2", "PS3", "PS4", "OLDPWD", "SHELL", "SHLVL",
		"REPLY", "LINENO", "FUNCNAME", "RANDOM", "SECONDS", "BASHPID",
		"BASH", "BASH_VERSION", "BASH_VERSINFO", "BASH_SOURCE",
		"BASH_LINENO", "BASH_ARGC", "BASH_ARGV", "BASH_SUBSHELL",
		"BASH_REMATCH", "BASH_COMMAND", "PIPESTATUS",
		"UID", "EUID", "PPID", "GROUPS", "HOSTNAME", "HOSTTYPE",
		"MACHTYPE", "OSTYPE", "COLUMNS", "LINES":
		return true
	}
	return false
}

func detectRelativePathHostMiss(scriptTail, scriptDir string) string {
	if scriptDir == "" {
		return ""
	}
	for _, m := range reRelativePathInOutput.FindAllStringSubmatch(scriptTail, -1) {
		rel := m[1]
		name := strings.TrimPrefix(rel, "./")
		if name == "" || strings.Contains(name, "..") {
			continue
		}
		if _, err := os.Stat(filepath.Join(scriptDir, name)); err == nil {
			return rel
		}
	}
	return ""
}

type envRelativePathDefault struct {
	name string
	def  string
}

// siblingRelativePathEnvs returns env vars in the script whose default value
// looks like a relative path (`./foo`, `foo.txt`), excluding `exclude`. Used
// to nudge users to pass all path-shaped --env values up front instead of
// discovering them one profile-failure at a time.
func siblingRelativePathEnvs(scriptPath, interp, exclude string) []envRelativePathDefault {
	defaults := scriptEnvDefaults(scriptPath, interp)
	var out []envRelativePathDefault
	for name, def := range defaults {
		if name == exclude {
			continue
		}
		if !looksLikeRelativePathDefault(def) {
			continue
		}
		out = append(out, envRelativePathDefault{name: name, def: def})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func looksLikeRelativePathDefault(v string) bool {
	if v == "" || strings.HasPrefix(v, "/") {
		return false
	}
	if strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") {
		return true
	}
	// Bare filename with an extension counts (e.g. "summary.txt").
	base := filepath.Base(v)
	return base == v && strings.Contains(base, ".") && !strings.ContainsAny(v, " \t")
}

func inferEnvVarForRelativePath(scriptPath, relPath string) string {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return ""
	}
	q := regexp.QuoteMeta(relPath)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):?[-=]` + q + `\}`),
		regexp.MustCompile(`os\.environ\.get\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*['"]` + q + `['"]`),
		regexp.MustCompile(`os\.getenv\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*['"]` + q + `['"]`),
	}
	for _, re := range patterns {
		if m := re.FindSubmatch(src); m != nil {
			return string(m[1])
		}
	}
	return ""
}

func noteShellCwdAssumption(w io.Writer, scriptPath, interp string) {
	if !isShellInterpreter(interp) {
		return
	}
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return
	}
	if !reShellCwdAssumption.Match(src) {
		return
	}
	fmt.Fprintln(w, "[bento]   the script references `$0` / `dirname $0` / `${BASH_SOURCE[0]}`. Inside the")
	fmt.Fprintln(w, "[bento]   sandbox `$0` is `/sandbox/script` (not the host path), so `dirname $0` and")
	fmt.Fprintln(w, "[bento]   `cd $(dirname $0)` won't locate sibling files. Use `$BENTO_SCRIPT_DIR` instead:")
	fmt.Fprintln(w, "[bento]     source \"$BENTO_SCRIPT_DIR/lib.sh\"     # was: source \"$(dirname \"$0\")/lib.sh\"")
	fmt.Fprintln(w, "[bento]     cd \"$BENTO_SCRIPT_DIR\"                 # was: cd \"$(dirname \"$0\")\"")
}

var (
	reTemplatedBasename = regexp.MustCompile(
		`[0-9]{10,}` + 
			`|[0-9]{4}-[0-9]{2}-[0-9]{2}` + 
			`|[0-9]{8}T[0-9]{6}` + 
			`|\b[0-9]{8}\b` + 
			`|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b` + 
			`|\b[0-9a-fA-F]{32}\b`)
	reLikelyPID = regexp.MustCompile(`(^|[._-])[0-9]{3,9}([._-]|$)`)
	reMktempRun = regexp.MustCompile(`[._-][A-Za-z0-9]{6,}`)
)
