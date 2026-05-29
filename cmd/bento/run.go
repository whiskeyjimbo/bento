package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/whiskeyjimbo/bento"
	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

var (
	runTimeout      time.Duration
	runEnv          = envFlag{}
	runNetMode      string
	runTelemetryOut string
	runInterpreter  string
	runPrompt       bool
	runAppendArgs   bool
	runReplaceArgs  bool
	runVerbose      bool
)

var runCmd = &cobra.Command{
	Use:   "run <manifest.yaml | script> [-- script-args...]",
	Short: "Run a script (zero-config) or a manifest in the sandbox",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: bento run needs a manifest or script path")
			fmt.Fprintln(os.Stderr, "  bento run <manifest.yaml | script>")
			fmt.Fprintln(os.Stderr, "  bento run --help     # full flag list")
			os.Exit(2)
		}

		target := args[0]
		scriptArgs := args[1:]

		// Misplaced flag checks and forwarding warnings
		if len(scriptArgs) > 0 && scriptArgs[0] == "--" {
			scriptArgs = scriptArgs[1:]
		} else if msg := misplacedBentoFlag(scriptArgs); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
			fmt.Fprintf(os.Stderr, "  bento run [flags] %s [-- script-args...]\n", target)
			fmt.Fprintln(os.Stderr, "  (if the token really is meant for the script, prefix it with `--` to disambiguate)")
			os.Exit(2)
		} else if note := noteForwardedFlags(scriptArgs); note != "" {
			fmt.Fprintln(os.Stderr, note)
		}

		warnEmptyEnv(os.Stderr, runEnv)
		mode, ok := bento.ParseNetworkMode(runNetMode)
		if !ok {
			fmt.Fprintf(os.Stderr, "error: unknown --network-mode %q (want auto|landlock|bridge)\n", runNetMode)
			os.Exit(2)
		}

		var telemetry io.Writer
		if runTelemetryOut == "-" {
			telemetry = os.Stdout
		} else if runTelemetryOut != "" {
			f, err := os.Create(runTelemetryOut)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error opening --telemetry-out:", err)
				os.Exit(1)
			}
			defer f.Close()
			telemetry = f
		}

		var grantCB bento.GrantCallback
		if runPrompt {
			cb, err := grants.TTYCallback()
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				fmt.Fprintln(os.Stderr, "[bento] --prompt/-i opens /dev/tty to ask interactively when the script tries to")
				fmt.Fprintln(os.Stderr, "[bento]   reach a host not on the allowlist. It needs a real terminal — drop -i in CI")
				fmt.Fprintln(os.Stderr, "[bento]   or non-interactive shells, and instead add the missing hosts to your manifest's")
				fmt.Fprintln(os.Stderr, "[bento]   `network: rules:` (or re-run `bento profile` to record them).")
				os.Exit(1)
			}
			grantCB = cb
		}

		if runAppendArgs && runReplaceArgs {
			fmt.Fprintln(os.Stderr, "error: --append-args and --replace-args are mutually exclusive")
			os.Exit(2)
		}
		if runReplaceArgs {
			fmt.Fprintln(os.Stderr, "[bento] note: --replace-args is the default now (kept for compatibility); pass --append-args for the old append behavior.")
		}

		var code int
		if isManifestPath(target) {
			code = runManifest(target, scriptArgs, runAppendArgs, runTimeout, runEnv, mode, telemetry, grantCB, runVerbose)
		} else {
			if runAppendArgs {
				fmt.Fprintln(os.Stderr, "[bento] note: --append-args has no effect in zero-config mode (no manifest args to append to).")
			}
			warnSiblingManifest(os.Stderr, target)
			code = runScriptZeroConfig(target, scriptArgs, runInterpreter, runTimeout, runEnv, mode, telemetry, grantCB, runVerbose)
		}
		os.Exit(code)
	},
}

func init() {
	runCmd.Flags().DurationVar(&runTimeout, "timeout", 0, "wall-clock timeout (e.g. 30s, 5m). 0 = no timeout.")
	runCmd.Flags().Var(runEnv, "env", "extra env var KEY=VALUE for the sandboxed script (repeatable)")
	runCmd.Flags().StringVar(&runNetMode, "network-mode", "auto", "auto|landlock|bridge — Linux network strategy")
	runCmd.Flags().StringVar(&runTelemetryOut, "telemetry-out", "", "capture script's fd 3 writes to this file path; '-' for stdout")
	runCmd.Flags().StringVar(&runInterpreter, "interpreter", "", "override auto-detected interpreter (zero-config mode only)")
	runCmd.Flags().BoolVarP(&runPrompt, "prompt", "i", false, "interactively prompt via /dev/tty on allowlist misses (per-Run cached)")
	runCmd.Flags().BoolVarP(&runVerbose, "verbose", "v", false, "show sandbox argv and other diagnostic logging")
	runCmd.Flags().BoolVar(&runAppendArgs, "append-args", false, "append command-line args after the manifest's 'args:' list (default: replace).")
	runCmd.Flags().BoolVar(&runReplaceArgs, "replace-args", false, "(deprecated, now the default) replace the manifest's 'args:' list with command-line args.")

	// Allow arbitrary command line arguments to bypass Cobra's strict flag validation after the script name is passed
	runCmd.Flags().SetInterspersed(false)
}

type hintMode int

const (
	hintModeZeroConfig hintMode = 1
	hintModeManifest   hintMode = 2
)

var (
	// Python: `PermissionError: [Errno 1] Operation not permitted: 'ls'`
	// Bash:   `bash: line 1: ls: Operation not permitted`
	// Go:     `fork/exec /usr/bin/ls: operation not permitted`
	reExecBlock = regexp.MustCompile(`(?i)(operation not permitted|permissionerror.*errno 1|fork/exec.*not permitted)`)
	// Names of binaries the script tried to spawn before seccomp refused.
	reExecBinBash = regexp.MustCompile(`(?mi)(?:^|\s)([^\s:]+):\s*[Oo]peration not permitted`)
	reExecBinFork = regexp.MustCompile(`(?i)fork/exec\s+(\S+):\s*operation not permitted`)
	reExecBinPy   = regexp.MustCompile(`(?i)permissionerror[^\n]*errno 1[^\n]*:\s*['"]([^'"]+)['"]`)
	// Python: `socket.gaierror: [Errno -3] Temporary failure in name resolution`
	reNetBlock = regexp.MustCompile(`(?i)(name resolution|could not resolve|no such host|name or service not known|getaddrinfo|connection refused|http-connect: deny|tunnel connection failed|x-bento-reject-host|bento blocked outbound connection)`)
	// Python: `PermissionError: [Errno 13] Permission denied: '/etc/...'`
	reFSBlock = regexp.MustCompile(`(?i)permission denied`)
	// Python: `OSError: [Errno 30] Read-only file system: '/path'`
	reWriteBlock = regexp.MustCompile(`(?i)(read-only file system|errno 30)`)
	// ENOENT lines paired with a nearby absolute path.
	reENOENTLine = regexp.MustCompile(`(?i).*(?:no such file or directory|errno 2[^0-9]).*`)
	reAbsPath    = regexp.MustCompile(`(?:'(/[^'\s]+)'|"(/[^"\s]+)"|(/(?:etc|usr|var|opt|home|tmp|root|run|srv|mnt|media|proc|sys)/[^\s:'"]*))`)
)

func warnSiblingManifest(w io.Writer, scriptPath string) {
	candidate := strings.TrimSuffix(scriptPath, filepath.Ext(scriptPath)) + ".manifest.yaml"
	if candidate == scriptPath {
		return
	}
	if _, err := os.Stat(candidate); err != nil {
		return
	}
	fmt.Fprintf(w, "[bento] note: %s exists next to %s; this run is using zero-config and ignoring it.\n", candidate, scriptPath)
	fmt.Fprintf(w, "[bento]   to run under the manifest instead:  bento run %s\n", candidate)
}

func hasShebang(scriptPath string) bool {
	f, err := os.Open(scriptPath)
	if err != nil {
		return false
	}
	defer f.Close()
	var buf [2]byte
	n, _ := f.Read(buf[:])
	return n == 2 && buf[0] == '#' && buf[1] == '!'
}

func runScriptZeroConfig(scriptPath string, scriptArgs []string, interpOverride string, timeout time.Duration, env map[string]string, netMode bento.NetworkMode, telemetry io.Writer, grantCB bento.GrantCallback, verbose bool) int {
	interp := interpOverride
	if interp == "" {
		resolved, source, err := bento.ResolveInterpreterDetailed(scriptPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		interp = resolved
		if verbose && source == bento.InterpreterFromExtension && !hasShebang(scriptPath) {
			fmt.Fprintf(os.Stderr, "[bento] note: inferred interpreter %q from %q extension (no shebang in %s).\n",
				interp, strings.ToLower(filepath.Ext(scriptPath)), scriptPath)
			fmt.Fprintln(os.Stderr, "[bento]   add `#!/usr/bin/env <interp>` to the script, or pass --interpreter=BIN, to silence this.")
		}
	}
	m, err := bento.PracticalStrictManifest(scriptPath, interp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	m.Args = append(m.Args, scriptArgs...)
	emitZeroConfigPosture(os.Stderr, scriptPath)
	warnStrippedShellVars(os.Stderr, scriptPath, interp, env, true /* includeIdentity */)
	preflightNetFired := warnLikelyNetworkUseInZeroConfig(os.Stderr, scriptPath, interp)
	tail := newTailBuffer(16 << 10)
	var fsOpens []bento.FSOpen
	opts := []bento.Option{
		bento.WithLogger(log.New(io.MultiWriter(os.Stderr, tail), "", 0)),
		bento.WithVerbose(verbose),
		bento.WithNetworkMode(netMode),
		bento.WithStdout(io.MultiWriter(os.Stdout, tail)),
		bento.WithStderr(io.MultiWriter(os.Stderr, tail)),
		bento.WithFilesystemObserver(func(opens []bento.FSOpen) { fsOpens = opens }),
	}
	if timeout > 0 {
		opts = append(opts, bento.WithTimeout(timeout))
	}
	if len(env) > 0 {
		opts = append(opts, bento.WithExtraEnv(env))
	}
	if telemetry != nil {
		opts = append(opts, bento.WithTelemetry(telemetry))
	}
	if grantCB != nil {
		opts = append(opts, bento.WithGrantCallback(grantCB))
	}
	code, err := bento.Run(context.Background(), m, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	emitPostRunHint(os.Stderr, hintModeZeroConfig, scriptPath, m, tail.String(), preflightNetFired)
	if emitSilentWriteWarning(os.Stderr, fsOpens, nil, tail.String()) && code == 0 {
		fmt.Fprintln(os.Stderr, "[bento] tmpfs writes are treated as errors; exiting non-zero.")
		code = 1
	}
	return code
}

func emitZeroConfigPosture(w io.Writer, scriptPath string) {
	scriptDir := filepath.Dir(scriptPath)
	if scriptDir == "" {
		scriptDir = "."
	}
	fmt.Fprintf(w, "[bento] zero-config: read=%s/  write=(none)  network=(none)  exec=blocked\n", scriptDir)
	fmt.Fprintln(w, "[bento]   (inside the sandbox cwd is /sandbox; pass argv paths as absolute —")
	fmt.Fprintln(w, "[bento]   relative paths resolve against /sandbox, not your shell's pwd.)")
}

func runManifest(manifestPath string, scriptArgs []string, appendArgs bool, timeout time.Duration, env map[string]string, netMode bento.NetworkMode, telemetry io.Writer, grantCB bento.GrantCallback, verbose bool) int {
	abs, err := filepath.Abs(manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	f, err := os.Open(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	m, err := bento.LoadManifest(f, bento.WithBaseDir(filepath.Dir(abs)))
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if m.LegacyExecField {
		fmt.Fprintln(os.Stderr, "[bento] warning: `exec: [...]` is deprecated and was never a per-binary allowlist;")
		fmt.Fprintln(os.Stderr, "[bento]   any non-empty value disables the subprocess block. Use `allow_exec: true` instead.")
	}
	if conflicts := mandatoryDenyConflicts(m.Read); len(conflicts) > 0 {
		fmt.Fprintln(os.Stderr, "[bento] error: manifest read: contains paths that conflict with mandatory-deny:")
		for _, c := range conflicts {
			fmt.Fprintf(os.Stderr, "[bento]   - %s\n", c)
		}
		fmt.Fprintln(os.Stderr, "[bento]   bento's mandatory-deny shadows ~/.bashrc, ~/.ssh/*, cloud creds, etc. by")
		fmt.Fprintln(os.Stderr, "[bento]   binding /dev/null over them. That binding can't be applied under a")
		fmt.Fprintln(os.Stderr, "[bento]   read-only parent — bwrap would fail with `Can't create file at ...`.")
		fmt.Fprintln(os.Stderr, "[bento]   narrow these paths to the specific subdirectories the script actually needs.")
		return 1
	}
	warnEnvNeedsValue(os.Stderr, abs, m.Env, env)
	var manifestPreflightNetFired bool
	if scriptForEnvScan := m.Script; scriptForEnvScan != "" {
		merged := make(map[string]string, len(env)+len(m.Env))
		for k, v := range env {
			merged[k] = v
		}
		for _, k := range m.Env {
			merged[k] = ""
		}
		warnStrippedShellVars(os.Stderr, scriptForEnvScan, m.Interpreter, merged, false /* includeIdentity */)
		manifestPreflightNetFired = warnLikelyFailureInManifest(os.Stderr, scriptForEnvScan, m)
	}
	emitEffectiveArgv(os.Stderr, m.Args, scriptArgs, appendArgs)
	if appendArgs {
		m.Args = append(m.Args, scriptArgs...)
	} else if len(scriptArgs) > 0 {
		m.Args = append([]string{}, scriptArgs...)
	}

	tail := newTailBuffer(16 << 10)
	var fsOpens []bento.FSOpen
	opts := []bento.Option{
		bento.WithLogger(log.New(io.MultiWriter(os.Stderr, tail), "", 0)),
		bento.WithVerbose(verbose),
		bento.WithStdout(io.MultiWriter(os.Stdout, tail)),
		bento.WithStderr(io.MultiWriter(os.Stderr, tail)),
		bento.WithFilesystemObserver(func(opens []bento.FSOpen) { fsOpens = opens }),
	}
	if timeout > 0 {
		opts = append(opts, bento.WithTimeout(timeout))
	}
	if len(env) > 0 {
		opts = append(opts, bento.WithExtraEnv(env))
	}
	opts = append(opts, bento.WithNetworkMode(netMode))
	if telemetry != nil {
		opts = append(opts, bento.WithTelemetry(telemetry))
	}
	if grantCB != nil {
		opts = append(opts, bento.WithGrantCallback(grantCB))
	}

	code, err := bento.Run(context.Background(), m, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		suggestValidateIfRelevant(os.Stderr, err, manifestPath)
		return 1
	}
	emitPostRunHint(os.Stderr, hintModeManifest, m.Script, m, tail.String(), manifestPreflightNetFired)
	declaredWrites := resolveDeclaredWrites(m, filepath.Dir(abs))
	if emitSilentWriteWarning(os.Stderr, fsOpens, declaredWrites, tail.String()) && code == 0 {
		fmt.Fprintln(os.Stderr, "[bento] tmpfs writes are treated as errors; exiting non-zero.")
		code = 1
	} else if code == 0 {
		emitPersistedWriteNote(os.Stderr, fsOpens, declaredWrites)
	}
	emitLimitsKillHint(os.Stderr, code, m.Limits)
	return code
}

func emitLimitsKillHint(w io.Writer, code int, lim *bento.Limits) {
	if lim == nil {
		return
	}
	switch code {
	case 137:
		if lim.Memory != "" {
			fmt.Fprintln(w, "[bento] ──────────────── hint ────────────────")
			fmt.Fprintf(w, "[bento] script exited 137 (SIGKILL). The manifest sets limits.memory=%s; an\n", lim.Memory)
			fmt.Fprintln(w, "[bento]   OOM kill is the most likely cause. Either raise the limit, or trim the")
			fmt.Fprintln(w, "[bento]   script's allocations. (Exit 137 with no Memory limit usually means an")
			fmt.Fprintln(w, "[bento]   external `kill -9` — not bento.)")
			fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
		}
	case 143:
		if lim.CPU != "" || lim.Tasks != 0 {
			fmt.Fprintln(w, "[bento] ──────────────── hint ────────────────")
			fmt.Fprintln(w, "[bento] script exited 143 (SIGTERM). If you passed `bento run --timeout=…`, the")
			fmt.Fprintln(w, "[bento]   wall-clock backstop likely fired. Otherwise check cgroup limits in the")
			fmt.Fprintln(w, "[bento]   manifest's limits: block.")
			fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
		}
	}
}

func suggestValidateIfRelevant(w io.Writer, err error, manifestPath string) {
	msg := err.Error()
	if !strings.Contains(msg, "script:") &&
		!strings.Contains(msg, "interpreter") &&
		!strings.Contains(msg, "no such file or directory") {
		return
	}
	fmt.Fprintf(w, "[bento] hint: paths in a manifest are relative to the manifest file.\n")
	fmt.Fprintf(w, "[bento]   run `bento validate %s` to see how bento resolves them.\n", manifestPath)
}

func warnStrippedShellVars(w io.Writer, scriptPath, interp string, env map[string]string, includeIdentity bool) {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return
	}
	var names []string
	switch {
	case isShellInterpreter(interp):
		names = referencedShellVars(src)
	case isPythonInterpreter(interp):
		names = referencedPythonEnvVars(src)
	default:
		return
	}
	type ref struct {
		name  string
		value string
		set   bool
	}
	var refs []ref
	for _, name := range names {
		if _, supplied := env[name]; supplied {
			continue
		}
		v, ok := os.LookupEnv(name)
		refs = append(refs, ref{name: name, value: v, set: ok})
	}
	var sandboxIdentityHits []string
	filtered := refs[:0]
	for _, r := range refs {
		switch r.name {
		case "USER", "LOGNAME":
			sandboxIdentityHits = append(sandboxIdentityHits, r.name)
		default:
			filtered = append(filtered, r)
		}
	}
	refs = filtered
	if includeIdentity && isShellInterpreter(interp) {
		for _, tok := range identityShellTokens(src) {
			sandboxIdentityHits = appendUniqueStr(sandboxIdentityHits, tok)
		}
	}
	if includeIdentity && isPythonInterpreter(interp) {
		for _, tok := range identityPythonTokens(src) {
			sandboxIdentityHits = appendUniqueStr(sandboxIdentityHits, tok)
		}
	}
	if !includeIdentity {
		sandboxIdentityHits = nil
	}
	if len(refs) == 0 && len(sandboxIdentityHits) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] ──────────────── note ────────────────")
	if len(refs) > 0 {
		var hostSet, hostUnset []ref
		for _, r := range refs {
			if r.set {
				hostSet = append(hostSet, r)
			} else {
				hostUnset = append(hostUnset, r)
			}
		}
		fmt.Fprintln(w, "[bento] script references host env var(s) that bento strips by default.")
		fmt.Fprintln(w, "[bento] preferred fix: add them to the manifest's `env:` allowlist so any host value")
		fmt.Fprintln(w, "[bento]   flows through automatically (and CI/teammates inherit the contract):")
		fmt.Fprintln(w, "[bento]   env:")
		for _, r := range refs {
			fmt.Fprintf(w, "[bento]     - %s\n", r.name)
		}
		if len(hostSet) > 0 {
			fmt.Fprintln(w, "[bento] one-off override (must precede the manifest/script path on the command line):")
			for _, r := range hostSet {
				fmt.Fprintf(w, "[bento]   bento run --env %s=%s <manifest-or-script> [args...]\n", r.name, suggestionEnvValue(r.name, r.value))
			}
		}
		if len(hostUnset) > 0 {
			fmt.Fprintln(w, "[bento] these vars are NOT currently set on your host (script will see empty strings):")
			for _, r := range hostUnset {
				fmt.Fprintf(w, "[bento]   $%s\n", r.name)
			}
		}
	}
	if len(sandboxIdentityHits) > 0 {
		fmt.Fprintf(w, "[bento] script references sandbox identity (%s) — inside the sandbox HOME=/sandbox,\n",
			strings.Join(sandboxIdentityHits, ", "))
		fmt.Fprintln(w, "[bento]   USER is unset, and `whoami` returns \"sandbox\" (bento's synthetic /etc/passwd).")
		fmt.Fprintln(w, "[bento]   This is by design; --env won't change it. If you need the host login name,")
		fmt.Fprintln(w, "[bento]   compute it on the host and pass it in: `bento run --env LOGIN=$USER <manifest>`.")
	}
	fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
}

func suggestionEnvValue(name, value string) string {
	if len(value) > 60 || strings.Count(value, ":") >= 2 {
		return `"$` + name + `"`
	}
	return shellQuote(value)
}

var (
	rePyNetCall = regexp.MustCompile(
		`\b(?:urllib\.request|urllib\.urlopen|urlopen|http\.client|httplib|` +
			`requests\.(?:get|post|put|delete|patch|head|request|Session)|` +
			`httpx\.|aiohttp\.|socket\.(?:create_connection|socket|gethostbyname)|` +
			`urllib3\.|smtplib\.|ftplib\.|imaplib\.|poplib\.)`)
	reShellNetCall = regexp.MustCompile(
		`(?m)(?:^|[\s;|&$(` + "`" + `])(curl|wget|nc|ncat|netcat|http|httpie|aws\s+s3)\b`)
	reShellExecCall = regexp.MustCompile(
		`(?m)(?:^|[\s;|&$(` + "`" + `])(awk|sed|grep|egrep|fgrep|find|xargs|jq|yq|git|tar|zip|unzip|gzip|gunzip|curl|wget|python|python3|node|npm|npx|ruby|gem|pip|pip3|go|cargo|rustc|gcc|g\+\+|clang|make|docker|kubectl|helm|terraform|aws|gcloud|az|ansible|puppet|chef|salt|ssh|scp|rsync|sftp|ftp|telnet|openssl|gpg|ssh-keygen|envsubst|eval|sh|bash|zsh|ksh|csh|tcsh)\b`)
	reDeniedHost = regexp.MustCompile(
		`(?i)(?:could not resolve host[:\s]+|lookup\s+|resolve host address\s+['"]?|name or service not known[:\s]+)([A-Za-z0-9_.-]+)`)
	rePyTracebackURL = regexp.MustCompile(`(https?)://([A-Za-z0-9_.-]+)(?::([0-9]+))?`)
	reProxyDenyHost = regexp.MustCompile(
		`(?i)(?:http-connect: DENY\s+|x-bento-reject-host:\s*|bento blocked outbound connection to\s+)([A-Za-z0-9_.-]+)(?::([0-9]+))?`)
	reProxyAllowHost = regexp.MustCompile(
		`(?i)http-connect: ALLOW\s+([A-Za-z0-9_.-]+)(?::[0-9]+)?`)
)

func warnLikelyNetworkUseInZeroConfig(w io.Writer, scriptPath, interp string) bool {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return false
	}
	var pat *regexp.Regexp
	switch {
	case isShellInterpreter(interp):
		pat = reShellNetCall
	case isPythonInterpreter(interp):
		pat = rePyNetCall
	}
	if pat != nil && pat.Match(src) {
		fmt.Fprintln(w, "[bento] preflight: script appears to make outbound network calls, but zero-config")
		fmt.Fprintln(w, "[bento]   mode blocks network access by default. The call will fail with a DNS or")
		fmt.Fprintln(w, "[bento]   connection error. Run `bento profile <script>` first to discover and allow")
		fmt.Fprintln(w, "[bento]   the specific host(s) it needs.")
		return true
	}
	return false
}

func warnLikelyFailureInManifest(w io.Writer, scriptPath string, m *bento.Manifest) bool {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return false
	}
	interp := m.Interpreter
	var pat *regexp.Regexp
	switch {
	case isShellInterpreter(interp):
		pat = reShellNetCall
	case isPythonInterpreter(interp):
		pat = rePyNetCall
	}
	netFired := false
	if pat != nil && pat.Match(src) && networkRulesEmpty(m.Network) {
		fmt.Fprintln(w, "[bento] preflight: script appears to make outbound network calls, but this manifest")
		fmt.Fprintln(w, "[bento]   has no `network.rules`. The call will fail with a DNS or connection error.")
		fmt.Fprintln(w, "[bento]   Add a `network:` block with the host(s) the script needs, or re-profile.")
		netFired = true
	} else if pat != nil && pat.Match(src) && len(scriptHostsMissingFromRules(src, m.Network)) > 0 {
		missing := scriptHostsMissingFromRules(src, m.Network)
		fmt.Fprintln(w, "[bento] preflight: script source references host(s) that aren't in this manifest's")
		fmt.Fprintln(w, "[bento]   `network.rules`. The proxy will reject these with 403 and the script's network")
		fmt.Fprintln(w, "[bento]   call will fail (typically buried in a multi-line traceback):")
		for _, h := range missing {
			fmt.Fprintf(w, "[bento]   - %s\n", h)
		}
		fmt.Fprintln(w, "[bento]   add to network.rules or re-profile to capture them.")
		netFired = true
	}
	if isShellInterpreter(interp) && !m.AllowExec && reShellExecCall.Match(src) {
		fmt.Fprintln(w, "[bento] preflight: shell script forks external commands but the manifest leaves")
		fmt.Fprintln(w, "[bento]   `allow_exec: false` (the default). Every subprocess will fail with EPERM.")
		fmt.Fprintln(w, "[bento]   Add `allow_exec: true` to the manifest if those subprocesses are expected.")
	}
	return netFired
}

var reScriptHostRef = regexp.MustCompile(`https?://([A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})`)

func scriptHostsMissingFromRules(src []byte, net *bento.NetworkPerm) []string {
	if net == nil || len(net.Rules) == 0 {
		return nil
	}
	matches := reScriptHostRef.FindAllSubmatch(src, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		host := strings.ToLower(string(m[1]))
		if seen[host] {
			continue
		}
		seen[host] = true
		matched := false
		for _, r := range net.Rules {
			if matchHostWildcard(host, r.Host) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, host)
		}
	}
	return out
}

func matchHostWildcard(host, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(host, pattern) || host == pattern[1:]
	}
	return host == pattern
}

func networkRulesEmpty(n *bento.NetworkPerm) bool {
	return n == nil || len(n.Rules) == 0
}

func mandatoryDenyConflicts(reads []string) []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil
	}
	var out []string
	all := append(spec.ExpandDangerousPaths(home), spec.ExpandDangerousWritePaths(home)...)
	for _, r := range reads {
		clean := filepath.Clean(r)
		for _, d := range all {
			if filepath.Dir(d) == clean {
				out = appendUniqueStr(out, r)
			}
		}
	}
	return out
}

func emitEffectiveArgv(w io.Writer, manifestArgs, cliArgs []string, appendMode bool) {
	if len(manifestArgs) == 0 || len(cliArgs) == 0 {
		// Nothing to clarify: either the manifest doesn't bake args or the
		// user didn't pass any. The trap only triggers at the intersection.
		return
	}
	var effective []string
	suffix := "cli args replaced manifest args (default; --append-args to extend instead)"
	if appendMode {
		effective = append(append([]string{}, manifestArgs...), cliArgs...)
		suffix = "--append-args extended manifest args"
	} else {
		effective = cliArgs
	}
	fmt.Fprintf(w, "[bento] argv: %q (manifest: %d, cli: %d, %s)\n",
		effective, len(manifestArgs), len(cliArgs), suffix)
}

func warnEnvNeedsValue(w io.Writer, manifestPath string, allowlist []string, cliEnv map[string]string) {
	var missing []string
	for _, name := range allowlist {
		if _, supplied := cliEnv[name]; supplied {
			continue
		}
		if _, set := os.LookupEnv(name); !set {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return
	}
	sort.Strings(missing)
	// Profile recorded the actual values it used at profile time in the
	// manifest header (`#   --env NAME=value` or `#   --env NAME=<absolute-host-path>
	// (recorded at profile time: /abs/path)`). Reuse them in the example so the
	// junior doesn't have to scroll up and copy them by hand.
	recorded := readProfileTimeEnvValues(manifestPath)
	fmt.Fprintln(w, "[bento] ──────────────── note ────────────────")
	fmt.Fprintln(w, "[bento] the manifest allows these host env vars, but they are NOT currently")
	fmt.Fprintln(w, "[bento]   set in your environment (script will see empty strings):")
	for _, name := range missing {
		fmt.Fprintf(w, "[bento]     - %s\n", name)
	}
	fmt.Fprintln(w, "[bento]   to supply values, either export them in your shell first or pass")
	fmt.Fprintln(w, "[bento]   them literally on the command line, e.g.:")
	var examples []string
	var reusedRecorded bool
	for _, name := range missing {
		if v, ok := recorded[name]; ok {
			examples = append(examples, fmt.Sprintf("--env %s=%s", name, v))
			reusedRecorded = true
		} else {
			examples = append(examples, fmt.Sprintf("--env %s=VALUE", name))
		}
	}
	fmt.Fprintf(w, "[bento]     bento run %s %s\n", strings.Join(examples, " "), filepath.Base(manifestPath))
	if reusedRecorded {
		fmt.Fprintln(w, "[bento]   (recorded values come from `bento profile` — may differ from what you need now.)")
	}
	fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
}

// readProfileTimeEnvValues returns NAME → value pairs the profile recorded in
// the manifest header. Supports two emitted shapes:
//   - `#   --env NAME=value`
//   - `#   --env NAME=<absolute-host-path>   (recorded at profile time: /abs)`
//
// Returns an empty map if the manifest can't be read or has no such block.
func readProfileTimeEnvValues(manifestPath string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return out
	}
	reRecordedPath := regexp.MustCompile(
		`^#\s*--env\s+([A-Za-z_][A-Za-z0-9_]*)=<absolute-host-path>\s*\(recorded at profile time:\s*(.+?)\)\s*$`)
	reLiteral := regexp.MustCompile(
		`^#\s*--env\s+([A-Za-z_][A-Za-z0-9_]*)=(.+?)\s*$`)
	for _, line := range strings.Split(string(data), "\n") {
		if m := reRecordedPath.FindStringSubmatch(line); m != nil {
			out[m[1]] = m[2]
			continue
		}
		if m := reLiteral.FindStringSubmatch(line); m != nil {
			// Skip the `<absolute-host-path>` template literal — that's the
			// outer pattern's placeholder, not a real value.
			if strings.HasPrefix(m[2], "<") {
				continue
			}
			out[m[1]] = m[2]
		}
	}
	return out
}

func emitPostRunHint(w io.Writer, mode hintMode, scriptPath string, m *bento.Manifest, stderrTail string, preflightNetworkFired bool) {
	var sections [][]string

	if matchesExecBlock(stderrTail) && !m.AllowExec {
		switch mode {
		case hintModeZeroConfig:
			sections = append(sections, []string{
				"[bento] zero-config blocks subprocess spawn (execve) by default.",
				"[bento]   Run `bento profile --allow-exec <script>` to record sibling commands",
				"[bento]   and generate a manifest with `allow_exec: true` already set.",
			})
		case hintModeManifest:
			sections = append(sections, []string{
				"[bento] script tried to spawn a subprocess, but the manifest sets `allow_exec: false`.",
				"[bento]   To permit subprocess spawning, set `allow_exec: true` in the manifest.",
			})
		}
	}

	if matchesNetworkBlock(stderrTail) {
		denied := extractDeniedHosts(stderrTail)
		if preflightNetworkFired && mode == hintModeZeroConfig {
			// Preflight already explained the cause at the top of output, but the
			// script's traceback has since scrolled it offscreen. Re-surface a short
			// trailer with the actionable next step so it's the last thing on screen.
			lines := []string{
				"[bento] the network error above is zero-config's deny-by-default kicking in",
				"[bento]   (see preflight at top of output). Run `bento profile <script>` to discover",
				"[bento]   and allow the specific host(s) the script needs.",
			}
			if len(denied) > 0 {
				lines = append(lines, "[bento] hosts the script tried to reach:")
				for _, h := range denied {
					lines = append(lines, "  - "+h)
				}
			}
			sections = append(sections, lines)
		} else if !preflightNetworkFired && len(denied) > 0 {
			switch mode {
			case hintModeZeroConfig:
				lines := []string{
					"[bento] script tried to contact host(s) that bento blocked (zero-config blocks network):",
				}
				for _, h := range denied {
					lines = append(lines, "  - "+h)
				}
				lines = append(lines,
					"[bento] run `bento profile <script>` first to discover and allow the specific",
					"[bento] host(s) it needs in the generated manifest.",
				)
				sections = append(sections, lines)
			case hintModeManifest:
				lines := []string{
					"[bento] script tried to contact host(s) not covered by the manifest's `network:` block:",
				}
				for _, h := range denied {
					lines = append(lines, "  - "+h)
				}
				lines = append(lines,
					"[bento] add the host(s) (or a wildcard like `*.example.com`) under `network.rules:`",
					"[bento] in the manifest and re-run. Unrecognized hosts are hard-denied by default.",
					"[bento]   The script's own error output (connection refused / Forbidden / TCP",
					"[bento]   reset) is the same event surfaced from the script's side.",
				)
				sections = append(sections, lines)
			}
		}
	}

	if matchesWriteBlock(stderrTail) {
		switch mode {
		case hintModeZeroConfig:
			sections = append(sections, []string{
				"[bento] zero-config grants no write access — not even to the script's own directory.",
				"[bento]   `bento profile <script>` runs with /tmp and the script's directory writable",
				"[bento]   AND records the paths the script wrote to, then emits a manifest with those",
				"[bento]   paths already in `write:`. Review, trim, and re-run with `bento run <manifest>.yaml`.",
			})
		case hintModeManifest:
			sections = append(sections, []string{
				"[bento] script tried to write a path not covered by the manifest's `write:` list.",
				"[bento]   Add the path (or its containing directory) to `write:` and re-run. Paths in",
				"[bento]   `read:` only are bound read-only inside the sandbox.",
			})
		}
	}

	if !matchesWriteBlock(stderrTail) && matchesFSBlock(stderrTail) {
		switch mode {
		case hintModeZeroConfig:
			sections = append(sections, []string{
				"[bento] zero-config only grants read access to the script's directory. If the script needs",
				"[bento]   other paths, run `bento profile <script>` and add them to the generated manifest's `read:` list.",
			})
		case hintModeManifest:
			sections = append(sections, []string{
				"[bento] script tried to read a path not covered by the manifest's `read:` or `write:` list.",
				"[bento]   Add the path (or its containing directory) to `read:` and re-run.",
			})
		}
	}

	if len(sections) > 0 {
		fmt.Fprintln(w, "[bento] ──────────────── hint ────────────────")
		for i, sec := range sections {
			if i > 0 {
				fmt.Fprintln(w, "[bento]")
			}
			for _, l := range sec {
				fmt.Fprintln(w, l)
			}
		}
		fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
		return
	}

	if paths := pathsMissingButOnHost(stderrTail); len(paths) > 0 {
		lines := []string{
			"[bento] script tried to open paths that aren't bind-mounted into the sandbox:",
		}
		for _, p := range paths {
			lines = append(lines, "[bento]   "+p)
		}
		lines = append(lines,
			"[bento] add them (or a parent directory) to the manifest's `read:` (or `write:`) list —",
			"[bento]   bento's filesystem isolation is deny-by-default, so undeclared paths are invisible",
			"[bento]   even when they exist on disk. \"No such file or directory\" here usually means",
			"[bento]   \"not declared in the manifest\", not \"actually missing\".",
		)
		fmt.Fprintln(w, "[bento] ──────────────── hint ────────────────")
		for _, l := range lines {
			fmt.Fprintln(w, l)
		}
		fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
		return
	}
}

func pathsMissingButOnHost(stderrTail string) []string {
	lines := reENOENTLine.FindAllString(stderrTail, -1)
	if len(lines) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, line := range lines {
		for _, m := range reAbsPath.FindAllStringSubmatch(line, -1) {
			p := m[1]
			if p == "" {
				p = m[2]
			}
			if p == "" {
				p = m[3]
			}
			if p == "" || !strings.HasPrefix(p, "/") {
				continue
			}
			if strings.HasPrefix(p, "/sandbox") {
				continue
			}
			if seen[p] {
				continue
			}
			seen[p] = true
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			} else if _, err := os.Stat(filepath.Dir(p)); err == nil {
				out = append(out, p)
			}
			if len(out) >= 5 {
				return out
			}
		}
	}
	return out
}

func extractDeniedHosts(stderrTail string) []string {
	// Allowed-host set: the http-connect ALLOW log lines name hosts the proxy
	// actually let through. The script's own output frequently echoes those
	// hosts back (e.g. a JSON response containing the request URL), which the
	// permissive rePyTracebackURL fallback would otherwise pick up as "denied".
	// Subtracting the ALLOW set keeps the hint focused on hosts the manifest
	// truly doesn't cover.
	allowed := make(map[string]bool)
	for _, m := range reProxyAllowHost.FindAllStringSubmatch(stderrTail, -1) {
		allowed[strings.ToLower(m[1])] = true
	}
	var out []string
	seen := make(map[string]bool)
	add := func(h string) {
		h = strings.ToLower(h)
		if allowed[h] || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, m := range reProxyDenyHost.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
	}
	for _, m := range reDeniedHost.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
	}
	for _, m := range rePyTracebackURL.FindAllStringSubmatch(stderrTail, -1) {
		add(m[2])
	}
	return out
}

func matchesExecBlock(s string) bool { return reExecBlock.MatchString(s) }

func extractDeniedBinaries(stderrTail string) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(b string) {
		b = filepath.Base(b)
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	for _, m := range reExecBinBash.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
	}
	for _, m := range reExecBinFork.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
	}
	for _, m := range reExecBinPy.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
	}
	return out
}

func matchesNetworkBlock(s string) bool {
	return reNetBlock.MatchString(s)
}

func matchesFSBlock(s string) bool {
	return reFSBlock.MatchString(s) && !reExecBlock.MatchString(s)
}

func matchesWriteBlock(s string) bool { return reWriteBlock.MatchString(s) }

func emitSilentWriteWarning(w io.Writer, opens []bento.FSOpen, declaredWrites []string, scriptTail string) bool {
	var lost []string
	for _, e := range opens {
		if !e.OK || !e.Write {
			continue
		}
		if isSandboxTmpfsPath(e.Path) {
			lost = appendUniqueStr(lost, e.Path)
		}
	}
	if len(lost) == 0 {
		return false
	}
	sort.Strings(lost)
	fmt.Fprintln(w, "[bento] ──────────────── warning ────────────────")
	fmt.Fprintf(w, "[bento] script successfully wrote %d %s inside the sandbox tmpfs that DID NOT persist\n",
		len(lost), pluralize(len(lost), "file", "files"))
	fmt.Fprintln(w, "[bento]   on the host. Inside the sandbox `./` resolves to `/sandbox/` (a fresh tmpfs)")
	fmt.Fprintln(w, "[bento]   and relative writes land there and are lost on exit. Lost files:")
	for _, p := range lost {
		fmt.Fprintf(w, "[bento]     - %s\n", p)
	}
	fmt.Fprintln(w, "[bento]")
	fmt.Fprintln(w, "[bento] fix: point the script at an absolute host path (usually via env var or arg), and")
	fmt.Fprintln(w, "[bento]   add the host target directory to the manifest's `write:` list. Adding the")
	fmt.Fprintln(w, "[bento]   host directory to `write:` ALONE will not help — the script must also be pointed")
	fmt.Fprintln(w, "[bento]   at the host path.")
	fmt.Fprintln(w, "[bento] ─────────────────────────────────────────")
	return true
}

func isSandboxTmpfsPath(p string) bool {
	if !strings.HasPrefix(p, spec.SandboxRoot+"/") {
		return false
	}
	switch p {
	case spec.SandboxScriptPath, spec.SandboxLauncherPath, spec.SandboxProxychainsConfPath:
		return false
	}
	rest := p[len(spec.SandboxRoot)+1:]
	if strings.HasPrefix(rest, ".bento-") {
		return false
	}
	return true
}

func resolveDeclaredWrites(m *bento.Manifest, baseDir string) []string {
	if m == nil {
		return nil
	}
	var out []string
	for _, p := range m.Write {
		if !filepath.IsAbs(p) && baseDir != "" {
			p = filepath.Join(baseDir, p)
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

func emitPersistedWriteNote(w io.Writer, opens []bento.FSOpen, declaredWrites []string) {
	if len(opens) == 0 || len(declaredWrites) == 0 {
		return
	}
	declared := make(map[string]bool, len(declaredWrites))
	prefixes := make([]string, 0, len(declaredWrites))
	for _, p := range declaredWrites {
		declared[p] = true
		prefixes = append(prefixes, p+"/")
	}
	seen := make(map[string]bool)
	var persisted []string
	for _, o := range opens {
		if !(o.Write && o.OK) {
			continue
		}
		if !declared[o.Path] {
			under := false
			for _, pfx := range prefixes {
				if strings.HasPrefix(o.Path, pfx) {
					under = true
					break
				}
			}
			if !under {
				continue
			}
		}
		if seen[o.Path] {
			continue
		}
		seen[o.Path] = true
		persisted = append(persisted, o.Path)
	}
	if len(persisted) == 0 {
		return
	}
	// Stat each path for a byte-count: a script that silently produces an
	// empty file (e.g. an API fetch that returned 0 items) otherwise gets
	// the same green "persisted writes:" line as a script that wrote real
	// output. Surfacing the size lets a junior catch the silent no-op
	// without an extra `ls`.
	if len(persisted) == 1 {
		fmt.Fprintf(w, "[bento] persisted writes: %s%s\n", persisted[0], persistedSizeSuffix(persisted[0]))
		return
	}
	fmt.Fprintln(w, "[bento] persisted writes:")
	for _, p := range persisted {
		fmt.Fprintf(w, "[bento]   %s%s\n", p, persistedSizeSuffix(p))
	}
}

func persistedSizeSuffix(p string) string {
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		return ""
	}
	n := st.Size()
	switch {
	case n == 0:
		return " (0 bytes — empty file; script may have silently produced no output)"
	case n == 1:
		return " (1 byte)"
	case n < 1024:
		return fmt.Sprintf(" (%d bytes)", n)
	case n < 1024*1024:
		return fmt.Sprintf(" (%.1f KiB)", float64(n)/1024)
	default:
		return fmt.Sprintf(" (%.1f MiB)", float64(n)/(1024*1024))
	}
}
