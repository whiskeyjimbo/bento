// bento: CLI for invoking the bento sandbox.
//
//	bento doctor [--skip-network] [--fail-fast]
//	bento run [--timeout=DUR] [--env KEY=VALUE]... <manifest.yaml>
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/whiskeyjimbo/bento"
	"github.com/whiskeyjimbo/bento/internal/grants"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(0)
	}
	switch os.Args[1] {
	case "doctor":
		os.Exit(cmdDoctor(os.Args[2:]))
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "validate":
		os.Exit(cmdValidate(os.Args[2:]))
	case "setup":
		os.Exit(cmdInit(os.Args[2:]))
	case "init":
		fmt.Fprintln(os.Stderr, "[bento] note: `bento init` is now `bento setup` (host-readiness check).")
		fmt.Fprintln(os.Stderr, "[bento]       For 'generate a starter manifest' use `bento profile <script>`.")
		os.Exit(cmdInit(os.Args[2:]))
	case "profile":
		os.Exit(cmdProfile(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  bento run [-v] [--timeout=DUR] [--env KEY=VALUE]... [--network-mode=auto|landlock|bridge] <manifest.yaml | script> [-- script-args...]")
	fmt.Fprintln(os.Stderr, "      run a script (zero-config) or a manifest. Zero-config picks an interpreter")
	fmt.Fprintln(os.Stderr, "      from extension, shebang, or — for ELF binaries — runs them directly.")
	fmt.Fprintln(os.Stderr, "      Use `--` to separate bento flags from arguments passed to the script.")
	fmt.Fprintln(os.Stderr, "  bento profile [-v] [--out=PATH] [--force] [--interpreter=BIN] <script>")
	fmt.Fprintln(os.Stderr, "      record one trial run and emit <script>.manifest.yaml. Start here.")
	fmt.Fprintln(os.Stderr, "  bento validate [-q] <manifest.yaml>")
	fmt.Fprintln(os.Stderr, "      load the manifest and print the resolved interpreter, paths, and posture.")
	fmt.Fprintln(os.Stderr, "  bento doctor [--skip-network] [--fail-fast]")
	fmt.Fprintln(os.Stderr, "      check the host for required and optional sandboxing primitives.")
	fmt.Fprintln(os.Stderr, "  bento setup [--dry-run]")
	fmt.Fprintln(os.Stderr, "      install/configure host bits (AppArmor profile, etc.) where needed.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  bento <subcommand> --help    flags for one subcommand")
	fmt.Fprintln(os.Stderr, "  bento --help                 this help screen")
}

func cmdProfile(args []string) int {
	fs := flag.NewFlagSet("profile", flag.ExitOnError)
	out := fs.String("out", "", "manifest output path (default: <script>.manifest.yaml)")
	force := fs.Bool("force", false, "overwrite the output file if it already exists")
	interpreter := fs.String("interpreter", "", "override auto-detected interpreter")
	verbose := fs.Bool("verbose", false, "show sandbox argv and other diagnostic logging")
	fs.BoolVar(verbose, "v", false, "shorthand for --verbose")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
		return 2
	}
	scriptPath := fs.Arg(0)

	interp := *interpreter
	if interp == "" {
		var err error
		interp, err = bento.ResolveInterpreter(scriptPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	m, err := bento.PracticalStrictManifest(scriptPath, interp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	outPath := *out
	if outPath == "" {
		outPath = strings.TrimSuffix(scriptPath, filepath.Ext(scriptPath)) + ".manifest.yaml"
	}
	if !*force {
		if _, err := os.Stat(outPath); err == nil {
			fmt.Fprintf(os.Stderr, "[bento] %s already exists. To proceed, choose one:\n", outPath)
			fmt.Fprintf(os.Stderr, "[bento]   bento profile --force %s            # overwrite the existing manifest\n", scriptPath)
			fmt.Fprintf(os.Stderr, "[bento]   bento profile --out=PATH %s         # write somewhere else\n", scriptPath)
			fmt.Fprintf(os.Stderr, "[bento]   rm %s && bento profile %s           # delete the existing one first\n", outPath, scriptPath)
			return 1
		}
	}

	fmt.Fprintf(os.Stderr, "[bento] profiling %q (permissive network)...\n", scriptPath)
	tail := newTailBuffer(16 << 10)
	result, err := bento.Profile(context.Background(), m,
		bento.WithLogger(log.New(os.Stderr, "", log.LstdFlags)),
		bento.WithVerbose(*verbose),
		bento.WithStderr(io.MultiWriter(os.Stderr, tail)),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[bento] script exit code: %d\n\n", result.ExitCode)
	printObservations(os.Stderr, result.Observations)
	printFSObservations(os.Stderr, result.FSObservations)
	printDeniedAttempts(os.Stderr, result.DeniedAttempts)

	if result.ExitCode != 0 && !*force {
		if matchesExecBlock(tail.String()) {
			fmt.Fprintln(os.Stderr, "[bento] the script tried to spawn a subprocess, which `bento profile` still blocks")
			fmt.Fprintln(os.Stderr, "[bento]   (profile relaxes network, not exec). Profile cannot observe scripts that exec.")
			fmt.Fprintln(os.Stderr, "[bento]   Hand-author a manifest with `allow_exec: true` and run with `bento run`.")
		} else {
			fmt.Fprintf(os.Stderr, "[bento] trial run exited %d — skipping manifest write (the run did not get far\n", result.ExitCode)
			fmt.Fprintln(os.Stderr, "[bento] enough to record useful observations). Re-run with --force to write anyway.")
		}
		return result.ExitCode
	}

	rewriteManifestForOutput(result.SuggestedManifest, outPath)

	yamlBytes, err := yaml.Marshal(result.SuggestedManifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error marshaling suggested manifest:", err)
		return 1
	}
	header := "# generated by `bento profile " + scriptPath + "` — review and trim before use\n"
	if len(result.DeniedAttempts) > 0 {
		header += "#\n# Script attempted to open these paths, blocked by bento's mandatory-deny\n# list (cannot be granted via manifest rules):\n"
		for _, p := range result.DeniedAttempts {
			header += "#   - " + p + "\n"
		}
	}
	header += "\n"
	if err := os.WriteFile(outPath, append([]byte(header), yamlBytes...), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error writing manifest:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[bento] wrote %s — review and trim before running with `bento run`\n", outPath)
	return result.ExitCode
}

// rewriteManifestForOutput makes a generated manifest portable:
//   - paths under the manifest's directory become relative (so moving the
//     directory doesn't break the manifest);
//   - for ELF binaries (interpreter == script), the redundant `interpreter:`
//     field is cleared so it's omitted from the YAML.
func rewriteManifestForOutput(m *bento.Manifest, outPath string) {
	if m == nil {
		return
	}
	outAbs, err := filepath.Abs(outPath)
	if err != nil {
		return
	}
	outDir := filepath.Dir(outAbs)

	relIfChild := func(p string) string {
		if p == "" || !filepath.IsAbs(p) {
			return p
		}
		rel, err := filepath.Rel(outDir, p)
		if err != nil {
			return p
		}
		// Only rewrite if the path stays inside outDir; avoid emitting
		// "../../.." style relatives that obscure the real location.
		if strings.HasPrefix(rel, "..") {
			return p
		}
		if rel == "" {
			return "."
		}
		return rel
	}

	elf := m.Interpreter != "" && m.Script != "" && m.Interpreter == m.Script
	m.Script = relIfChild(m.Script)
	for i, p := range m.Read {
		m.Read[i] = relIfChild(p)
	}
	for i, p := range m.Write {
		m.Write[i] = relIfChild(p)
	}
	if elf {
		m.Interpreter = ""
	}
}

func printFSObservations(w io.Writer, paths []string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] observed filesystem opens:")
	for _, p := range paths {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintln(w)
}

func printDeniedAttempts(w io.Writer, paths []string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] mandatory-deny hits (script attempted, cannot be granted):")
	for _, p := range paths {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintln(w)
}

func printObservations(w io.Writer, obs []bento.NetworkObservation) {
	if len(obs) == 0 {
		fmt.Fprintln(w, "[bento] no network observations")
		return
	}
	fmt.Fprintln(w, "[bento] observed network:")
	fmt.Fprintf(w, "  %-32s  %-6s  %s\n", "Host", "Port", "Count")
	fmt.Fprintf(w, "  %-32s  %-6s  %s\n", "----", "----", "-----")
	for _, o := range obs {
		fmt.Fprintf(w, "  %-32s  %-6d  %d\n", o.Host, o.Port, o.Count)
	}
	fmt.Fprintln(w)
}

func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "print plan without making changes")
	fs.Parse(args)
	var opts []bento.InitOption
	if *dryRun {
		opts = append(opts, bento.WithDryRun())
	}
	_, err := bento.Init(context.Background(), os.Stdout, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	quiet := fs.Bool("quiet", false, "print only 'ok' or the error (script-friendly)")
	fs.BoolVar(quiet, "q", false, "shorthand for --quiet")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
		return 2
	}
	path := fs.Arg(0)
	abs, _ := filepath.Abs(path)
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer f.Close()
	m, err := bento.LoadManifest(f, bento.WithBaseDir(filepath.Dir(abs)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if m.LegacyExecField {
		fmt.Fprintln(os.Stderr, "[bento] warning: `exec: [...]` is deprecated; use `allow_exec: true` instead.")
	}
	if *quiet {
		fmt.Println("ok")
		return 0
	}
	printResolvedManifest(os.Stdout, m, abs)
	return 0
}

func printResolvedManifest(w io.Writer, m *bento.Manifest, manifestPath string) {
	fmt.Fprintf(w, "manifest: %s — ok\n\n", manifestPath)

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
		} else {
			fmt.Fprintf(w, "interpreter: %s  (NOT FOUND on $PATH)\n", interp)
		}
	}
	if _, err := os.Stat(script); err == nil {
		fmt.Fprintf(w, "script:      %s\n", script)
	} else {
		fmt.Fprintf(w, "script:      %s  (NOT FOUND)\n", script)
	}

	if len(m.Args) > 0 {
		fmt.Fprintf(w, "args:        %v\n", m.Args)
	}

	fmt.Fprintln(w)
	if len(m.Read) == 0 {
		fmt.Fprintln(w, "read:        (none)")
	} else {
		fmt.Fprintln(w, "read:")
		for _, p := range m.Read {
			fmt.Fprintf(w, "  - %s\n", p)
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
	fmt.Fprintln(w, "(mandatory-deny paths — SSH keys, cloud creds, shell rc files — are always shadowed)")
}

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	skipNetwork := fs.Bool("skip-network", false, "omit network-dependent checks (faster CI)")
	failFast := fs.Bool("fail-fast", false, "stop at the first FAIL")
	fs.Parse(args)

	var opts []bento.CheckOption
	if *skipNetwork {
		opts = append(opts, bento.WithSkipNetwork())
	}
	if *failFast {
		opts = append(opts, bento.WithFailFast())
	}
	if bento.Doctor(os.Stdout, opts...) {
		return 0
	}
	return 1
}

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

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	timeout := fs.Duration("timeout", 0, "wall-clock timeout (e.g. 30s, 5m). 0 = no timeout.")
	env := envFlag{}
	fs.Var(env, "env", "extra env var KEY=VALUE for the sandboxed script (repeatable)")
	netMode := fs.String("network-mode", "auto", "auto|landlock|bridge — Linux network strategy")
	telemetryOut := fs.String("telemetry-out", "", "capture script's fd 3 writes to this file path; '-' for stdout")
	interpreter := fs.String("interpreter", "", "override auto-detected interpreter (zero-config mode only)")
	prompt := fs.Bool("prompt", false, "interactively prompt via /dev/tty on allowlist misses (per-Run cached)")
	fs.BoolVar(prompt, "i", false, "shorthand for --prompt")
	verbose := fs.Bool("verbose", false, "show sandbox argv and other diagnostic logging")
	fs.BoolVar(verbose, "v", false, "shorthand for --verbose")
	fs.Parse(args)

	if fs.NArg() < 1 {
		usage()
		return 2
	}
	scriptArgs := fs.Args()[1:]
	// Convention: a leading `--` separates bento flags from script args
	// (`bento run foo.py -- --flag`). The separator itself is not forwarded.
	if len(scriptArgs) > 0 && scriptArgs[0] == "--" {
		scriptArgs = scriptArgs[1:]
	}
	mode, ok := bento.ParseNetworkMode(*netMode)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown --network-mode %q (want auto|landlock|bridge)\n", *netMode)
		return 2
	}
	var telemetry io.Writer
	if *telemetryOut == "-" {
		telemetry = os.Stdout
	} else if *telemetryOut != "" {
		f, err := os.Create(*telemetryOut)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error opening --telemetry-out:", err)
			return 1
		}
		defer f.Close()
		telemetry = f
	}
	var grantCB bento.GrantCallback
	if *prompt {
		cb, err := grants.TTYCallback()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		grantCB = cb
	}

	target := fs.Arg(0)
	if isManifestPath(target) {
		return runManifest(target, scriptArgs, *timeout, env, mode, telemetry, grantCB, *verbose)
	}
	return runScriptZeroConfig(target, scriptArgs, *interpreter, *timeout, env, mode, telemetry, grantCB, *verbose)
}

func isManifestPath(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

// runScriptZeroConfig synthesizes a practical-strict manifest and runs it.
func runScriptZeroConfig(scriptPath string, scriptArgs []string, interpOverride string, timeout time.Duration, env map[string]string, netMode bento.NetworkMode, telemetry io.Writer, grantCB bento.GrantCallback, verbose bool) int {
	interp := interpOverride
	if interp == "" {
		var err error
		interp, err = bento.ResolveInterpreter(scriptPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	m, err := bento.PracticalStrictManifest(scriptPath, interp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	m.Args = append(m.Args, scriptArgs...)
	tail := newTailBuffer(16 << 10)
	opts := []bento.Option{
		bento.WithLogger(log.New(os.Stderr, "", log.LstdFlags)),
		bento.WithVerbose(verbose),
		bento.WithNetworkMode(netMode),
		bento.WithStderr(io.MultiWriter(os.Stderr, tail)),
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
	if code != 0 {
		emitZeroConfigHint(os.Stderr, scriptPath, m, tail.String())
	}
	return code
}

// emitZeroConfigHint inspects the script's stderr to point the user at the
// likely cause of failure: exec block, DNS/no-network, or denied file access.
// Silent when nothing matches.
func emitZeroConfigHint(w io.Writer, scriptPath string, m *bento.Manifest, stderrTail string) {
	if matchesExecBlock(stderrTail) {
		fmt.Fprintln(w, "[bento] note: zero-config blocks subprocess execve. If the script needs to spawn processes,")
		fmt.Fprintln(w, "[bento]   write a manifest with `allow_exec: true` and run with `bento run <manifest>.yaml`.")
		return
	}
	if m.Network == nil && matchesNetworkBlock(stderrTail) {
		fmt.Fprintln(w, "[bento] note: zero-config runs have no network access. If the script needs network, try:")
		fmt.Fprintf(w, "[bento]   bento profile %s   # records observed hosts into a manifest\n", scriptPath)
		fmt.Fprintln(w, "[bento]   bento run <manifest>.yaml  # re-run under the trimmed manifest")
		return
	}
	if matchesWriteBlock(stderrTail) {
		fmt.Fprintln(w, "[bento] note: zero-config grants no write access. If the script needs to write files,")
		fmt.Fprintln(w, "[bento]   run `bento profile <script>` and add the destination paths to the manifest's `write:` list,")
		fmt.Fprintln(w, "[bento]   then re-run with `bento run <manifest>.yaml`.")
		return
	}
	if matchesFSBlock(stderrTail) {
		fmt.Fprintln(w, "[bento] note: zero-config only grants read access to the script's directory. If the script needs")
		fmt.Fprintln(w, "[bento]   other paths, run `bento profile <script>` and add them to the generated manifest's `read:` list.")
		return
	}
}

var (
	// Python: `PermissionError: [Errno 1] Operation not permitted: 'ls'`
	// Bash:   `bash: line 1: ls: Operation not permitted`
	// Go:     `fork/exec /usr/bin/ls: operation not permitted`
	reExecBlock = regexp.MustCompile(`(?i)(operation not permitted|permissionerror.*errno 1|fork/exec.*not permitted)`)
	// Python: `socket.gaierror: [Errno -3] Temporary failure in name resolution`
	// curl:   `Could not resolve host`
	// Go:     `dial tcp: lookup ...: no such host`
	reNetBlock = regexp.MustCompile(`(?i)(name resolution|could not resolve|no such host|name or service not known|getaddrinfo|connection refused)`)
	// Python: `PermissionError: [Errno 13] Permission denied: '/etc/...'`
	// Bash:   `cat: /etc/shadow: Permission denied`
	reFSBlock = regexp.MustCompile(`(?i)permission denied`)
	// Python: `OSError: [Errno 30] Read-only file system: '/path'`
	// Bash:   `bash: foo.txt: Read-only file system`
	// Go:     `open /path: read-only file system`
	reWriteBlock = regexp.MustCompile(`(?i)(read-only file system|errno 30)`)
)

func matchesExecBlock(s string) bool { return reExecBlock.MatchString(s) }
func matchesNetworkBlock(s string) bool {
	return reNetBlock.MatchString(s)
}
func matchesFSBlock(s string) bool {
	// Exclude execve-related "permission denied" so we don't double-fire.
	return reFSBlock.MatchString(s) && !reExecBlock.MatchString(s)
}
func matchesWriteBlock(s string) bool { return reWriteBlock.MatchString(s) }

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

func runManifest(manifestPath string, scriptArgs []string, timeout time.Duration, env map[string]string, netMode bento.NetworkMode, telemetry io.Writer, grantCB bento.GrantCallback, verbose bool) int {
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
	m.Args = append(m.Args, scriptArgs...)

	opts := []bento.Option{
		bento.WithLogger(log.New(os.Stderr, "", log.LstdFlags)),
		bento.WithVerbose(verbose),
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
		return 1
	}
	return code
}
