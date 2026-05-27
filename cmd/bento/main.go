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
	"runtime/debug"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/whiskeyjimbo/bento"
	"github.com/whiskeyjimbo/bento/internal/grants"
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
	case "-V", "--version", "version":
		fmt.Println("bento", bentoVersionTag())
		os.Exit(0)
	default:
		usage()
		os.Exit(2)
	}
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
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  bento <subcommand> --help    flags for one subcommand")
	fmt.Fprintln(os.Stderr, "  bento --help                 this help screen")
	fmt.Fprintln(os.Stderr, "  bento --version              print the version")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "flag placement: flags belong AFTER the subcommand.")
	fmt.Fprintln(os.Stderr, "  bento run --timeout=30s script.py     # correct")
	fmt.Fprintln(os.Stderr, "  bento --timeout=30s run script.py     # NOT a valid flag")
}

func cmdProfile(args []string) int {
	fs := flag.NewFlagSet("profile", flag.ExitOnError)
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "usage: bento profile [flags] <script> [-- script-args...]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Profile runs the script ONCE with a relaxed sandbox to record what it actually")
		fmt.Fprintln(out, "uses, then emits a starter manifest. Relaxations during the trial run:")
		fmt.Fprintln(out, "  * network: every outbound connect is allowed and recorded (host:port)")
		fmt.Fprintln(out, "  * writes:  the script's directory AND /tmp are bound writable, and every")
		fmt.Fprintln(out, "             write is recorded into the generated manifest's `write:` list")
		fmt.Fprintln(out, "  * reads:   all paths the script opens are recorded (deduped, noise-filtered)")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Mandatory-deny (SSH keys, cloud creds, shell rc files) STAYS in effect during")
		fmt.Fprintln(out, "profiling. Exec is still blocked unless --allow-exec is set (required for")
		fmt.Fprintln(out, "almost every bash script). Review the generated manifest and trim broad grants")
		fmt.Fprintln(out, "before committing — the trial run reflects only one code path.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "flags:")
		fs.PrintDefaults()
	}
	out := fs.String("out", "", "manifest output path (default: <script>.manifest.yaml)")
	force := fs.Bool("force", false, "overwrite the output file if it already exists")
	interpreter := fs.String("interpreter", "", "override auto-detected interpreter")
	verbose := fs.Bool("verbose", false, "show sandbox argv and other diagnostic logging")
	fs.BoolVar(verbose, "v", false, "shorthand for --verbose")
	allowExec := fs.Bool("allow-exec", false, "permit subprocess execve during profiling (required to profile bash scripts and build tools)")
	env := envFlag{}
	fs.Var(env, "env", "extra env var KEY=VALUE for the script during profiling; the name is also added to the generated manifest's `env:` allowlist (repeatable)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: bento profile needs a script path")
		fmt.Fprintln(os.Stderr, "  bento profile <script> [args...]")
		fmt.Fprintln(os.Stderr, "  bento profile --help     # full flag list")
		return 2
	}
	scriptPath := fs.Arg(0)
	scriptArgs := fs.Args()[1:]
	// Accept an explicit `--` separator after the script path (so users can
	// pass flags that would otherwise be interpreted by bento's FlagSet, e.g.
	// `bento profile ./tool -- --verbose`). Drop the separator if present.
	if len(scriptArgs) > 0 && scriptArgs[0] == "--" {
		scriptArgs = scriptArgs[1:]
	} else if msg := misplacedBentoFlag(scriptArgs); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		fmt.Fprintf(os.Stderr, "  bento profile [flags] %s [-- script-args...]\n", scriptPath)
		fmt.Fprintln(os.Stderr, "  (if the token really is meant for the script, prefix it with `--` to disambiguate)")
		return 2
	}

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
	if *allowExec {
		m.AllowExec = true
	}
	if len(scriptArgs) > 0 {
		m.Args = append(m.Args, scriptArgs...)
	}

	outPath := *out
	if outPath == "" {
		outPath = strings.TrimSuffix(scriptPath, filepath.Ext(scriptPath)) + ".manifest.yaml"
	}
	// Normalize for display so the trailing "wrote X" message is consistent
	// regardless of whether the user typed `./script.py` or `script.py`.
	outPath = filepath.Clean(outPath)
	if !*force {
		if _, err := os.Stat(outPath); err == nil {
			fmt.Fprintf(os.Stderr, "[bento] %s already exists. To proceed, choose one:\n", outPath)
			fmt.Fprintf(os.Stderr, "[bento]   bento profile --force %s            # overwrite the existing manifest\n", scriptPath)
			fmt.Fprintf(os.Stderr, "[bento]   bento profile --out=PATH %s         # write somewhere else\n", scriptPath)
			fmt.Fprintf(os.Stderr, "[bento]   rm %s && bento profile %s           # delete the existing one first\n", outPath, scriptPath)
			return 1
		}
	}

	// Proactive --allow-exec nudge for shells: bash/sh scripts almost
	// universally shell out (mkdir, sha256sum, …). Without --allow-exec
	// profile fails on the first subprocess and produces a useless manifest.
	if !*allowExec && isShellInterpreter(interp) {
		fmt.Fprintf(os.Stderr, "[bento] note: %q looks like a shell script; consider --allow-exec\n", scriptPath)
		fmt.Fprintln(os.Stderr, "[bento]   (shell scripts call external binaries — mkdir, ls, curl — which are blocked")
		fmt.Fprintln(os.Stderr, "[bento]   by default and will make this profile run fail at the first subprocess).")
	}
	fmt.Fprintf(os.Stderr, "[bento] profiling %q (permissive network)...\n", scriptPath)
	tail := newTailBuffer(16 << 10)
	runOpts := []bento.Option{
		bento.WithLogger(log.New(os.Stderr, "", 0)),
		bento.WithVerbose(*verbose),
		bento.WithStderr(io.MultiWriter(os.Stderr, tail)),
	}
	if len(env) > 0 {
		runOpts = append(runOpts, bento.WithExtraEnv(env))
	}
	result, err := bento.Profile(context.Background(), m, runOpts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[bento] script exit code: %d\n\n", result.ExitCode)
	printObservations(os.Stderr, result.Observations)
	printFSObservations(os.Stderr, result.FSObservations)
	printFSWrites(os.Stderr, result.FSWrites)
	printDeniedAttempts(os.Stderr, result.DeniedAttempts)
	noteSandboxPathIfReferenced(os.Stderr, tail.String())

	if result.ExitCode != 0 && !*force {
		if matchesExecBlock(tail.String()) {
			fmt.Fprintln(os.Stderr, "[bento] the script tried to spawn a subprocess, which `bento profile` blocks by default")
			fmt.Fprintln(os.Stderr, "[bento]   (profile relaxes network, not exec). Re-run with --allow-exec to let")
			fmt.Fprintln(os.Stderr, "[bento]   subprocesses run during profiling; the generated manifest will have")
			fmt.Fprintln(os.Stderr, "[bento]   `allow_exec: true` set:")
			fmt.Fprintf(os.Stderr, "[bento]     bento profile --allow-exec %s\n", scriptPath)
		} else {
			fmt.Fprintf(os.Stderr, "[bento] trial run exited %d — skipping manifest write.\n", result.ExitCode)
			if len(result.Observations) == 0 && len(result.FSWrites) == 0 {
				fmt.Fprintln(os.Stderr, "[bento]   no network/write activity was recorded — the script likely failed before doing")
				fmt.Fprintln(os.Stderr, "[bento]   anything useful. If the failure is unrelated to sandboxing (a Python ImportError,")
				fmt.Fprintln(os.Stderr, "[bento]   a missing dependency, a syntax error), fix it outside bento first, then re-profile.")
			}
			fmt.Fprintln(os.Stderr, "[bento]   --force writes a partial manifest annotated with the failure (you'll likely")
			fmt.Fprintln(os.Stderr, "[bento]   need to hand-edit it).")
		}
		return result.ExitCode
	}

	rewriteManifestForOutput(result.SuggestedManifest, outPath)

	// Populate `env:` from explicit --env names the user passed: profile
	// can't infer intent for *all* referenced env vars (USER may be a
	// false positive), but anything the caller passed at the CLI is an
	// explicit signal they want that var available at run time too.
	if result.SuggestedManifest != nil && len(env) > 0 {
		for name := range env {
			result.SuggestedManifest.Env = appendUniqueStr(result.SuggestedManifest.Env, name)
		}
	}

	yamlBytes, err := yaml.Marshal(result.SuggestedManifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error marshaling suggested manifest:", err)
		return 1
	}
	var header strings.Builder
	fmt.Fprintf(&header, "# generated by `bento profile %s` — review and trim before use\n", scriptPath)
	fmt.Fprintf(&header, "# bento %s · %s\n", bentoVersionTag(), time.Now().UTC().Format(time.RFC3339))
	if result.ExitCode != 0 {
		fmt.Fprintf(&header, "#\n# WARNING: generated from a failed trial run (exit=%d). Observations may be\n", result.ExitCode)
		header.WriteString("# incomplete — anything the script didn't reach before exiting is missing.\n")
		header.WriteString("# Hand-edit before relying on this manifest.\n")
	}
	if result.SuggestedManifest != nil && result.SuggestedManifest.Interpreter == "" {
		header.WriteString("#\n# No `interpreter:` field: script is an ELF binary and bento will exec it directly.\n")
	} else if result.SuggestedManifest != nil && result.SuggestedManifest.Interpreter != "" {
		// Record the resolved interpreter path so reviewers can spot $PATH
		// drift between profile-time and run-time. The manifest itself still
		// names the unresolved interpreter (e.g. `python3`) so it stays
		// portable across hosts — but a teammate cloning this manifest with
		// a different python on $PATH will get a different binary at run
		// time, often with no warning until something breaks.
		if resolved, err := exec.LookPath(result.SuggestedManifest.Interpreter); err == nil {
			header.WriteString("#\n# Interpreter at profile time: " + resolved + "\n")
			header.WriteString("# (`interpreter:` is re-resolved via $PATH on every `bento run` — if a teammate's\n")
			header.WriteString("# $PATH points elsewhere they'll get a different binary. Pin by setting an\n")
			header.WriteString("# absolute path above if that matters for your team.)\n")
		}
	}
	if len(result.DeniedAttempts) > 0 {
		header.WriteString("#\n# Script attempted to open these paths, blocked by bento's mandatory-deny\n# list (cannot be granted via manifest rules):\n")
		for _, p := range result.DeniedAttempts {
			fmt.Fprintf(&header, "#   - %s\n", p)
		}
	}
	// Emit a commented `env:` stub when the script references host env vars
	// that aren't already in the manifest's allowlist. Without this, the
	// generated manifest looks complete but silently strips $CITY / $DEPLOY_ID
	// / etc. at run time — every subsequent `bento run` re-prints the same
	// "stripped env var" note. Tell the user, in the manifest itself, exactly
	// what to uncomment.
	referenced := referencedEnvVarsInScript(scriptPath, interp)
	already := make(map[string]bool)
	if result.SuggestedManifest != nil {
		for _, name := range result.SuggestedManifest.Env {
			already[name] = true
		}
	}
	var stub []string
	for _, name := range referenced {
		if !already[name] {
			stub = append(stub, name)
		}
	}
	if len(stub) > 0 {
		header.WriteString("#\n# Script references these host env vars; uncomment names you want inherited\n")
		header.WriteString("# (bento strips host env by default). Or pass `--env NAME=VALUE` at run time.\n")
		header.WriteString("# env:\n")
		for _, name := range stub {
			fmt.Fprintf(&header, "#   - %s\n", name)
		}
	}
	// Profile captures the LITERAL write path the script touched. When the
	// basename looks templated (embedded unix timestamp, ISO date, pid-like
	// digit run) the next run will write a different filename, the rule won't
	// match, the write will land on tmpfs, and the user sees a silent loss.
	// Surface this in the manifest itself so the user is nudged to widen the
	// rule to the containing directory before committing.
	if result.SuggestedManifest != nil {
		var templated []string
		for _, p := range result.SuggestedManifest.Write {
			if templatedBasename(filepath.Base(p)) {
				templated = append(templated, p)
			}
		}
		if len(templated) > 0 {
			header.WriteString("#\n# Heads-up: the write path(s) below look templated (embedded timestamp/date/PID).\n")
			header.WriteString("# `bento profile` captured the LITERAL filename from this run; subsequent runs will\n")
			header.WriteString("# produce a different name, won't match the rule, and the write will silently land\n")
			header.WriteString("# on the sandbox tmpfs. Widen to the containing directory before committing:\n")
			for _, p := range templated {
				fmt.Fprintf(&header, "#   - %s  →  %s\n", p, filepath.Dir(p))
			}
		}
	}
	header.WriteString("\n")
	if err := os.WriteFile(outPath, append([]byte(header.String()), yamlBytes...), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error writing manifest:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[bento] wrote %s — review and trim before running with `bento run`\n", outPath)
	if result.SuggestedManifest != nil && result.SuggestedManifest.Network != nil && len(result.SuggestedManifest.Network.Rules) > 0 {
		fmt.Fprintf(os.Stderr, "[bento] tip: review the %d network rule(s) before committing — profile records what\n", len(result.SuggestedManifest.Network.Rules))
		fmt.Fprintln(os.Stderr, "[bento]   this one run touched; production paths may differ.")
	}
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

func printFSWrites(w io.Writer, paths []string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] observed filesystem writes:")
	for _, p := range paths {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintln(w)
}

// noteSandboxPathIfReferenced explains the /sandbox/script path that appears
// in tracebacks. New users assume bento moved their file; the note clarifies
// once that the script is bind-mounted at a fixed in-sandbox path.
func noteSandboxPathIfReferenced(w io.Writer, stderrTail string) {
	if !strings.Contains(stderrTail, "/sandbox/script") {
		return
	}
	fmt.Fprintln(w, "[bento] note: tracebacks above reference `/sandbox/script` — that's the in-sandbox")
	fmt.Fprintln(w, "[bento]   bind-mount path of your script (the file on disk is unchanged). The")
	fmt.Fprintln(w, "[bento]   sandbox's cwd is `/sandbox` and `$HOME` is `/sandbox`.")
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
	issues := collectManifestIssues(m, abs)
	if *quiet {
		if len(issues) > 0 {
			for _, s := range issues {
				fmt.Fprintln(os.Stderr, "issue:", s)
			}
			return 1
		}
		fmt.Println("ok")
		return 0
	}
	printResolvedManifest(os.Stdout, m, abs, issues)
	if len(issues) > 0 {
		return 1
	}
	return 0
}

// collectManifestIssues returns human-readable problems detected in a manifest
// that LoadManifest's structural parse accepts but that would surprise the
// user at run time: missing script file, unresolvable interpreter, missing
// read/write paths. Network rule canonicality is already enforced by
// Manifest.Validate at load time.
func collectManifestIssues(m *bento.Manifest, manifestPath string) []string {
	var issues []string
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
	// Env allowlist entries that aren't set on the host become empty strings
	// at runtime with no error — the script just misbehaves. Validate should
	// surface this so CI fails fast on a misconfigured deploy env.
	for _, name := range m.Env {
		if _, ok := os.LookupEnv(name); !ok {
			issues = append(issues, fmt.Sprintf("env: %s is declared in allowlist but not set on host (script will see empty string)", name))
		}
	}
	return issues
}

func printResolvedManifest(w io.Writer, m *bento.Manifest, manifestPath string, issues []string) {
	status := "ok"
	if len(issues) > 0 {
		status = fmt.Sprintf("%d ISSUE(S) FOUND — see end of output", len(issues))
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
	if len(m.Env) == 0 {
		fmt.Fprintln(w, "env:         (none — host env is fully stripped)")
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

	if len(issues) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ISSUES:")
		for _, s := range issues {
			fmt.Fprintf(w, "  - %s\n", s)
		}
	}
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
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: bento run [flags] <manifest.yaml | script>")
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output(), "\nNote: there is no --allow-exec flag for `run`; that's a manifest-only")
		fmt.Fprintln(fs.Output(), "setting. To bootstrap a manifest with subprocess execve allowed, run:")
		fmt.Fprintln(fs.Output(), "  bento profile --allow-exec <script>")
	}
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
		fmt.Fprintln(os.Stderr, "error: bento run needs a manifest or script path")
		fmt.Fprintln(os.Stderr, "  bento run <manifest.yaml | script>")
		fmt.Fprintln(os.Stderr, "  bento run --help     # full flag list")
		return 2
	}
	scriptArgs := fs.Args()[1:]
	// `--` is accepted but optional — flag parsing stops at the first
	// non-flag (the script/manifest path), so trailing args are forwarded
	// to the script even when they look like flags. Drop the separator
	// when present so the script doesn't receive it. If we instead see a
	// token that *looks* like a bento flag (--env, --timeout, ...), the
	// user almost certainly meant it for bento and not the script: refuse
	// loudly rather than silently passing it through. This is the #1 trap
	// for new users following the env-var note's "--env NAME=VALUE" hint.
	if len(scriptArgs) > 0 && scriptArgs[0] == "--" {
		scriptArgs = scriptArgs[1:]
	} else if msg := misplacedBentoFlag(scriptArgs); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		fmt.Fprintf(os.Stderr, "  bento run [flags] %s [-- script-args...]\n", fs.Arg(0))
		fmt.Fprintln(os.Stderr, "  (if the token really is meant for the script, prefix it with `--` to disambiguate)")
		return 2
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
			fmt.Fprintln(os.Stderr, "[bento] --prompt/-i opens /dev/tty to ask interactively when the script tries to")
			fmt.Fprintln(os.Stderr, "[bento]   reach a host not on the allowlist. It needs a real terminal — drop -i in CI")
			fmt.Fprintln(os.Stderr, "[bento]   or non-interactive shells, and instead add the missing hosts to your manifest's")
			fmt.Fprintln(os.Stderr, "[bento]   `network: rules:` (or re-run `bento profile` to record them).")
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
	warnStrippedShellVars(os.Stderr, scriptPath, interp, env)
	tail := newTailBuffer(16 << 10)
	var fsOpens []bento.FSOpen
	opts := []bento.Option{
		bento.WithLogger(log.New(os.Stderr, "", 0)),
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
	// Always check for hint signatures — a bash script that runs `ls` (blocked)
	// then `echo done` exits 0, but the user still needs the exec-block hint.
	emitZeroConfigHint(os.Stderr, scriptPath, m, tail.String())
	// Zero-config has no `write:` list, so every successful write outside
	// bento's sandbox bookkeeping is by definition lost.
	emitSilentWriteWarning(os.Stderr, fsOpens, nil)
	return code
}

// warnStrippedShellVars scans the script for references to host env vars
// (e.g. $USER, $HOME, os.environ["USER"]) that bento strips by default.
// Without this hint, a script like `echo "User: $USER"` silently prints
// `User:` blank in the sandbox. Fires for shell and Python scripts; warns
// at most once per run.
// warnUnsetEnvAllowlist fires when a manifest lists `env: [X]` but X is not
// set on the host — the var won't be passed in and the script sees an empty
// value, often silently. CLI --env overrides take precedence and suppress
// the warning per-variable.
func warnUnsetEnvAllowlist(w io.Writer, allowlist []string, cliEnv map[string]string) {
	var missing []string
	for _, name := range allowlist {
		if _, overridden := cliEnv[name]; overridden {
			continue
		}
		if _, set := os.LookupEnv(name); !set {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] ──────────────── note ────────────────")
	fmt.Fprintf(w, "[bento] manifest's env: allowlist names %d var(s) not currently set on the host:\n", len(missing))
	for _, name := range missing {
		fmt.Fprintf(w, "[bento]   $%s\n", name)
	}
	fmt.Fprintln(w, "[bento] the script will see them as empty strings (no error). Either export them in")
	fmt.Fprintln(w, "[bento]   your shell, or pass `--env NAME=VALUE` BEFORE the manifest path:")
	fmt.Fprintf(w, "[bento]   bento run --env %s=... <manifest> [args...]\n", missing[0])
	fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
}

func warnStrippedShellVars(w io.Writer, scriptPath, interp string, env map[string]string) {
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
	// Partition by whether the var is set on the host:
	//   - set: silent-misbehavior case (user expected shell export to flow
	//     through). Show the exact `--env NAME=VALUE` line so they can copy
	//     it verbatim.
	//   - unset: script will see empty in any sandbox; user almost certainly
	//     needs to export it or pass it inline.
	// Skip anything the user already supplied via --env.
	type ref struct {
		name  string
		value string // empty when not set on host
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
	// Special-case USER/HOME: bento sets HOME=/sandbox explicitly inside the
	// sandbox, and USER is intentionally unset (the script runs as an unnamed
	// uid). A junior seeing `USER=None` from `os.environ.get('USER')` thinks
	// something is broken; clarify this is by design and not fixable via --env.
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
	// `whoami` / `id` / `getent passwd` are the *shell* equivalents of $USER:
	// they don't reference an env var but they share the same surprise — they
	// return "sandbox" (bento's synthetic /etc/passwd uid), not the host
	// user's login name. Trigger the identity note the same way.
	if isShellInterpreter(interp) {
		for _, tok := range identityShellTokens(src) {
			sandboxIdentityHits = appendUniqueStr(sandboxIdentityHits, tok)
		}
	}
	// Python equivalents that reach libc / /etc/passwd directly. Same surprise:
	// these return "sandbox", not the host user.
	if isPythonInterpreter(interp) {
		for _, tok := range identityPythonTokens(src) {
			sandboxIdentityHits = appendUniqueStr(sandboxIdentityHits, tok)
		}
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
				fmt.Fprintf(w, "[bento]   bento run --env %s=%s <manifest-or-script> [args...]\n", r.name, shellQuote(r.value))
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
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

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
)

// identityShellTokens returns the unique identity-leak tokens a shell script
// invokes (whoami, id, getent passwd, groups, logname). Each one returns
// bento's synthetic identity ("sandbox" / a numeric uid) rather than the host
// user. Empty when none match.
func identityShellTokens(src []byte) []string {
	var out []string
	for _, m := range reShellIdentity.FindAllSubmatch(src, -1) {
		tok := strings.TrimSpace(string(m[1]))
		// Normalize "id -un" / "id -u" to "id" for display.
		if strings.HasPrefix(tok, "id") {
			tok = "id"
		}
		out = appendUniqueStr(out, tok)
	}
	return out
}

// identityPythonTokens returns the unique identity-leak API calls a Python
// script makes (os.getlogin, getpass.getuser, pwd.getpwuid, os.getuid,
// os.geteuid). These reach the synthetic /etc/passwd or the sandbox uid and
// return "sandbox" / a numeric uid rather than the host user.
func identityPythonTokens(src []byte) []string {
	var out []string
	for _, m := range rePyIdentity.FindAllSubmatch(src, -1) {
		out = appendUniqueStr(out, string(m[1]))
	}
	return out
}

// referencedEnvVarsInScript returns the host env var names a script references.
// Best-effort: shell `$NAME` for shell interpreters, `os.environ[…]` /
// `os.getenv(…)` for Python. Returns nil for binaries or unreadable files.
// Used by `bento profile` to seed a commented `env:` stub in the generated
// manifest so the user sees, in the file they just generated, exactly which
// vars need to be allowlisted.
func referencedEnvVarsInScript(scriptPath, interp string) []string {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil
	}
	var names []string
	switch {
	case isShellInterpreter(interp):
		names = referencedShellVars(src)
	case isPythonInterpreter(interp):
		names = referencedPythonEnvVars(src)
	default:
		return nil
	}
	out := names[:0]
	for _, n := range names {
		switch n {
		case "USER", "LOGNAME":
			continue // sandbox-managed; not user-settable
		}
		out = append(out, n)
	}
	return out
}

// reTemplatedBasename matches basenames that contain a unix timestamp (10+
// consecutive digits), an ISO-style date (YYYY-MM-DD), a YYYYMMDD run, or
// HHMMSS-style stamp. Each of these strongly suggests `date +%s` / `date +%F`
// / `$$` interpolation in the path — the next run will produce a different
// name, the write rule won't match, and the file silently lands on tmpfs.
var reTemplatedBasename = regexp.MustCompile(
	`[0-9]{10,}` + // unix timestamp / nanos
		`|[0-9]{4}-[0-9]{2}-[0-9]{2}` + // ISO date
		`|[0-9]{8}T[0-9]{6}` + // ISO compact datetime
		`|\b[0-9]{8}\b`) // YYYYMMDD

func templatedBasename(name string) bool {
	return reTemplatedBasename.MatchString(name)
}

// appendUniqueStr appends v to s unless it is already present.
func appendUniqueStr(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// misplacedBentoFlag detects a common UX trap: the user put a bento flag
// (--env, --timeout, --network-mode, …) AFTER the manifest/script path, so
// Go's `flag` package treated it as an argument to the script and silently
// passed it through. The most common case is following the env-strip note's
// hint and typing `bento run foo.yaml --env CITY=Tokyo`. Returns an empty
// string when no misplaced flag is detected; otherwise a multi-line error
// message ready to print to stderr.
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
	known := map[string]bool{
		"env": true, "timeout": true, "network-mode": true,
		"interpreter": true, "verbose": true, "v": true,
		"prompt": true, "i": true, "telemetry-out": true,
		"out": true, "force": true, "allow-exec": true,
	}
	if !known[name] {
		return ""
	}
	return fmt.Sprintf("error: `%s` looks like a bento flag but appeared after the script/manifest path,\n  so it was silently treated as an argument to the script. Move the flag BEFORE the path:", tok)
}

// referencedShellVars returns the unique env var names a shell script reads
// from the host environment. It deliberately excludes:
//   - names assigned in the script (FOO=bar, export FOO=, local FOO, read FOO,
//     for FOO in …, etc.) — those are script-local, not host env;
//   - names referenced only via a default-providing expansion (${FOO:-x},
//     ${FOO-x}, ${FOO:=x}, ${FOO:?msg}, …) — the script is already handling
//     the unset case, so the env-strip note is noise.
//
// Single-quoted strings and `#` comments are stripped first; expansion is
// suppressed inside them so `echo '$FOO'` and `# uses $FOO` would otherwise
// be false positives. Heredoc bodies aren't tracked separately; quoted
// heredocs ('EOF') still leak through but the false-positive rate is low.
func referencedShellVars(src []byte) []string {
	scrub := reShellSingleQuoted.ReplaceAll(src, []byte(`''`))
	scrub = reShellLineComment.ReplaceAllFunc(scrub, func(b []byte) []byte {
		// Preserve the leading non-`#` char (capture group 1 of reShellLineComment)
		// so the surrounding statement boundary stays intact for reShellAssign.
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

// shellAssignedNames extracts the union of names assigned, read-into, or used
// as a for-loop target in the (already-scrubbed) shell source.
func shellAssignedNames(src []byte) map[string]bool {
	set := make(map[string]bool)
	for _, m := range reShellAssign.FindAllSubmatch(src, -1) {
		set[string(m[1])] = true
	}
	for _, m := range reShellRead.FindAllSubmatch(src, -1) {
		// `read A B C` binds multiple names — split on whitespace.
		for _, w := range strings.Fields(string(m[1])) {
			set[w] = true
		}
	}
	for _, m := range reShellForIn.FindAllSubmatch(src, -1) {
		set[string(m[1])] = true
	}
	return set
}

// referencedPythonEnvVars returns names the script reads from os.environ /
// os.getenv WITHOUT supplying a default. A call like `os.environ.get("X", "y")`
// or `os.getenv("X", "y")` is excluded: the caller is handling the unset case,
// and bento's "you forgot to allowlist this" note would be misleading.
// `os.environ["X"]` (subscript) is always included — it raises KeyError if
// unset, which is not "handling" the unset case.
func referencedPythonEnvVars(src []byte) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(name string) {
		if seen[name] || name == "" {
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
			// os.environ.get("X" [, default]) — only count when no default arg.
			if !pyCallHasSecondArg(m[3]) {
				add(string(m[2]))
			}
		case len(m[4]) > 0:
			// os.getenv("X" [, default]) — only count when no default arg.
			if !pyCallHasSecondArg(m[5]) {
				add(string(m[4]))
			}
		}
	}
	return out
}

// pyCallHasSecondArg reports whether the captured "rest" of a Python call's
// arg list (everything after the first quoted name, before the closing paren)
// contains a positional or keyword second argument. We only need to know
// "is there a comma at depth 0 followed by something non-whitespace": that's
// the default. Brackets/braces/parens inside the default itself are tolerated.
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
				// Require at least one non-whitespace byte after the comma.
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

// uniqueEnvNames extracts capture group 1 from each match, skipping shell
// positional/special vars (digits, _, ?, !, #, *, @) and well-known builtins
// that bento sets explicitly inside the sandbox.
func uniqueEnvNames(matches [][][]byte) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		name := string(m[1])
		switch name {
		case "HOME", "PATH", "LANG", "PWD", "IFS", "PS1", "PS2": // bento sets or shell-sets these
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

func isShellInterpreter(interp string) bool {
	base := filepath.Base(interp)
	switch base {
	case "sh", "bash", "dash", "zsh", "ksh":
		return true
	}
	return false
}

func isPythonInterpreter(interp string) bool {
	base := filepath.Base(interp)
	return strings.HasPrefix(base, "python")
}

// emitSilentWriteWarning warns when the script successfully wrote to paths
// that aren't backed by a host bind-mount. These writes look successful inside
// the sandbox (the syscall returns >= 0, the bytes are buffered), but they
// land in the sandbox's tmpfs and vanish when the sandbox exits. The script
// has no way to know — there is no error to catch.
//
// Two classes of lost writes:
//   - /sandbox/* paths that aren't the script bind. The sandbox root is a
//     tmpfs; anything written there directly is ephemeral.
//   - Paths the script wrote that aren't declared (or transitively under) any
//     entry in the manifest's write: list. /tmp is `--tmpfs` by default, so
//     undeclared /tmp writes vanish; same for /var, /opt, /etc, etc.
//
// declaredWrites should already be normalized to absolute, cleaned paths.
func emitSilentWriteWarning(w io.Writer, opens []bento.FSOpen, declaredWrites []string) {
	if len(opens) == 0 {
		return
	}
	declared := make(map[string]bool, len(declaredWrites))
	prefixes := make([]string, 0, len(declaredWrites))
	for _, p := range declaredWrites {
		declared[p] = true
		prefixes = append(prefixes, p+"/")
	}
	isPersisted := func(p string) bool {
		if declared[p] {
			return true
		}
		for _, pfx := range prefixes {
			if strings.HasPrefix(p, pfx) {
				return true
			}
		}
		return false
	}

	var lost []string
	for _, o := range opens {
		if !(o.Write && o.OK) {
			continue
		}
		// Skip bento's own scratch under /sandbox (script, launcher, shim,
		// proxychains conf). Anything else under /sandbox is ephemeral.
		if strings.HasPrefix(o.Path, "/sandbox/.") {
			continue
		}
		switch o.Path {
		case "/sandbox", "/sandbox/script", "/sandbox/launcher", "/sandbox/proxychains.conf":
			continue
		}
		if isPersisted(o.Path) {
			continue
		}
		lost = append(lost, o.Path)
	}
	if len(lost) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] ──────────────── warning ────────────────")
	fmt.Fprintln(w, "[bento] script wrote to paths not declared in `write:` — these landed in the")
	fmt.Fprintln(w, "[bento]   sandbox tmpfs and vanished on exit (no error was raised inside the script):")
	for _, p := range lost {
		fmt.Fprintln(w, "[bento]   "+p)
	}
	fmt.Fprintln(w, "[bento] add the destination(s) to the manifest's `write:` list to persist them on the host.")
	fmt.Fprintln(w, "[bento] ─────────────────────────────────────────")
}

// resolveDeclaredWrites returns m.Write with relative entries joined against
// baseDir and all entries filepath.Cleaned, so emitSilentWriteWarning can do
// simple prefix matching against the absolute paths strace reports.
func resolveDeclaredWrites(m *bento.Manifest, baseDir string) []string {
	if m == nil || len(m.Write) == 0 {
		return nil
	}
	out := make([]string, 0, len(m.Write))
	for _, p := range m.Write {
		if !filepath.IsAbs(p) && baseDir != "" {
			p = filepath.Join(baseDir, p)
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// emitZeroConfigHint inspects the script's stderr to point the user at the
// likely cause of failure: exec block, DNS/no-network, or denied file access.
// Silent when nothing matches. The hint is wrapped in a visual separator so
// it's recognizable as bento output after a long script traceback.
//
// A single script can trip multiple categories in one run (a bash script that
// does `> out.txt` then `wc out.txt` hits BOTH write and exec block). When
// that happens we emit each section in one combined hint block rather than
// silently dropping all but the first — picking only one was the most common
// "the hint is about something other than my first error" complaint.
func emitZeroConfigHint(w io.Writer, scriptPath string, m *bento.Manifest, stderrTail string) {
	var sections [][]string
	if matchesExecBlock(stderrTail) {
		sections = append(sections, []string{
			"[bento] zero-config blocks subprocess execve. To allow the script to spawn processes,",
			"[bento]   generate a starter manifest with the exec block already opt-in:",
			fmt.Sprintf("[bento]     bento profile --allow-exec %s", scriptPath),
			"[bento]     bento run <manifest>.yaml",
			"[bento]   (or set `allow_exec: true` in an existing manifest. `bento run` has no",
			"[bento]   --allow-exec flag by design — it's a manifest-only setting.)",
		})
	}
	if m.Network == nil && matchesNetworkBlock(stderrTail) {
		hostLine := ""
		if hosts := extractDeniedHosts(stderrTail); len(hosts) > 0 {
			hostLine = fmt.Sprintf("[bento]   script attempted: %s", strings.Join(hosts, ", "))
		}
		lines := []string{
			"[bento] zero-config runs have no network access. If the script needs network, try:",
		}
		if hostLine != "" {
			lines = append(lines, hostLine)
		}
		lines = append(lines,
			fmt.Sprintf("[bento]   bento profile %s   # records observed hosts into a manifest", scriptPath),
			"[bento]   bento run <manifest>.yaml  # re-run under the trimmed manifest",
		)
		sections = append(sections, lines)
	}
	if matchesWriteBlock(stderrTail) {
		sections = append(sections, []string{
			"[bento] zero-config grants no write access — not even to the script's own directory.",
			"[bento]   `bento profile <script>` runs with /tmp and the script's directory writable",
			"[bento]   AND records the paths the script wrote to, then emits a manifest with those",
			"[bento]   paths already in `write:`. Review, trim, and re-run with `bento run <manifest>.yaml`.",
		})
	}
	// matchesFSBlock catches "Permission denied" from path opens; exec also
	// surfaces as PermissionError on Python so the matcher already excludes
	// that — but only print the read hint if the more specific write hint
	// didn't fire (a missing `write:` shows up as both "Permission denied"
	// on directory create AND "Read-only file system" on the write itself).
	if !matchesWriteBlock(stderrTail) && matchesFSBlock(stderrTail) {
		sections = append(sections, []string{
			"[bento] zero-config only grants read access to the script's directory. If the script needs",
			"[bento]   other paths, run `bento profile <script>` and add them to the generated manifest's `read:` list.",
		})
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
	// ENOENT for an absolute host path that exists on the host (or whose
	// parent does) is almost always a "you forgot to bind-mount this" error
	// rather than a real missing-file. The kernel sees no such file because
	// bwrap didn't bind it; the user sees a confusing FileNotFoundError or
	// "No such file or directory". Surface the real cause.
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

// pathsMissingButOnHost scans stderr for ENOENT-style errors that name an
// absolute path which DOES exist on the host. Returns at most a few unique
// paths. Patterns matched:
//   - Python: `FileNotFoundError: [Errno 2] No such file or directory: '/etc/hostname'`
//   - Bash:   `cat: /etc/hostname: No such file or directory`
//   - Go:     `open /etc/hostname: no such file or directory`
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
			// Trigger if the path itself exists on the host (read case:
			// `/etc/hostname`) OR if its parent directory exists (write
			// case: `/var/log/myapp.log` where /var/log is on the host
			// but not in the manifest).
			if _, err := os.Stat(p); err != nil {
				if _, err := os.Stat(filepath.Dir(p)); err != nil {
					continue
				}
			}
			out = append(out, p)
			if len(out) >= 5 {
				return out
			}
		}
	}
	return out
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
	// ENOENT lines paired with a nearby absolute path. Two passes:
	// reENOENTLine matches the marker, then reAbsPath extracts every absolute
	// path on that same line (handles "path-before" Go/bash format AND
	// "path-after" Python format).
	reENOENTLine = regexp.MustCompile(`(?i).*(?:no such file or directory|errno 2[^0-9]).*`)
	reAbsPath    = regexp.MustCompile(`(?:'(/[^'\s]+)'|"(/[^"\s]+)"|(/(?:etc|usr|var|opt|home|tmp|root|run|srv|mnt|media|proc|sys)/[^\s:'"]*))`)
)

// reDeniedHost captures the hostname from common DNS-failure shapes so the
// zero-config network hint can name what the script tried to reach. Each
// pattern wraps the hostname in capture group 1.
//
//   curl:   curl: (6) Could not resolve host: api.github.com
//   Go:     dial tcp: lookup api.github.com on 127.0.0.53:53: ...
//   getent: getent: name or service not known: api.github.com
//   wget:   wget: unable to resolve host address 'api.github.com'
var reDeniedHost = regexp.MustCompile(
	`(?i)(?:could not resolve host[:\s]+|lookup\s+|resolve host address\s+['"]?|name or service not known[:\s]+)([A-Za-z0-9_.-]+)`)

// rePyTracebackURL pulls URLs out of Python tracebacks. urlopen / requests.get
// don't include the hostname in the gaierror message itself, but the call
// frame nearly always does — e.g. `r = urlopen("https://api.github.com")`.
// We extract the URL host as the next-best signal.
var rePyTracebackURL = regexp.MustCompile(`https?://([A-Za-z0-9_.-]+)`)

// extractDeniedHosts returns up to a few unique hostnames the script tried to
// resolve before the sandbox refused. Empty when nothing matches — the caller
// then prints the generic hint without naming a host.
func extractDeniedHosts(stderrTail string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(h string) {
		h = strings.Trim(h, "'\".:")
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, m := range reDeniedHost.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
		if len(out) >= 5 {
			return out
		}
	}
	// Python fallback: gaierror doesn't name the host, but the traceback
	// frame that triggered it almost always does as a URL literal.
	for _, m := range rePyTracebackURL.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
		if len(out) >= 5 {
			return out
		}
	}
	return out
}

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
	warnUnsetEnvAllowlist(os.Stderr, m.Env, env)
	// Also warn when the script references host env vars that the manifest
	// hasn't allowlisted — same silent-misbehavior trap as the zero-config
	// case (user exports FOO, expects it to flow through, gets empty string).
	// Skip vars the manifest already allows or the user passed via --env.
	if scriptForEnvScan := m.Script; scriptForEnvScan != "" {
		merged := make(map[string]string, len(env)+len(m.Env))
		for k, v := range env {
			merged[k] = v
		}
		for _, k := range m.Env {
			merged[k] = ""
		}
		warnStrippedShellVars(os.Stderr, scriptForEnvScan, m.Interpreter, merged)
	}
	m.Args = append(m.Args, scriptArgs...)

	var fsOpens []bento.FSOpen
	opts := []bento.Option{
		bento.WithLogger(log.New(os.Stderr, "", 0)),
		bento.WithVerbose(verbose),
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
	emitSilentWriteWarning(os.Stderr, fsOpens, resolveDeclaredWrites(m, filepath.Dir(abs)))
	emitLimitsKillHint(os.Stderr, code, m.Limits)
	return code
}

// emitLimitsKillHint surfaces the most common silent kills bento itself
// installs (cgroup memory cap → SIGKILL → exit 137; --timeout / RuntimeMaxSec
// → SIGTERM → exit 143). Without this, the user sees only "exit 137" with no
// indication that the limit they wrote in the manifest fired.
func emitLimitsKillHint(w io.Writer, code int, lim *bento.Limits) {
	if lim == nil {
		return
	}
	switch code {
	case 137: // 128 + SIGKILL (9)
		if lim.Memory != "" {
			fmt.Fprintln(w, "[bento] ──────────────── hint ────────────────")
			fmt.Fprintf(w, "[bento] script exited 137 (SIGKILL). The manifest sets limits.memory=%s; an\n", lim.Memory)
			fmt.Fprintln(w, "[bento]   OOM kill is the most likely cause. Either raise the limit, or trim the")
			fmt.Fprintln(w, "[bento]   script's allocations. (Exit 137 with no Memory limit usually means an")
			fmt.Fprintln(w, "[bento]   external `kill -9` — not bento.)")
			fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
		}
	case 143: // 128 + SIGTERM (15)
		// Don't overclaim — many things send SIGTERM. Only hint when bento is
		// the likely sender (limits set or run --timeout was applied).
		if lim.CPU != "" || lim.Tasks != 0 {
			fmt.Fprintln(w, "[bento] ──────────────── hint ────────────────")
			fmt.Fprintln(w, "[bento] script exited 143 (SIGTERM). If you passed `bento run --timeout=…`, the")
			fmt.Fprintln(w, "[bento]   wall-clock backstop likely fired. Otherwise check cgroup limits in the")
			fmt.Fprintln(w, "[bento]   manifest's limits: block.")
			fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
		}
	}
}

// suggestValidateIfRelevant points the user at `bento validate` when a run-time
// error looks like something validate would have flagged at load time (missing
// script, unresolvable interpreter, missing read paths). Hides the fact that
// `script:` is relative to the manifest, which trips up first-time users who
// move a manifest without realizing it.
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
