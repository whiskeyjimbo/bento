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
	"sort"
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
		fmt.Fprintln(out, "  * writes:  the script's directory AND host /tmp are bound writable, and every")
		fmt.Fprintln(out, "             write is recorded into the generated manifest's `write:` list.")
		fmt.Fprintln(out, "             NOTE: binding host /tmp also makes other processes' tempfiles VISIBLE")
		fmt.Fprintln(out, "             to the script during this trial run. Profile in a directory whose")
		fmt.Fprintln(out, "             /tmp content you're comfortable exposing, or skim the manifest's")
		fmt.Fprintln(out, "             `write:` list before committing.")
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
	warnEmptyEnv(os.Stderr, env)
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
	} else if note := noteForwardedFlags(scriptArgs); note != "" {
		fmt.Fprintln(os.Stderr, note)
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
	// Profile binds the host's /tmp so scripts that write tempfiles (the
	// `tempfile.mkstemp()` / `mktemp` pattern) complete instead of crashing
	// on Read-only file system. Side effect: the script can also READ other
	// processes' tempfiles during the trial run. Surface this once so the
	// user can decide whether to profile in a more isolated environment.
	if _, err := os.Stat("/tmp"); err == nil {
		fmt.Fprintln(os.Stderr, "[bento] note: profile binds host /tmp writable for the trial run — other")
		fmt.Fprintln(os.Stderr, "[bento]   processes' tempfiles are visible to the script during profiling.")
	}
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
	printTmpfsWrites(os.Stderr, result.TmpfsWrites)
	printDeniedAttempts(os.Stderr, result.DeniedAttempts)
	printBlockedReads(os.Stderr, result.BlockedReads)
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
			noteShellCwdAssumption(os.Stderr, scriptPath, interp)
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
			header.WriteString("# $PATH points elsewhere they'll get a different binary. To pin, replace the\n")
			header.WriteString("# `interpreter:` value below with the absolute path, e.g.:\n")
			fmt.Fprintf(&header, "#     interpreter: %s\n", resolved)
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

// printTmpfsWrites surfaces /sandbox/* writes that landed on the sandbox tmpfs.
// These don't go into the suggested manifest (they have no host destination),
// but the script believed them — the user needs to pick a real target.
func printTmpfsWrites(w io.Writer, paths []string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] writes that landed on sandbox tmpfs (NOT persisted, no host destination):")
	for _, p := range paths {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintln(w, "[bento]   these were written to relative paths inside the sandbox (cwd=/sandbox).")
	fmt.Fprintln(w, "[bento]   pick an absolute host path (e.g. /tmp/... or under the script dir) and re-profile,")
	fmt.Fprintln(w, "[bento]   or add an absolute target to `write:` and rewrite the script to use it.")
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

func printBlockedReads(w io.Writer, paths []string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] read attempts blocked by deny-by-default (added to generated manifest's `read:`):")
	for _, p := range paths {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintln(w, "[bento]   review the new `read:` entries before committing — profile auto-grants any")
	fmt.Fprintln(w, "[bento]   path the script tried to read so the manifest works on first run; trim what")
	fmt.Fprintln(w, "[bento]   the script doesn't actually need.")
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
	fmt.Fprintln(w, "             (bind-mounted inside the sandbox at /sandbox/script; tracebacks, $0,")
	fmt.Fprintln(w, "              and __file__ reference that path, not the host path above.)")

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

// warnEmptyEnv flags `--env KEY=` with no value — almost always a shell
// quoting bug. The canonical case is:
//
//	API_KEY=secret bento run --env API_KEY=$API_KEY script.py
//
// The inline `API_KEY=secret` assignment isn't exported into the parent
// shell, so `$API_KEY` expands to "" before bento ever sees it. Bento happily
// sets the var to "" inside the sandbox and the script silently
// misbehaves. Surfacing this once per run saves an hour of debugging.
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
	} else if note := noteForwardedFlags(scriptArgs); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	warnEmptyEnv(os.Stderr, env)
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
	warnSiblingManifest(os.Stderr, target)
	return runScriptZeroConfig(target, scriptArgs, *interpreter, *timeout, env, mode, telemetry, grantCB, *verbose)
}

// warnSiblingManifest fires when the user runs `bento run script.py` while a
// `script.manifest.yaml` sits next to it. The convention from `bento profile`
// is that the manifest is the file you want to run under; the bare-script
// form silently falls back to zero-config and ignores the manifest. Without
// this nudge, a junior who profiled their script yesterday and forgot the
// `.manifest.yaml` suffix today gets a different (more restrictive) sandbox
// and may not notice for a while.
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

func isManifestPath(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

// hasShebang reports whether the file begins with `#!`. Used to suppress the
// extension-inferred-interpreter warning when the user has already expressed
// intent via a shebang line (even if the extension table currently wins).
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

// runScriptZeroConfig synthesizes a practical-strict manifest and runs it.
func runScriptZeroConfig(scriptPath string, scriptArgs []string, interpOverride string, timeout time.Duration, env map[string]string, netMode bento.NetworkMode, telemetry io.Writer, grantCB bento.GrantCallback, verbose bool) int {
	interp := interpOverride
	if interp == "" {
		resolved, source, err := bento.ResolveInterpreterDetailed(scriptPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		interp = resolved
		// Extension-only inference is a guess: bento picked the interpreter
		// from the filename rather than from anything in the file. Warn
		// only when the script ALSO has no shebang — if a shebang exists
		// the user has expressed intent (even though the extension table
		// currently wins over shebang in resolution order, the warning
		// would be noise).
		// Print only under --verbose: this is informational, not a problem,
		// and every zero-config run on a foo.py without a shebang would
		// otherwise repeat it forever. `bento profile` still surfaces it
		// once at manifest-generation time where it's actually actionable.
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
	warnStrippedShellVars(os.Stderr, scriptPath, interp, env)
	// Preflight: zero-config has no network, but a script using urllib/http/
	// requests/etc. will fail deep inside its stdlib's stack trace — by the
	// time the post-run hint fires, the user has already scrolled past 30
	// lines of traceback. Surface the diagnosis BEFORE the script runs so
	// the warning sits above any traceback in the user's terminal.
	warnLikelyNetworkUseInZeroConfig(os.Stderr, scriptPath, interp)
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
	emitPostRunHint(os.Stderr, hintModeZeroConfig, scriptPath, m, tail.String())
	// Zero-config has no `write:` list, so every successful write outside
	// bento's sandbox bookkeeping is by definition lost.
	emitSilentWriteWarning(os.Stderr, fsOpens, nil)
	return code
}

// emitZeroConfigPosture prints a one-line summary of what zero-config grants.
// Without this, first-time users don't know whether `bento run script.py`
// gave them network, write access, or anything else — and there's no manifest
// file to read. Single line so it doesn't drown out the script's own output.
func emitZeroConfigPosture(w io.Writer, scriptPath string) {
	scriptDir := filepath.Dir(scriptPath)
	if scriptDir == "" {
		scriptDir = "."
	}
	fmt.Fprintf(w, "[bento] zero-config: read=%s/  write=(none)  network=(none)  exec=blocked\n", scriptDir)
}

// noteShellCwdAssumption fires when a shell script's profile run failed and
// the source contains the most common cwd-based patterns that silently break
// inside the sandbox: `$0`, `dirname "$0"`, `${BASH_SOURCE[0]}`, or `cd $(…)`.
// Inside the sandbox the script is bind-mounted at `/sandbox/script` — so
// `dirname "$0"` yields `/sandbox`, not the host directory the script lives
// in. The result is a script that "works on my machine" but lists nothing,
// finds no siblings, and exits 1 or 2 with a confusing error.
//
// The fix is BENTO_SCRIPT_DIR (always set inside the sandbox to the script's
// host directory). Point the user at it.
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

var reShellCwdAssumption = regexp.MustCompile(
	`\$0\b|\bdirname\b|\$\{?BASH_SOURCE\b`)

// warnLikelyNetworkUseInZeroConfig scans the script source for cheap, high-
// confidence indicators that it makes outbound network calls. When found, it
// emits a single-line preflight note so the warning lands ABOVE any traceback
// the script later produces. The post-run hint (emitPostRunHint) still fires
// on actual failure with the precise host name — this is just the heads-up.
//
// Restricted to shell and Python scripts (the source-scanning interpreters);
// binaries and other languages get the post-run hint only.
func warnLikelyNetworkUseInZeroConfig(w io.Writer, scriptPath, interp string) {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return
	}
	var pat *regexp.Regexp
	switch {
	case isShellInterpreter(interp):
		pat = reShellNetCall
	case isPythonInterpreter(interp):
		pat = rePyNetCall
	default:
		return
	}
	if !pat.Match(src) {
		return
	}
	fmt.Fprintln(w, "[bento] preflight: script appears to make outbound network calls, but zero-config has")
	fmt.Fprintln(w, "[bento]   no network access. The call will fail with a DNS or connection error. Run")
	fmt.Fprintf(w, "[bento]   `bento profile %s` to record observed hosts and emit a manifest.\n", scriptPath)
}

var (
	// Conservative — only matches binaries that are almost certainly making
	// network calls. False positives produce a noisy warning; we'd rather
	// miss a quirky script than warn on every `import os`.
	rePyNetCall = regexp.MustCompile(
		`\b(?:urllib\.request|urllib\.urlopen|urlopen|http\.client|httplib|` +
			`requests\.(?:get|post|put|delete|patch|head|request|Session)|` +
			`httpx\.|aiohttp\.|socket\.(?:create_connection|socket|gethostbyname)|` +
			`urllib3\.|smtplib\.|ftplib\.|imaplib\.|poplib\.)`)
	// Shell-level network tools. Bound to a token edge so `mycurl` doesn't
	// trip `curl`. ssh/scp/rsync intentionally omitted (often local-only).
	reShellNetCall = regexp.MustCompile(
		`(?m)(?:^|[\s;|&$(` + "`" + `])(curl|wget|nc|ncat|netcat|http|httpie|aws\s+s3)\b`)
)

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
				// PATH-style values (long, colon-separated lists) make the
				// suggestion line unreadably wrap; use the shell expansion
				// `"$NAME"` so the copy-paste does the right thing regardless
				// of what the host value is. Short, safe values are shown
				// inline so the user can see exactly what would be passed.
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

// suggestionEnvValue returns either the literal value (when it's short and
// shell-safe) or a `"$NAME"` shell expansion (when the literal would be long,
// colon-separated, or otherwise hard to read in a single suggestion line).
// The shell-expansion form is just as copy-pasteable and stays current with
// whatever the host value is at paste time.
func suggestionEnvValue(name, value string) string {
	// PATH-like (colon-separated list of >2 entries) or anything over ~60 chars
	// gets the `"$NAME"` form to keep the suggestion on one terminal line.
	if len(value) > 60 || strings.Count(value, ":") >= 2 {
		return `"$` + name + `"`
	}
	return shellQuote(value)
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

// reTemplatedBasename matches basenames whose digit pattern strongly suggests
// runtime interpolation — `date +%s`, `date +%F`, `$$`, `os.getpid()`,
// `uuid4()`. Each next run will produce a different name, the write rule
// won't match, and the file silently lands on tmpfs.
//
// Patterns:
//   - 10+ consecutive digits (unix timestamp, nanos, large pid)
//   - YYYY-MM-DD (ISO date)
//   - YYYYMMDDTHHMMSS (ISO compact datetime)
//   - 8 isolated digits (YYYYMMDD)
//   - hex UUID with hyphens (8-4-4-4-12)
//   - bare 32-char hex run (uuid4().hex / md5-style)
var reTemplatedBasename = regexp.MustCompile(
	`[0-9]{10,}` + // unix timestamp / nanos / large pid
		`|[0-9]{4}-[0-9]{2}-[0-9]{2}` + // ISO date
		`|[0-9]{8}T[0-9]{6}` + // ISO compact datetime
		`|\b[0-9]{8}\b` + // YYYYMMDD
		`|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b` + // UUID
		`|\b[0-9a-fA-F]{32}\b`) // bare hex uuid / md5

// reLikelyPID matches 3-9 digit runs flanked by a separator (or string edge),
// e.g. "-1234.", "_42-", ".999". Conservative on length to avoid catching
// version strings like "v1" or "log2".
var reLikelyPID = regexp.MustCompile(`(^|[._-])[0-9]{3,9}([._-]|$)`)

// reMktempRun matches a separator followed by 6+ alnum chars (mktemp suffix
// shape: `tmp.XXXXXX`, `out_aB3xY9`). We confirm in code that the run
// contains both letters and digits to avoid flagging plain words like
// "summary" or pure digit runs already caught above.
var reMktempRun = regexp.MustCompile(`[._-][A-Za-z0-9]{6,}`)

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
// script as argv. Without this note, `bento run greet.py --name Alice` runs
// successfully with the script seeing `argv = ["--name", "Alice"]`, which
// almost never matches what the user expected (they assumed bento would parse
// `--name`). A one-line note tells them how to silence it (`-- --name Alice`)
// if forwarding was intentional. Returns empty when nothing flag-shaped is
// present.
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
		// HOME/PATH/LANG are set unconditionally inside the sandbox
		// (HOME=/sandbox, PATH=/usr/bin:/bin:..., LANG=C.UTF-8). The script
		// reads a *real* value, not an empty string — flagging them as
		// "stripped" misleads users into thinking they're broken. The
		// existing identity note (USER/LOGNAME, whoami, getlogin) still
		// handles the cases that genuinely surprise users.
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

// shellInternalVar reports whether name is a bash/shell internal variable
// (provided by the shell itself, not the environment) or a var bento sets
// inside the sandbox. Flagging these as "host env vars the user forgot to
// allowlist" is a false positive: `BASH_SOURCE`, `LINENO`, `RANDOM`, etc.
// have nothing to do with the host environment and cannot be passed through
// via the manifest's `env:` allowlist.
func shellInternalVar(name string) bool {
	switch name {
	// Bento-managed (always set inside the sandbox).
	case "HOME", "PATH", "LANG", "PWD", "BENTO_HOST_HOME", "BENTO_SCRIPT_DIR":
		return true
	// Bash special parameters and shell-maintained vars.
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

// hintMode distinguishes the two surfaces where the post-run hint detector
// runs: zero-config (no manifest; remediation is "create one with profile") vs
// manifest (remediation is "edit the manifest field"). The matchers and stderr
// signatures are identical between modes; only the user-facing copy differs.
type hintMode int

const (
	hintModeZeroConfig hintMode = iota
	hintModeManifest
)

// emitPostRunHint inspects the script's stderr to point the user at the
// likely cause of failure: exec block, DNS/no-network, or denied file access.
// Silent when nothing matches. The hint is wrapped in a visual separator so
// it's recognizable as bento output after a long script traceback.
//
// A single script can trip multiple categories in one run (a bash script that
// does `> out.txt` then `wc out.txt` hits BOTH write and exec block). When
// that happens we emit each section in one combined hint block rather than
// silently dropping all but the first — picking only one was the most common
// "the hint is about something other than my first error" complaint.
//
// In manifest mode the remediation points at the manifest field to change
// rather than at `bento profile`, so a junior who has already committed a
// manifest doesn't get bounced back to the on-ramp tool.
func emitPostRunHint(w io.Writer, mode hintMode, scriptPath string, m *bento.Manifest, stderrTail string) {
	var sections [][]string

	if !m.AllowExec && matchesExecBlock(stderrTail) {
		bins := extractDeniedBinaries(stderrTail)
		var binLine string
		if len(bins) > 0 {
			binLine = fmt.Sprintf("[bento]   script attempted to exec: %s", strings.Join(bins, ", "))
		}
		switch mode {
		case hintModeZeroConfig:
			s := []string{"[bento] zero-config blocks subprocess execve. To allow the script to spawn processes,"}
			if binLine != "" {
				s = append(s, binLine)
			}
			s = append(s,
				"[bento]   generate a starter manifest with the exec block already opt-in:",
				fmt.Sprintf("[bento]     bento profile --allow-exec %s", scriptPath),
				"[bento]     bento run <manifest>.yaml",
				"[bento]   (or set `allow_exec: true` in an existing manifest. `bento run` has no",
				"[bento]   --allow-exec flag by design — it's a manifest-only setting.)",
			)
			sections = append(sections, s)
		case hintModeManifest:
			s := []string{"[bento] manifest has `allow_exec: false` (the default). The seccomp filter is"}
			s = append(s,
				"[bento]   all-or-nothing — every subprocess execve returns EPERM. To permit subprocesses,",
				"[bento]   set `allow_exec: true` in the manifest, then re-run.",
			)
			if binLine != "" {
				s = append(s, binLine)
			}
			sections = append(sections, s)
		}
	}

	netDenied := matchesNetworkBlock(stderrTail) && (m.Network == nil || networkRulesEmpty(m.Network))
	if netDenied || (matchesNetworkBlock(stderrTail) && mode == hintModeManifest) {
		hosts := extractDeniedHosts(stderrTail)
		var hostLine string
		if len(hosts) > 0 {
			hostLine = fmt.Sprintf("[bento]   script attempted: %s", strings.Join(hosts, ", "))
		}
		switch mode {
		case hintModeZeroConfig:
			s := []string{"[bento] zero-config runs have no network access. If the script needs network, try:"}
			if hostLine != "" {
				s = append(s, hostLine)
			}
			s = append(s,
				fmt.Sprintf("[bento]   bento profile %s   # records observed hosts into a manifest", scriptPath),
				"[bento]   bento run <manifest>.yaml  # re-run under the trimmed manifest",
			)
			sections = append(sections, s)
		case hintModeManifest:
			s := []string{}
			if m.Network == nil || networkRulesEmpty(m.Network) {
				s = append(s, "[bento] manifest's `network:` is blocked (no rules). To allow the script to reach hosts,")
				s = append(s, "[bento]   add a `network:` block with `rules:` listing each allowed host:port.")
			} else {
				s = append(s, "[bento] script tried to reach a host that doesn't match any rule in `network.rules`.")
				s = append(s, "[bento]   Add a matching rule (or widen an existing one) and re-run.")
			}
			if hostLine != "" {
				s = append(s, hostLine)
			}
			sections = append(sections, s)
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
	// matchesFSBlock catches "Permission denied" from path opens; exec also
	// surfaces as PermissionError on Python so the matcher already excludes
	// that — but only print the read hint if the more specific write hint
	// didn't fire (a missing `write:` shows up as both "Permission denied"
	// on directory create AND "Read-only file system" on the write itself).
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
	// Names of binaries the script tried to spawn before seccomp refused.
	// Three shapes cover the runtime-engine variations:
	//   bash:   `<script>: line 5: /usr/bin/wc: Operation not permitted` → match the
	//           last colon-delimited token before "Operation not permitted" (works
	//           for both `/usr/bin/wc` and bare `ls`).
	//   Go:     `fork/exec /usr/bin/ls: operation not permitted`
	//   Python: `PermissionError: [Errno 1] Operation not permitted: 'ls'`
	reExecBinBash = regexp.MustCompile(`(?mi)(?:^|\s)([^\s:]+):\s*[Oo]peration not permitted`)
	reExecBinFork = regexp.MustCompile(`(?i)fork/exec\s+(\S+):\s*operation not permitted`)
	reExecBinPy   = regexp.MustCompile(`(?i)permissionerror[^\n]*errno 1[^\n]*:\s*['"]([^'"]+)['"]`)
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

// networkRulesEmpty reports whether the manifest's network block is the
// "explicit zero" form (`network: { rules: [] }`) — semantically the same as
// nil but tracked separately for clarity in error messages.
func networkRulesEmpty(n *bento.NetworkPerm) bool {
	return n == nil || len(n.Rules) == 0
}

func matchesExecBlock(s string) bool { return reExecBlock.MatchString(s) }

// extractDeniedBinaries returns up to a few unique binary names the script
// tried to exec before seccomp refused. Empty when nothing matches — the
// caller then prints the generic hint without naming a binary.
func extractDeniedBinaries(stderrTail string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(name string) {
		name = strings.Trim(name, "'\".:")
		if name == "" || seen[name] {
			return
		}
		// Filter obvious noise: a bare "PermissionError" or "fork/exec"
		// shouldn't surface as a binary name.
		switch strings.ToLower(name) {
		case "permissionerror", "fork/exec":
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, m := range reExecBinPy.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
	}
	for _, m := range reExecBinFork.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
	}
	for _, m := range reExecBinBash.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1])
		if len(out) >= 5 {
			break
		}
	}
	return out
}
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

	tail := newTailBuffer(16 << 10)
	var fsOpens []bento.FSOpen
	opts := []bento.Option{
		bento.WithLogger(log.New(os.Stderr, "", 0)),
		bento.WithVerbose(verbose),
		// Tap both streams: scripts often print errors to stdout (Python's
		// `except: print(e)`), and the hint detector keys off the message
		// text regardless of which stream it landed on.
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
	// Always check for hint signatures — a manifest run that has the right
	// network/read rules but missing `allow_exec` will silently keep going
	// past the EPERM and exit 0, but the user still needs the hint pointing
	// them at the field to flip.
	emitPostRunHint(os.Stderr, hintModeManifest, m.Script, m, tail.String())
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
