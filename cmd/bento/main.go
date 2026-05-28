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
	"github.com/whiskeyjimbo/bento/internal/spec"
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
	pinInterpreter := fs.Bool("pin-interpreter", false, "write the resolved absolute interpreter path into the manifest (not the $PATH name)")
	verbose := fs.Bool("verbose", false, "show sandbox argv and other diagnostic logging")
	fs.BoolVar(verbose, "v", false, "shorthand for --verbose")
	allowExec := fs.Bool("allow-exec", false, "permit subprocess execve during profiling (required to profile bash scripts and build tools)")
	scaffold := fs.Bool("scaffold", false, "emit a commented manifest skeleton WITHOUT running the script; for production-only scripts that can't be profiled live")
	env := envFlag{}
	fs.Var(env, "env", "extra env var KEY=VALUE for the script during profiling; the name is also added to the generated manifest's `env:` allowlist (repeatable)")
	var preMountReads stringSliceFlag
	fs.Var(&preMountReads, "read", "extra read path to bind-mount during profiling AND add to the generated manifest's `read:` list (repeatable). Use when the script gates on `[[ -d PATH ]]` and needs the path visible before profile can observe it.")
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
	// --read paths: pre-mount and seed manifest reads. Resolve to absolute paths
	// up front so the trial-run binding and the emitted manifest are consistent
	// (relative paths in `read:` resolve against the manifest's directory, but
	// at profile time we're running from the caller's cwd).
	for _, p := range preMountReads {
		abs, err := filepath.Abs(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: --read %q: %v\n", p, err)
			return 2
		}
		m.Read = appendUniqueStr(m.Read, abs)
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
			fmt.Fprintf(os.Stderr, "[bento] %s already exists. Options:\n", outPath)
			fmt.Fprintln(os.Stderr, "[bento]   --force                          overwrite (discards any hand-edits to read:/write:/env:)")
			sideBySide := sideBySidePath(outPath)
			fmt.Fprintf(os.Stderr, "[bento]   --out=%-25s write the new manifest alongside so you can diff first:\n", sideBySide)
			fmt.Fprintf(os.Stderr, "[bento]                                      diff %s %s\n", outPath, sideBySide)
			// Iteration nudge: if the user passed --allow-exec but the existing
			// manifest doesn't have it, the most common path here is "the first
			// profile silently failed without --allow-exec and I'm re-running
			// with it now." Surface --force directly so they don't have to read
			// between the lines.
			if *allowExec && priorManifestLacksAllowExec(outPath) {
				fmt.Fprintln(os.Stderr, "[bento]   the existing manifest doesn't set `allow_exec: true`; --allow-exec implies")
				fmt.Fprintln(os.Stderr, "[bento]   you want to overwrite that — add --force to do so.")
			}
			return 1
		}
	}

	if *scaffold {
		return writeScaffoldManifest(outPath, scriptPath, interp, m)
	}

	// Pre-run nudge intentionally omitted: it primes the user to read every
	// later failure as "a subprocess got blocked," even when the trial fails
	// for an unrelated reason (e.g. a bash builtin tripping the tmpfs-cwd).
	// The post-run path below already emits a specific --allow-exec advisory
	// when the script actually tried to execve, which is the only case where
	// the advice is relevant.
	netModeLabel := "permissive network"
	if isProfileTargetELF(scriptPath, interp) {
		// For ELF binaries the libproxychains-based hostname capture doesn't
		// fire — connect() calls bypass libc. Say so in the banner instead of
		// silently producing an empty `network:` block. printBlockedConnects
		// later surfaces IPs from the strace fallback.
		netModeLabel = "permissive network: hostnames only intercepted for libc-routed traffic — ELF binaries get IP-level kernel trace instead"
	}
	fmt.Fprintf(os.Stderr, "[bento] profiling %q (%s)...\n", scriptPath, netModeLabel)
	tail := newTailBuffer(16 << 10)
	// scriptTail captures ONLY the script's own stdout/stderr (no bento log
	// lines). On a failing trial run, dumping just the script's output gives
	// the user a clear signal — `[bento] script exit code: 1` is useless on
	// its own when bento and the script's stderr are interleaved.
	scriptTail := newTailBuffer(8 << 10)
	runOpts := []bento.Option{
		bento.WithLogger(log.New(io.MultiWriter(os.Stderr, tail), "", 0)),
		bento.WithVerbose(*verbose),
		bento.WithStdout(io.MultiWriter(os.Stdout, scriptTail, tail)),
		bento.WithStderr(io.MultiWriter(os.Stderr, scriptTail, tail)),
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
	printFSWrites(os.Stderr, result.FSWrites, len(result.TmpfsWrites) > 0)
	printTmpfsWrites(os.Stderr, result.TmpfsWrites, filepath.Dir(absScriptPath(scriptPath)))
	printDeniedAttempts(os.Stderr, result.DeniedAttempts)
	printBlockedReads(os.Stderr, result.BlockedReads)
	printBlockedConnects(os.Stderr, result.BlockedConnects, isProfileTargetELF(scriptPath, interp), result.SuggestedManifest)
	noteSandboxPathIfReferenced(os.Stderr, tail.String())
	// Note about host /tmp visibility moved to post-run and gated on actual
	// /tmp activity: printing it on every profile run trains the user to
	// ignore it before it ever matters.
	noteHostTmpBindIfRelevant(os.Stderr, result.FSWrites, result.FSObservations)

	execBlock := matchesExecBlock(tail.String())
	// Silent-failure trap: a shell script that wraps its body in `{ … } > out`
	// will exit 0 even when every forked subprocess failed with EPERM — the
	// redirect's exit status is the shell's, not the subprocesses'. Without
	// this check, profile would emit a manifest WITHOUT allow_exec, and every
	// future `bento run` would silently reproduce the same garbage output.
	// Treat exec-blocked + exit 0 the same as exec-blocked + non-zero: bail
	// unless --force, and point the user at --allow-exec.
	if execBlock && !*allowExec && result.ExitCode == 0 && !*force {
		fmt.Fprintln(os.Stderr, "[bento] ──────────────── warning ────────────────")
		fmt.Fprintln(os.Stderr, "[bento] script forked subprocesses that bento blocked, but it still exited 0.")
		fmt.Fprintln(os.Stderr, "[bento]   this usually means the script's output is incomplete (e.g. `{ … } > out`")
		fmt.Fprintln(os.Stderr, "[bento]   swallows subprocess failures, leaving empty fields in the captured file).")
		if bins := extractDeniedBinaries(tail.String()); len(bins) > 0 {
			fmt.Fprintf(os.Stderr, "[bento]   blocked: %s\n", strings.Join(bins, ", "))
		}
		fmt.Fprintln(os.Stderr, "[bento]   re-run with --allow-exec so subprocesses can execute and the manifest")
		fmt.Fprintln(os.Stderr, "[bento]   captures `allow_exec: true`:")
		fmt.Fprintf(os.Stderr, "[bento]     %s\n", reprofileCmd(scriptPath, scriptArgs, env, preMountReads, *allowExec, []string{"--allow-exec"}))
		fmt.Fprintln(os.Stderr, "[bento]   (or pass --force to emit the manifest anyway; you'll likely need to hand-edit it.)")
		fmt.Fprintln(os.Stderr, "[bento] ─────────────────────────────────────────")
		return 1
	}
	if result.ExitCode != 0 {
		// On failure, surface the SCRIPT's own output (separately from bento's
		// log lines). The interleaved stream made it easy for a shell script
		// that redirects everything inside `{ … } > file` to fail silently.
		if !execBlock {
			emitScriptOutputDiagnostic(os.Stderr, scriptTail.String(), scriptPath, interp)
		}
		// If the script failed at the *application* layer (HTTP 502, JSON parse,
		// upstream timeout) AFTER the sandbox successfully observed network
		// and/or filesystem use, the manifest captures real signal — the
		// allow-list for the host the script reached, the paths it touched.
		// Throwing it away forces the user to either wait for the upstream to
		// recover or pass --force and accept a "warning: failed trial" header.
		// Emit the manifest in this case with a non-fatal note instead.
		sandboxBlocked := execBlock || matchesFSBlock(tail.String()) || matchesWriteBlock(tail.String())
		hasObservations := len(result.Observations) > 0 || len(result.FSWrites) > 0
		applicationFailure := !sandboxBlocked && hasObservations
		if !*force && !applicationFailure {
			if execBlock {
				fmt.Fprintln(os.Stderr, "[bento] the script tried to spawn a subprocess, which `bento profile` blocks by default")
				fmt.Fprintln(os.Stderr, "[bento]   (profile relaxes network, not exec). Re-run with --allow-exec to let")
				fmt.Fprintln(os.Stderr, "[bento]   subprocesses run during profiling; the generated manifest will have")
				fmt.Fprintln(os.Stderr, "[bento]   `allow_exec: true` set:")
				fmt.Fprintf(os.Stderr, "[bento]     %s\n", reprofileCmd(scriptPath, scriptArgs, env, preMountReads, *allowExec, []string{"--allow-exec"}))
			} else {
				fmt.Fprintf(os.Stderr, "[bento] trial run exited %d — skipping manifest write.\n", result.ExitCode)
				if len(result.Observations) == 0 && len(result.FSWrites) == 0 {
					// Before falling back to "fix it outside bento", check whether
					// the failure looks like a script that referenced a relative
					// path (./X) that exists on the host script dir but not under
					// /sandbox. This is the recurring "sandbox cwd ≠ shell pwd"
					// trap — the script "works on my machine" outside bento.
					scriptDir := filepath.Dir(absScriptPath(scriptPath))
					if hit := detectRelativePathHostMiss(scriptTail.String(), scriptDir); hit != "" {
						fmt.Fprintf(os.Stderr, "[bento]   the script's output mentions `%s`, and that file exists on the host\n", hit)
						fmt.Fprintf(os.Stderr, "[bento]   at %s — but inside the sandbox `./` resolves to `/sandbox/` (a tmpfs),\n", filepath.Join(scriptDir, strings.TrimPrefix(hit, "./")))
						fmt.Fprintln(os.Stderr, "[bento]   not your host pwd. Fix one of:")
						absHit := filepath.Join(scriptDir, strings.TrimPrefix(hit, "./"))
						fmt.Fprintln(os.Stderr, "[bento]     - re-profile with an absolute host path via --env, e.g.:")
						fmt.Fprintf(os.Stderr, "[bento]         %s\n", reprofileCmd(scriptPath, scriptArgs, env, preMountReads, *allowExec, []string{"--env", shellQuote("IN=" + absHit)}))
						fmt.Fprintln(os.Stderr, "[bento]     - `cd \"$BENTO_SCRIPT_DIR\"` at the top of the script (and add the script")
						fmt.Fprintln(os.Stderr, "[bento]       directory to `read:` if needed).")
					} else {
						fmt.Fprintln(os.Stderr, "[bento]   no network/write activity was recorded — the script likely failed before doing")
						fmt.Fprintln(os.Stderr, "[bento]   anything useful. If the failure is unrelated to sandboxing (a Python ImportError,")
						fmt.Fprintln(os.Stderr, "[bento]   a missing dependency, a syntax error), fix it outside bento first, then re-profile.")
					}
				} else {
					// Profile mode bind-mounts host /tmp; run mode gives the
					// script a fresh tmpfs. A script that fails on `du /tmp/*`
					// or any other host-tmp content survives `bento run`. Tell
					// the user so they don't conclude the manifest is broken.
					noteProfileVsRunTmpDivergence(os.Stderr, scriptPath, result.FSWrites)
				}
				noteShellCwdAssumption(os.Stderr, scriptPath, interp)
				fmt.Fprintln(os.Stderr, "[bento]   --force writes a partial manifest annotated with the failure (you'll likely")
				fmt.Fprintln(os.Stderr, "[bento]   need to hand-edit it).")
			}
			return result.ExitCode
		}
		if applicationFailure && !*force {
			fmt.Fprintln(os.Stderr, "[bento] ──────────────── note ────────────────")
			fmt.Fprintf(os.Stderr, "[bento] trial run exited %d, but the sandbox was not the blocker — captured\n", result.ExitCode)
			fmt.Fprintln(os.Stderr, "[bento]   network/filesystem observations are real. Writing the manifest anyway;")
			fmt.Fprintln(os.Stderr, "[bento]   the script's own error (HTTP 5xx, parse failure, upstream timeout, etc.)")
			fmt.Fprintln(os.Stderr, "[bento]   is independent and likely transient — fix it and `bento run` will work.")
			fmt.Fprintln(os.Stderr, "[bento] ──────────────────────────────────────")
		}
	}

	rewriteManifestForOutput(result.SuggestedManifest, outPath)

	// --pin-interpreter: replace the unresolved $PATH name (e.g. `python3`)
	// with the absolute path we resolved at profile time. Makes the manifest
	// reproducible across hosts at the cost of portability — the teammate's
	// path won't match, and they'll need to update the manifest.
	if *pinInterpreter && result.SuggestedManifest != nil && result.SuggestedManifest.Interpreter != "" {
		if resolved, err := exec.LookPath(result.SuggestedManifest.Interpreter); err == nil {
			result.SuggestedManifest.Interpreter = resolved
		}
	}

	// Populate `env:` from explicit --env names the user passed: profile
	// can't infer intent for *all* referenced env vars (USER may be a
	// false positive), but anything the caller passed at the CLI is an
	// explicit signal they want that var available at run time too.
	if result.SuggestedManifest != nil && len(env) > 0 {
		for name := range env {
			result.SuggestedManifest.Env = appendUniqueStr(result.SuggestedManifest.Env, name)
		}
	}
	// --read paths the user passed are an explicit declaration of intent. The
	// observation pipeline may not have caught everything under them (e.g. a
	// script's `[[ -d PATH ]]` may not record a deep enumeration), so make sure
	// the user-declared paths land in the emitted manifest's read list.
	if result.SuggestedManifest != nil && len(preMountReads) > 0 {
		for _, p := range preMountReads {
			abs, _ := filepath.Abs(p)
			result.SuggestedManifest.Read = appendUniqueStr(result.SuggestedManifest.Read, abs)
		}
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
		// Profile usually records `read: - .` for ELF binaries because the script
		// directory is bind-mounted to expose the binary itself to the sandbox.
		// Without this hint a reviewer reads "read: - ." and assumes the binary
		// will read sibling files at runtime, then tries to narrow it.
		if hasDotRead(result.SuggestedManifest) {
			header.WriteString("# (`read: - .` below is the script directory — bento mounts it so the binary\n")
			header.WriteString("# is reachable for execve. Keep it as-is unless you've moved the binary.)\n")
		}
		// ELF binaries can't be statically scanned for env reads, so bento can't
		// detect `os.Getenv("USER")` the way it can for python `os.environ[...]`
		// or shell `$USER`. Surface the common identity vars in writing — a
		// junior who runs `bento run binary.manifest.yaml` and sees their tool
		// behave as if it's running as a different user has no signal otherwise.
		header.WriteString("#\n# Heads-up: this is a compiled binary, so bento can't scan its source for env\n")
		header.WriteString("# reads. Two patterns to be aware of at run time:\n")
		header.WriteString("#   - identity vars (USER, LOGNAME, HOME): bento strips/replaces these inside the\n")
		header.WriteString("#     sandbox regardless of `env:`. To pass host values, use --env explicitly:\n")
		header.WriteString("#       bento run --env USER=$USER --env LOGNAME=$LOGNAME <manifest>\n")
		header.WriteString("#   - other host env vars (API_TOKEN, REGION, …): list the names below and bento\n")
		header.WriteString("#     will inherit them from your current environment at run time. --env NAME=VAL\n")
		header.WriteString("#     overrides or supplies a value without needing the name in this list.\n")
		header.WriteString("# env:\n")
		header.WriteString("#   - API_TOKEN\n")
		header.WriteString("#   - REGION\n")
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
	// When profile observed reads under $HOME (or another mandatory-deny
	// parent), the broad parent path is dropped from `read:` and replaced
	// with narrower descendants — emitting it would crash `bento run`
	// because mandatory-deny can't shadow ~/.bashrc et al under a ro-bound
	// parent (bwrap: "Can't create file"). Surface what was narrowed so the
	// reviewer can widen back to specific subpaths if needed.
	if len(result.NarrowedReadPaths) > 0 {
		header.WriteString("#\n# Profile observed reads under a path that contains mandatory-deny targets\n")
		header.WriteString("# (~/.bashrc, ~/.ssh/*, cloud creds, etc.). Emitting the parent as `read:` would\n")
		header.WriteString("# crash `bento run` because the deny shim can't mount under a ro-bound parent.\n")
		header.WriteString("# Narrowed away:\n")
		for _, p := range result.NarrowedReadPaths {
			fmt.Fprintf(&header, "#   - %s\n", p)
		}
		header.WriteString("# If the script needs a specific subdirectory, add it explicitly to `read:` below.\n")
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
		header.WriteString("#\n# To inherit these host env vars at run time — uncomment names under `env:`\n")
		header.WriteString("# below (bento strips host env by default). Or pass `--env NAME=VALUE` ad-hoc.\n")
		header.WriteString("# env:\n")
		for _, name := range stub {
			fmt.Fprintf(&header, "#   - %s\n", name)
		}
	}
	// Identity env vars (USER/LOGNAME/HOME) are deliberately not user-settable
	// in the sandbox — adding them to `env:` won't help. But the script
	// *references* them and the user-visible symptom is silent (empty string
	// or "?"). Surface this in the manifest so a reviewer sees, in writing,
	// why the script will see empty/synthetic identity values.
	if identity := referencedIdentityEnvVarsInScript(scriptPath, interp); len(identity) > 0 {
		header.WriteString("#\n# To override identity values at run time — pass `--env NAME=$NAME` (NOT env: above):\n")
		header.WriteString("# bento strips/replaces these inside the sandbox regardless of the `env:` allowlist\n")
		header.WriteString("# (HOME is hardcoded to /sandbox; USER/LOGNAME are unset; whoami → \"sandbox\").\n")
		header.WriteString("# Per-var run-time recipe:\n")
		for _, name := range identity {
			if isShellOrLibcIdentityCall(name) {
				fmt.Fprintf(&header, "#   - %s  ← shell/libc call; can't be overridden, returns sandbox identity\n", name)
			} else {
				fmt.Fprintf(&header, "#   - %s  ← `bento run --env %s=$%s manifest.yaml` to reinstate host value\n", name, name, name)
			}
		}
	}
	// Profile captures the LITERAL write path the script touched. When the
	// basename looks templated (embedded unix timestamp, ISO date, pid-like
	// digit run) OR contains the value of an env var the script reads, the
	// next run will write a different filename, the rule won't match, the
	// write will land on tmpfs, and the user sees a silent loss. Surface this
	// in the manifest itself so the user is nudged to widen the rule to the
	// containing directory before committing.
	if result.SuggestedManifest != nil {
		// Values that, if found in a write basename, suggest the path was
		// interpolated from a runtime input. Sourced from --env and from any
		// host env var the script source references.
		var inputValues []string
		for _, v := range env {
			if len(v) >= 2 {
				inputValues = append(inputValues, v)
			}
		}
		for _, name := range referenced {
			if v, ok := os.LookupEnv(name); ok && len(v) >= 2 {
				inputValues = append(inputValues, v)
			}
		}
		// Pick up literal defaults from `os.environ.get("X", "London")` /
		// `os.getenv("X", "London")` patterns. When CITY isn't set on the
		// host, the script ran with the default value — and that default
		// is what showed up in the captured write path.
		if src, err := os.ReadFile(scriptPath); err == nil {
			for _, v := range pythonEnvDefaultStrings(src) {
				if len(v) >= 2 {
					inputValues = append(inputValues, v)
				}
			}
		}
		seen := make(map[string]bool)
		type flag struct{ path, reason string }
		var flagged []flag
		add := func(p, reason string) {
			if seen[p] {
				return
			}
			seen[p] = true
			flagged = append(flagged, flag{p, reason})
		}
		for _, p := range result.SuggestedManifest.Write {
			base := filepath.Base(p)
			if templatedBasename(base) {
				add(p, "embedded timestamp/date/PID")
				continue
			}
			for _, v := range inputValues {
				if strings.Contains(base, v) {
					add(p, "contains a referenced env var's value (input-templated)")
					break
				}
			}
		}
		if len(flagged) > 0 {
			// Auto-apply the widening: a manifest that we already know will fail
			// on the next run is worse than one with a wider rule the user can
			// narrow. The flagged literal goes into the header comment so the
			// reviewer can see what was captured and tighten if they want.
			widenedFrom := make(map[string]string, len(flagged))
			for _, f := range flagged {
				widenedFrom[f.path] = filepath.Dir(f.path)
			}
			out := result.SuggestedManifest.Write[:0]
			seenWidened := make(map[string]bool)
			for _, p := range result.SuggestedManifest.Write {
				if widened, ok := widenedFrom[p]; ok {
					if !seenWidened[widened] {
						seenWidened[widened] = true
						out = append(out, widened)
					}
					continue
				}
				out = append(out, p)
			}
			result.SuggestedManifest.Write = out

			header.WriteString("#\n# Heads-up: the write path(s) below were widened to their containing directory.\n")
			header.WriteString("# `bento profile` captured a LITERAL filename from this run that looks templated\n")
			header.WriteString("# (timestamp / PID / env-var interpolation). Without widening, the next run with\n")
			header.WriteString("# different inputs would produce a different name, miss the rule, and silently\n")
			header.WriteString("# land on the sandbox tmpfs. Narrow back to a literal if you actually want that:\n")
			for _, f := range flagged {
				fmt.Fprintf(&header, "#   - %s  ←  observed: %s   (%s)\n", filepath.Dir(f.path), f.path, f.reason)
			}
		}
	}
	// Surface the literal VALUES from --env NAME=VALUE so a user re-running
	// from a fresh shell knows what the trial captured. The manifest only
	// stores the NAME (so it stays portable across hosts); without this hint
	// a script that conditioned behavior on QUOTES_LOG=/tmp/foo silently uses
	// its default when run later because the env isn't set on host.
	if len(env) > 0 {
		header.WriteString("#\n# Profile-time --env values (script used these defaults — pass them again at run\n")
		header.WriteString("# time with `--env NAME=VALUE`; the manifest's `env:` allowlist only forwards a\n")
		header.WriteString("# variable from your shell, it does not preserve the value):\n")
		names := make([]string, 0, len(env))
		for k := range env {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			fmt.Fprintf(&header, "#   --env %s=%s\n", k, env[k])
		}
	}
	// When the trial run wrote to paths that landed on the sandbox tmpfs, the
	// profile-time warning told the user how to fix it — but the manifest
	// itself carries none of those fixes, so the first `bento run <manifest>`
	// will fail with the same error. Inline the warning into the manifest so
	// the artifact matches what profile said, and a reviewer/teammate opening
	// it cold sees the failure mode before running.
	if len(result.TmpfsWrites) > 0 {
		scriptDir := filepath.Dir(absScriptPath(scriptPath))
		header.WriteString("#\n# ⚠ WARNING: the trial run wrote to relative paths that landed on the sandbox\n")
		header.WriteString("# tmpfs and were lost. `bento run <this manifest>` will exit non-zero with the\n")
		header.WriteString("# same diagnostic unless you apply one of the fixes below.\n")
		header.WriteString("# Lost writes:\n")
		for _, p := range result.TmpfsWrites {
			fmt.Fprintf(&header, "#   - %s\n", p)
		}
		header.WriteString("# Fix one of:\n")
		header.WriteString("#   (a) point the script at an absolute host path via --env, e.g.\n")
		fmt.Fprintf(&header, "#       bento run --env OUT=%s/<file> <this manifest>\n", scriptDir)
		fmt.Fprintf(&header, "#       and add `%s` to `write:` below.\n", scriptDir)
		header.WriteString("#   (b) add `cd \"$BENTO_SCRIPT_DIR\"` at the top of the script so relative paths\n")
		fmt.Fprintf(&header, "#       land in the (writable) script directory, then add `%s` to `write:`.\n", scriptDir)
		header.WriteString("# Adding the host directory to `write:` ALONE will not help — the script must\n")
		header.WriteString("# also be pointed at the host path; otherwise it keeps writing to /sandbox.\n")
		// Scaffold fix (a) as edit-ready YAML below the prose. The user
		// uncomments two lines instead of synthesizing them from the recipe
		// above. Pick the most plausible env-var name from the script's
		// referenced set — prefer output-shaped names (OUT, DEST, FILE,
		// OUTPUT) — falling back to the first referenced name, then a
		// placeholder. We deliberately do not re-emit `env:` here because
		// the `env:` comment block above already lists the referenced names.
		envName := pickOutputEnvName(referenced)
		header.WriteString("#\n# ── Quick-apply fix (a) ─ uncomment the `write:` block below AND uncomment\n")
		fmt.Fprintf(&header, "#    `- %s` under the `env:` comment above. Then run with:\n", envName)
		fmt.Fprintf(&header, "#       bento run --env %s=%s/<file> <this manifest>\n", envName, scriptDir)
		fmt.Fprintf(&header, "# write:\n#   - %s\n", scriptDir)
	}
	header.WriteString("\n")
	// Marshal AFTER all header-building code, which may mutate the manifest
	// (e.g. auto-widening templated write paths).
	yamlBytes, err := yaml.Marshal(result.SuggestedManifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error marshaling suggested manifest:", err)
		return 1
	}
	// Inject a comment immediately above the marshaled `args:` block. Profile
	// bakes the one-time trial args into the manifest as defaults; without an
	// in-file nudge a reviewer has no signal that these were captured from a
	// specific invocation and will be passed to every future `bento run`.
	if result.SuggestedManifest != nil && len(result.SuggestedManifest.Args) > 0 {
		yamlBytes = annotateArgsBlock(yamlBytes)
	}
	// If the manifest carries relative entries under read:/write: (e.g. "."),
	// add an in-file note. These resolve against the manifest's directory, not
	// the shell's cwd — which is the right behavior but invisible from the
	// file alone, so a reader running the manifest from a different cwd has no
	// way to know without testing.
	if result.SuggestedManifest != nil && manifestHasRelativeReadWrite(result.SuggestedManifest) {
		yamlBytes = annotateRelativePaths(yamlBytes)
	}
	// Inject "this trial actually touched: ..." notes above read:/write: so the
	// reviewer has a concrete trimming target. The manifest's grants are often
	// broader than the observation set (e.g. `read: [.]` granting the whole
	// script dir to expose one file).
	if result.SuggestedManifest != nil {
		hasBroadRead := manifestHasBroadDot(result.SuggestedManifest.Read)
		hasBroadWrite := manifestHasBroadDot(result.SuggestedManifest.Write)
		if len(result.FSObservations) > 0 || len(result.FSWrites) > 0 || hasBroadRead || hasBroadWrite {
			yamlBytes = annotateObservedPaths(yamlBytes, result.FSObservations, result.FSWrites, hasBroadRead, hasBroadWrite)
		}
	}
	if err := os.WriteFile(outPath, append([]byte(header.String()), yamlBytes...), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error writing manifest:", err)
		return 1
	}
	if result.ExitCode != 0 {
		// --force path: the trial failed but we wrote anyway. Be loud about
		// it — the final line was previously indistinguishable from a clean
		// profile, and the manifest header's WARNING block is easy to miss.
		fmt.Fprintln(os.Stderr, "[bento] ──────────────── warning ────────────────")
		fmt.Fprintf(os.Stderr, "[bento] wrote %s FROM A FAILED TRIAL (script exit=%d)\n", outPath, result.ExitCode)
		fmt.Fprintln(os.Stderr, "[bento]   the manifest may be incomplete — see the WARNING block at the top of the file.")
		fmt.Fprintln(os.Stderr, "[bento]   bento profile is exiting with the script's exit code.")
		fmt.Fprintln(os.Stderr, "[bento] ─────────────────────────────────────────")
	} else {
		fmt.Fprintf(os.Stderr, "[bento] wrote %s — review, then `bento validate %s` to see the resolved\n", outPath, outPath)
		fmt.Fprintf(os.Stderr, "[bento]   interpreter/paths, then `bento run %s` to execute under the manifest.\n", outPath)
	}
	if result.SuggestedManifest != nil && result.SuggestedManifest.Network != nil && len(result.SuggestedManifest.Network.Rules) > 0 {
		n := len(result.SuggestedManifest.Network.Rules)
		noun := "rule"
		if n > 1 {
			noun = fmt.Sprintf("%d rules", n)
		}
		fmt.Fprintf(os.Stderr, "[bento] tip: review the network %s before committing — profile records what\n", noun)
		fmt.Fprintln(os.Stderr, "[bento]   this one run touched; production paths may differ.")
	}
	return result.ExitCode
}

// writeScaffoldManifest emits a commented manifest skeleton without running
// the script. Used by `bento profile --scaffold` for scripts that can't be
// profiled live (production-only, destructive on first run, requires
// secrets the developer doesn't have, etc.). The output is intentionally
// "everything commented" so the user opts in to each field.
func writeScaffoldManifest(outPath, scriptPath, interp string, m *bento.Manifest) int {
	var b strings.Builder
	fmt.Fprintf(&b, "# generated by `bento profile --scaffold %s` — fill in and uncomment fields.\n", scriptPath)
	fmt.Fprintf(&b, "# bento %s · %s\n", bentoVersionTag(), time.Now().UTC().Format(time.RFC3339))
	b.WriteString("#\n# This is a STATIC scaffold: the script was not executed. Compare with\n")
	b.WriteString("# `bento profile <script>` (which runs the script once and records what it\n")
	b.WriteString("# actually touched) — that produces a tighter, observation-based manifest.\n")
	b.WriteString("# Use --scaffold when you can't run the script (production-only, destructive,\n")
	b.WriteString("# requires unavailable secrets, etc.).\n")
	b.WriteString("#\n# Required fields are uncommented; everything else is opt-in. Start permissive\n")
	b.WriteString("# enough that the script runs, then `bento validate <this-file>` and tighten.\n")

	b.WriteString("\n")
	// ELF binaries report `interpreter == script` from PracticalStrictManifest;
	// the actual manifest omits `interpreter:` entirely for ELF.
	isELF := m.Interpreter != "" && m.Script != "" && m.Interpreter == m.Script
	switch {
	case isELF:
		b.WriteString("# (no interpreter: this is an ELF binary — bento execs it directly)\n")
	case m.Interpreter != "":
		fmt.Fprintf(&b, "interpreter: %s\n", m.Interpreter)
	default:
		b.WriteString("# interpreter: python3   # leave unset for ELF binaries\n")
	}
	fmt.Fprintf(&b, "script: %s\n", scriptPath)

	b.WriteString("\n# Paths the script may READ. Add directories rather than individual files when\n")
	b.WriteString("# the script enumerates a folder. Mandatory-deny paths (SSH keys, cloud creds,\n")
	b.WriteString("# shell rc files) are always shadowed regardless of what you list here.\n")
	b.WriteString("# read:\n")
	b.WriteString("#   - /etc/services\n")
	b.WriteString("#   - ./inputs\n")

	b.WriteString("\n# Paths the script may WRITE. Prefer containing directories over literal\n")
	b.WriteString("# filenames — a path with a timestamp/PID/UUID will not match a literal rule\n")
	b.WriteString("# on the next run, and the write will silently land on the sandbox tmpfs.\n")
	b.WriteString("# write:\n")
	b.WriteString("#   - /tmp\n")

	b.WriteString("\n# Outbound network. Bento blocks by default; each allowed destination needs an\n")
	b.WriteString("# explicit host:port rule. Wildcards: \"*\" (any host) and \".example.com\" (suffix).\n")
	b.WriteString("# network:\n")
	b.WriteString("#   rules:\n")
	b.WriteString("#     - host: api.example.com\n")
	b.WriteString("#       port: \"443\"\n")

	if isShellInterpreter(interp) {
		b.WriteString("\n# Shell script — uncomment to permit subprocess execve. Without this every\n")
		b.WriteString("# external command (ls, tar, curl, ...) fails with EPERM at the first fork.\n")
		b.WriteString("# allow_exec: true\n")
	} else {
		b.WriteString("\n# allow_exec: true   # permit subprocess execve (required by shell scripts and\n")
		b.WriteString("#                    # any tool that forks — `git`, `make`, `npm`, build wrappers)\n")
	}

	b.WriteString("\n# Host env vars to inherit into the sandbox. Bento strips host env by default,\n")
	b.WriteString("# so anything the script reads via `$NAME` / `os.environ[\"NAME\"]` must be listed\n")
	b.WriteString("# here OR passed at run time with `--env NAME=VALUE`. USER/LOGNAME/HOME are\n")
	b.WriteString("# always replaced by sandbox values regardless of this list.\n")
	b.WriteString("# env:\n")
	b.WriteString("#   - CITY\n")

	b.WriteString("\n# Resource caps (optional). bento installs a cgroup with these limits.\n")
	b.WriteString("# limits:\n")
	b.WriteString("#   memory: \"128M\"\n")
	b.WriteString("#   cpu:    \"100%\"\n")
	b.WriteString("#   tasks:  32\n")

	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error writing manifest:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[bento] wrote %s (scaffold; no observation run performed)\n", outPath)
	fmt.Fprintln(os.Stderr, "[bento] next: fill in the fields the script needs, then `bento validate` it.")
	fmt.Fprintln(os.Stderr, "[bento]   when you CAN run the script, `bento profile <script>` produces a tighter")
	fmt.Fprintln(os.Stderr, "[bento]   manifest by recording actual file/network activity.")
	return 0
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

func printFSWrites(w io.Writer, paths []string, tmpfsPresent bool) {
	// Always emit the section header — even when empty. Previously this
	// branch returned silently, and the asymmetry with the "no network
	// observations" line trained users to read "no output here" as "didn't
	// happen" when it actually meant "didn't look hard enough" (e.g. the
	// strace observer didn't trace unlinkat, so `find -delete` was invisible).
	// EXCEPT: when tmpfs-doomed writes ARE about to be printed, "no filesystem
	// writes observed" reads as contradictory — suppress the negative line
	// since printTmpfsWrites is going to surface the writes anyway.
	if len(paths) == 0 {
		if tmpfsPresent {
			return
		}
		fmt.Fprintln(w, "[bento] no persistent filesystem writes observed")
		fmt.Fprintln(w)
		return
	}
	fmt.Fprintln(w, "[bento] observed filesystem writes:")
	for _, p := range paths {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintln(w)
}

// readCommentedEnvNames returns names listed under a commented `# env:` block
// in the manifest file. `bento profile` writes such blocks to nudge users to
// uncomment names they want inherited; without this, `validate` says
// "env: (none)" while the manifest's own YAML right above shows names like
// CITY waiting to be activated.
//
// Pattern matched (lines starting with `#`, leading whitespace allowed):
//
//	# env:
//	#   - CITY
//	#   - REGION   ← arbitrary trailing comment
//
// Anything that doesn't look like `#   - NAME` ends the block.
func readCommentedEnvNames(manifestPath string) []string {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			inBlock = false
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		if body == "env:" {
			inBlock = true
			continue
		}
		if !inBlock {
			continue
		}
		// Expect `- NAME` (optionally with comment after).
		if !strings.HasPrefix(body, "- ") {
			inBlock = false
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(body, "-"))
		// Strip any trailing comment after the name (e.g. `CITY  ← uncomment if ...`).
		if i := strings.IndexAny(name, " \t"); i >= 0 {
			name = name[:i]
		}
		// Env var names: letters, digits, underscore. Bail on anything else.
		if name == "" || !isEnvVarName(name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// printImplicitMounts surfaces the directories the runner sets up regardless
// of what the manifest declares. Without this, the resolved view in validate
// leaves a junior thinking the sandbox sees only what's listed under `read:`
// / `write:` — but procfs, sysfs, the script bind-mount, and the mandatory-
// deny shadows are all live too.
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

// sideBySidePath produces a sibling filename next to the existing manifest
// so the "already exists" hint can suggest a concrete diff target. For
// `foo.manifest.yaml` returns `foo.manifest.next.yaml`.
func sideBySidePath(outPath string) string {
	dir, base := filepath.Split(outPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, stem+".next"+ext)
}

// annotateArgsBlock inserts a comment immediately above the top-level `args:`
// key in the marshaled YAML so the reader knows the args were captured from
// the profile trial — and won't be a surprise when every future `bento run`
// passes them. No-op if the line isn't found.
func annotateArgsBlock(yamlBytes []byte) []byte {
	const note = "# args from this profile trial — used by `bento run` only when no CLI args\n" +
		"# are passed (CLI args replace by default). Pass `--append-args` to extend\n" +
		"# these instead of replacing, or comment them out to drop the bake-in entirely.\n"
	lines := strings.Split(string(yamlBytes), "\n")
	for i, line := range lines {
		if line == "args:" {
			out := make([]string, 0, len(lines)+2)
			out = append(out, lines[:i]...)
			out = append(out, strings.TrimRight(note, "\n"))
			out = append(out, lines[i:]...)
			return []byte(strings.Join(out, "\n"))
		}
	}
	return yamlBytes
}

// manifestHasRelativeReadWrite reports whether any read: or write: entry in
// the manifest is a relative path. Used to decide whether to attach the
// "relative paths resolve against the manifest's directory" note.
func manifestHasRelativeReadWrite(m *bento.Manifest) bool {
	if m == nil {
		return false
	}
	for _, p := range m.Read {
		if !filepath.IsAbs(p) {
			return true
		}
	}
	for _, p := range m.Write {
		if !filepath.IsAbs(p) {
			return true
		}
	}
	return false
}

// annotateObservedPaths inserts, above the read:/write: YAML blocks, a comment
// listing the host paths the trial run actually touched. The manifest's
// `read:`/`write:` entries are often broader than the literal observations
// (e.g. `read: [.]` granting the whole script directory) — and `bento profile`
// already prints "observed filesystem writes: <paths>" to the terminal but
// drops that info on the floor. Re-encode it in the artifact so a reviewer
// has a concrete trimming target instead of the generic "review and trim".
//
// broadRead/broadWrite signal that the corresponding block contains a `.`
// grant. When true and no concrete observations exist for that side (common
// for `read:` in bash profiles — the profiler doesn't surface individual read
// paths there), emit a placeholder note so the reader knows the asymmetry
// with the other block is intentional, not a missing annotation.
func annotateObservedPaths(yamlBytes []byte, observedReads, observedWrites []string, broadRead, broadWrite bool) []byte {
	lines := strings.Split(string(yamlBytes), "\n")
	insertConcrete := func(idx int, paths []string, what string) []string {
		var b strings.Builder
		fmt.Fprintf(&b, "# this trial actually touched (%s):\n", what)
		for _, p := range paths {
			fmt.Fprintf(&b, "#   - %s\n", p)
		}
		b.WriteString("# the rule below may be broader (e.g. `.` grants the whole directory); trim to\n")
		b.WriteString("# the specific entries above to tighten, or keep broad if other invocations need more.")
		out := make([]string, 0, len(lines)+10)
		out = append(out, lines[:idx]...)
		out = append(out, b.String())
		out = append(out, lines[idx:]...)
		return out
	}
	insertPlaceholder := func(idx int, what string) []string {
		var b strings.Builder
		fmt.Fprintf(&b, "# this trial: no individual %s paths surfaced by the profiler — `.` below\n", what)
		b.WriteString("# is the conservative default (grants the manifest's directory). If you know\n")
		fmt.Fprintf(&b, "# which paths the script %ss, list them explicitly to tighten the grant.", what)
		out := make([]string, 0, len(lines)+5)
		out = append(out, lines[:idx]...)
		out = append(out, b.String())
		out = append(out, lines[idx:]...)
		return out
	}
	// Walk lines twice (read:, then write:) since each insertion shifts the
	// index of the next block; recompute by re-scanning the in-flight result.
	for i, line := range lines {
		if line == "read:" {
			switch {
			case len(observedReads) > 0:
				lines = insertConcrete(i, observedReads, "read")
			case broadRead:
				lines = insertPlaceholder(i, "read")
			}
			break
		}
	}
	for i, line := range lines {
		if line == "write:" {
			switch {
			case len(observedWrites) > 0:
				lines = insertConcrete(i, observedWrites, "write")
			case broadWrite:
				lines = insertPlaceholder(i, "write")
			}
			break
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// manifestHasBroadDot reports whether the slice contains a literal "." entry,
// which after manifest dir resolution grants the whole manifest directory.
func manifestHasBroadDot(paths []string) bool {
	for _, p := range paths {
		if p == "." {
			return true
		}
	}
	return false
}

// annotateRelativePaths inserts a one-line note above the first of read:/write:
// in the marshaled YAML so a reader understands that "." resolves against the
// manifest's directory, not the shell's cwd. No-op if neither block is found.
func annotateRelativePaths(yamlBytes []byte) []byte {
	const note = "# relative paths under read:/write: (e.g. `.`) resolve against this manifest's\n" +
		"# directory, NOT the shell cwd you run `bento` from."
	lines := strings.Split(string(yamlBytes), "\n")
	for i, line := range lines {
		if line == "read:" || line == "write:" {
			out := make([]string, 0, len(lines)+2)
			out = append(out, lines[:i]...)
			out = append(out, note)
			out = append(out, lines[i:]...)
			return []byte(strings.Join(out, "\n"))
		}
	}
	return yamlBytes
}

// manifestHasRelativePathEntries scans the raw manifest YAML for read:/write:
// entries that are relative paths. validate resolves these to absolute paths
// before printing, so without this check a reader can't tell whether the path
// in the output was literally typed or was rewritten relative to the manifest
// dir (a teammate running validate from a different cwd would otherwise see
// different paths from the same manifest, which looks like an edit).
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

// emitScriptOutputDiagnostic surfaces the failing script's own stdout/stderr
// when the trial run exited nonzero. Shell scripts that redirect everything
// inside `{ … } > file` (or via `exec >file`) print nothing to the terminal
// even on failure — without this block, the user sees only "script exit code:
// 1" and has no signal where the script broke. When the script DID print
// something, the lines already streamed live; we just point at them so the
// reader knows where to look.
func emitScriptOutputDiagnostic(w io.Writer, scriptOutput, _ string, interp string) {
	scriptOutput = strings.TrimRight(scriptOutput, "\n")
	if scriptOutput == "" {
		fmt.Fprintln(w, "[bento] ──────────────── note ────────────────")
		fmt.Fprintln(w, "[bento] script printed nothing to stdout/stderr before exiting nonzero.")
		fmt.Fprintln(w, "[bento]   common when shell scripts redirect with `{ … } > file` or `exec >file`")
		fmt.Fprintln(w, "[bento]   and never reach a later command that prints to the terminal. To see")
		fmt.Fprintln(w, "[bento]   where the script broke, add diagnostics that bypass the redirect:")
		if isShellInterpreter(interp) {
			fmt.Fprintln(w, "[bento]     set -x                    # at the top of the script (echoes commands as it runs)")
			fmt.Fprintln(w, "[bento]     command 2>&3 3>&-         # send a key step's stderr around the block redirect")
		} else {
			fmt.Fprintln(w, "[bento]     add `print(..., file=sys.stderr, flush=True)` around suspect lines")
		}
		fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
		return
	}
	// Show last ~20 lines. Lines already streamed live; we just point.
	lines := strings.Split(scriptOutput, "\n")
	const maxLines = 20
	start := 0
	truncated := false
	if len(lines) > maxLines {
		start = len(lines) - maxLines
		truncated = true
	}
	fmt.Fprintln(w, "[bento] ──────────────── script output (tail) ────────────────")
	if truncated {
		fmt.Fprintf(w, "[bento]   (last %d of %d lines; full output is interleaved above)\n", maxLines, len(lines))
	}
	for _, l := range lines[start:] {
		fmt.Fprintf(w, "    %s\n", l)
	}
	fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
}

// noteHostTmpBindIfRelevant fires the "host /tmp is bind-mounted" note only
// when the trial run actually touched /tmp paths (write or read). Printing
// it unconditionally trains users to ignore it — and it's only meaningful
// when /tmp content actually mattered to the script.
func noteHostTmpBindIfRelevant(w io.Writer, fsWrites, fsObservations []string) {
	touched := func(paths []string) bool {
		for _, p := range paths {
			if strings.HasPrefix(p, "/tmp/") || p == "/tmp" {
				return true
			}
		}
		return false
	}
	if !touched(fsWrites) && !touched(fsObservations) {
		return
	}
	if _, err := os.Stat("/tmp"); err != nil {
		return
	}
	fmt.Fprintln(w, "[bento] note: profile bound host /tmp writable for this trial — other processes'")
	fmt.Fprintln(w, "[bento]   tempfiles were visible to the script, and a script that walks /tmp (`du`,")
	fmt.Fprintln(w, "[bento]   `ls`, `find`) sees them. `bento run` gives the script a fresh tmpfs at /tmp")
	fmt.Fprintln(w, "[bento]   instead, so the runtime environment differs from this profile's.")
}

// noteProfileVsRunTmpDivergence points the user at `bento run` when the
// trial run failed but the generated manifest looks salvageable AND the
// script touched host /tmp. The most common shape: `du -sh /tmp/*` exits
// nonzero under pipefail during profile (host /tmp has unreadable files)
// but works fine under run (fresh tmpfs).
func noteProfileVsRunTmpDivergence(w io.Writer, scriptPath string, fsWrites []string) {
	relevant := false
	for _, p := range fsWrites {
		if strings.HasPrefix(p, "/tmp/") || p == "/tmp" {
			relevant = true
			break
		}
	}
	if !relevant {
		return
	}
	fmt.Fprintln(w, "[bento]   profile bind-mounted host /tmp, but `bento run` gives the script a fresh")
	fmt.Fprintln(w, "[bento]   tmpfs at /tmp. If the failure was triggered by something the script saw")
	fmt.Fprintln(w, "[bento]   under host /tmp (e.g. `du /tmp/*` + `set -o pipefail`), the manifest may")
	fmt.Fprintln(w, "[bento]   still work — re-run with --force to write it anyway, then:")
	candidate := strings.TrimSuffix(scriptPath, filepath.Ext(scriptPath)) + ".manifest.yaml"
	fmt.Fprintf(w, "[bento]     bento profile --force %s   # write the manifest from this failed trial\n", scriptPath)
	fmt.Fprintf(w, "[bento]     bento run %s   # /tmp is a fresh tmpfs here\n", candidate)
}

// printTmpfsWrites surfaces /sandbox/* writes that landed on the sandbox tmpfs.
// These don't go into the suggested manifest (they have no host destination),
// but the script believed them — the user needs to pick a real target.
func printTmpfsWrites(w io.Writer, paths []string, scriptDir string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] writes that landed on sandbox tmpfs (NOT persisted, no host destination):")
	for _, p := range paths {
		fmt.Fprintf(w, "  %s\n", p)
	}
	// The script wrote to /sandbox/X — a relative path resolved against the
	// in-sandbox cwd, not the host pwd. `write:` declares host destinations,
	// so adding the host equivalent of /sandbox does NOTHING: the script
	// still writes to /sandbox/X, which is tmpfs. Only two fixes actually
	// work: point the script at an absolute host path (via --env), or have
	// the script `cd $BENTO_SCRIPT_DIR` so its relative writes land in the
	// bind-mounted script directory.
	fmt.Fprintln(w, "[bento]   these were written to relative paths, which resolve against the sandbox cwd")
	fmt.Fprintln(w, "[bento]   `/sandbox` (a tmpfs) — NOT your shell's pwd. Adding the host directory to")
	fmt.Fprintln(w, "[bento]   `write:` will not help: the script never tries to reach the host path.")
	fmt.Fprintln(w, "[bento]   Two fixes (pick one):")
	if hosts := proposeHostWrites(paths, scriptDir); len(hosts) > 0 {
		fmt.Fprintln(w, "[bento]     (a) point the script at an absolute host path via env, e.g.:")
		fmt.Fprintf(w, "[bento]           bento run --env OUT=%s/<file> ...\n", hosts[0])
		fmt.Fprintln(w, "[bento]         (then add the host dir to `write:` so the abs path is grantable):")
		fmt.Fprintln(w, "[bento]           write:")
		for _, h := range hosts {
			fmt.Fprintf(w, "[bento]             - %s\n", h)
		}
		fmt.Fprintln(w, "[bento]     (b) `cd \"$BENTO_SCRIPT_DIR\"` at the top of the script so relative paths")
		fmt.Fprintln(w, "[bento]         land in the script's host directory (already bind-mounted writable")
		fmt.Fprintln(w, "[bento]         during profile; add it to `write:` for `bento run` to persist).")
	} else {
		fmt.Fprintln(w, "[bento]     (a) point the script at an absolute host path via --env NAME=/abs/path,")
		fmt.Fprintln(w, "[bento]         and add the directory to `write:`.")
		fmt.Fprintln(w, "[bento]     (b) `cd \"$BENTO_SCRIPT_DIR\"` at the top of the script so relative paths")
		fmt.Fprintln(w, "[bento]         land in the (writable) script directory.")
	}
	fmt.Fprintln(w)
}

// printBlockedConnects surfaces outbound connect() calls the proxy-based
// observation pipeline couldn't see — typically a Go/Rust/etc. compiled
// binary that doesn't route through libproxychains and gets denied by
// Landlock TCP. Without this, profile silently emits a manifest with no
// `network:` rules even when the binary clearly tried to dial out.
// isProfileTargetELF reports whether the script bento is about to profile is a
// compiled ELF binary (where libproxychains-based hostname capture doesn't
// fire) rather than a script run under an interpreter. The interp resolver
// returns the script's own path for ELF targets, so the comparison plus an
// `os.Stat` of the script is enough to tell.
func isProfileTargetELF(scriptPath, interp string) bool {
	if interp == "" {
		return false
	}
	abs, err := filepath.Abs(scriptPath)
	if err != nil {
		abs = scriptPath
	}
	return abs == interp
}

func printBlockedConnects(w io.Writer, attempts []bento.ConnectAttempt, elf bool, suggested *bento.Manifest) {
	if len(attempts) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] outbound connect() attempts the libproxychains shim could not observe:")
	for _, c := range attempts {
		status := "DENIED"
		if c.OK {
			status = "ok"
		}
		fmt.Fprintf(w, "  %s:%d  (%s)\n", c.IP, c.Port, status)
	}
	if elf {
		fmt.Fprintln(w, "[bento]   this is an ELF binary; the proxy-based hostname capture only works")
		fmt.Fprintln(w, "[bento]   for libc-routed traffic. The IPs above are what the kernel actually")
		fmt.Fprintln(w, "[bento]   saw — reverse-resolve them and add the hostnames to `network:`:")
	} else {
		fmt.Fprintln(w, "[bento]   the script issued raw socket calls outside the libc/proxychains path.")
		fmt.Fprintln(w, "[bento]   The IPs above are what the kernel saw — add the corresponding hostnames")
		fmt.Fprintln(w, "[bento]   to `network:` (or use IPs directly):")
	}
	fmt.Fprintln(w, "[bento]     network:")
	fmt.Fprintln(w, "[bento]       rules:")
	for _, c := range dedupConnectsByPort(attempts) {
		fmt.Fprintf(w, "[bento]         - host: %s   # or hostname; reverse-DNS may help\n", c.IP)
		fmt.Fprintf(w, "[bento]           port: \"%d\"\n", c.Port)
	}
	if suggested != nil && (suggested.Network == nil || len(suggested.Network.Rules) == 0) {
		fmt.Fprintln(w, "[bento]   (the emitted manifest has no `network:` block yet — this is exactly the")
		fmt.Fprintln(w, "[bento]   gap. hand-edit before `bento run`, or the binary will be denied again.)")
	}
	fmt.Fprintln(w)
}

func dedupConnectsByPort(in []bento.ConnectAttempt) []bento.ConnectAttempt {
	seen := make(map[string]bool)
	var out []bento.ConnectAttempt
	for _, c := range in {
		k := fmt.Sprintf("%s:%d", c.IP, c.Port)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}

// proposeHostWrites maps `/sandbox/X` tmpfs writes to their script-dir
// equivalents. Returns the parent directory of each path (deduped), since
// scripts that wrote `reports/a.txt` and `reports/b.txt` should grant
// `<scriptdir>/reports`, not the individual files.
func proposeHostWrites(tmpfsPaths []string, scriptDir string) []string {
	if scriptDir == "" {
		return nil
	}
	const prefix = "/sandbox/"
	seen := make(map[string]bool)
	var out []string
	for _, p := range tmpfsPaths {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rel := strings.TrimPrefix(p, prefix)
		if rel == "" {
			continue
		}
		// Use the parent dir so multi-file writes don't blow up the list.
		host := filepath.Join(scriptDir, filepath.Dir(rel))
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out
}

// absScriptPath best-effort resolves a script path to absolute so callers
// computing a scriptDir don't get a misleading relative one. Returns the
// input unchanged on error (callers will derive a relative scriptDir,
// which proposeHostWrites then declines to use).
func absScriptPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
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
	issues, notes := collectManifestIssues(m, abs)
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
	printResolvedManifest(os.Stdout, m, abs, issues, notes)
	if len(issues) > 0 {
		return 1
	}
	return 0
}

// collectManifestIssues returns:
//   - issues: real problems (missing script, unresolvable interpreter, missing
//     read paths, missing write parents) that will fail or surprise at run time.
//     Exits non-zero from `bento validate`.
//   - notes: informational findings that aren't necessarily wrong — most
//     commonly, env: allowlist names that aren't set in the current shell.
//     Those become empty strings at run time, but the documented happy path is
//     to supply them via `--env NAME=VALUE` to `bento run` (which `validate`
//     can't see). Surface as a note; do not exit non-zero.
//
// Network rule canonicality is already enforced by Manifest.Validate at load
// time.
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
		status = fmt.Sprintf("%d ISSUE(S) FOUND — see end of output", len(issues))
	case len(notes) > 0:
		status = fmt.Sprintf("ok (%d note(s) — see end of output)", len(notes))
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
	pendingEnv := readCommentedEnvNames(manifestPath)
	fmt.Fprintln(w)
	if len(m.Env) == 0 && len(pendingEnv) == 0 {
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

// mandatoryDenyConflicts returns read paths whose direct children include a
// mandatory-deny target. Mounting such a path read-only crashes bwrap when it
// tries to shadow the deny file with /dev/null (can't create the mount point
// under a ro parent). Profile narrows these before emit; this checks
// hand-written manifests too.
func mandatoryDenyConflicts(reads []string) []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil
	}
	denyParents := make(map[string]struct{})
	for _, d := range append(spec.ExpandDangerousPaths(home), spec.ExpandDangerousWritePaths(home)...) {
		denyParents[filepath.Dir(d)] = struct{}{}
	}
	var bad []string
	for _, r := range reads {
		abs, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if _, ok := denyParents[filepath.Clean(abs)]; ok {
			bad = append(bad, r)
		}
	}
	return bad
}

// emitEffectiveArgv prints the script's effective argv when the manifest bakes
// in args and the user passed more at the CLI. Silent-wrong-args is the
// classic profile trap: `bento profile script.py sample.txt` bakes sample.txt
// into the manifest, and `bento run manifest.yaml other.txt` then appends —
// the script still sees sample.txt as argv[1]. Surface what actually runs so
// the divergence is visible at a glance.
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
	// Default: command-line args REPLACE the manifest's `args:` list. This
	// matches `make`/`npm run`/`cargo run` mental model and avoids the
	// profile-bake-in trap (manifest carries the profile-time sample input
	// as `args:`; a CLI arg silently appended past the script's argv reach).
	// --append-args opts in to the pipeline case where the manifest args
	// are a canonical invocation that should be extended, not replaced.
	// --replace-args is preserved as a no-op for old scripts that pass it.
	appendArgs := fs.Bool("append-args", false, "append command-line args after the manifest's `args:` list (default: replace). Use when the manifest's args are a canonical invocation to extend.")
	replaceArgs := fs.Bool("replace-args", false, "(deprecated, now the default) replace the manifest's `args:` list with command-line args.")
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

	if *appendArgs && *replaceArgs {
		fmt.Fprintln(os.Stderr, "error: --append-args and --replace-args are mutually exclusive")
		return 2
	}
	if *replaceArgs {
		// --replace-args is the new default; keep accepting the flag so
		// existing scripts/docs don't break, but note that it's a no-op.
		fmt.Fprintln(os.Stderr, "[bento] note: --replace-args is the default now (kept for compatibility); pass --append-args for the old append behavior.")
	}
	target := fs.Arg(0)
	if isManifestPath(target) {
		return runManifest(target, scriptArgs, *appendArgs, *timeout, env, mode, telemetry, grantCB, *verbose)
	}
	if *appendArgs {
		fmt.Fprintln(os.Stderr, "[bento] note: --append-args has no effect in zero-config mode (no manifest args to append to).")
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
	warnStrippedShellVars(os.Stderr, scriptPath, interp, env, true /* includeIdentity */)
	// Preflight: zero-config has no network, but a script using urllib/http/
	// requests/etc. will fail deep inside its stdlib's stack trace — by the
	// time the post-run hint fires, the user has already scrolled past 30
	// lines of traceback. Surface the diagnosis BEFORE the script runs so
	// the warning sits above any traceback in the user's terminal.
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
	// Always check for hint signatures — a bash script that runs `ls` (blocked)
	// then `echo done` exits 0, but the user still needs the exec-block hint.
	emitPostRunHint(os.Stderr, hintModeZeroConfig, scriptPath, m, tail.String(), preflightNetFired)
	// Zero-config has no `write:` list, so every successful write outside
	// bento's sandbox bookkeeping is by definition lost.
	if emitSilentWriteWarning(os.Stderr, fsOpens, nil, tail.String()) && code == 0 {
		fmt.Fprintln(os.Stderr, "[bento] tmpfs writes are treated as errors; exiting non-zero.")
		code = 1
	}
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
	// The banner's `read=./` reads as "your current directory is mounted; relative
	// paths just work." But inside the sandbox cwd is /sandbox (not the host pwd),
	// so a relative argv like `./input.txt` resolves to /sandbox/input.txt and
	// hits FileNotFoundError. Pre-empt the most common first-day head-scratch.
	fmt.Fprintln(w, "[bento]   (inside the sandbox cwd is /sandbox; pass argv paths as absolute —")
	fmt.Fprintln(w, "[bento]   relative paths resolve against /sandbox, not your shell's pwd.)")
}

// detectRelativePathHostMiss looks for a script-tail mention of a `./X` path
// where X exists at scriptDir/X on the host. That's the "script works on my
// machine because pwd has the file, but inside the sandbox /sandbox is a
// fresh tmpfs that doesn't" trap — the failure is the sandbox, not the
// script. Returns the matched relative path (e.g. "./weather.csv") or ""
// when nothing matches.
func detectRelativePathHostMiss(scriptTail, scriptDir string) string {
	if scriptDir == "" {
		return ""
	}
	for _, m := range reRelativePathInOutput.FindAllStringSubmatch(scriptTail, -1) {
		rel := m[1]
		// Skip "./" alone or paths with traversal — only flag plain
		// `./name[/sub]` cases where we can confidently check the host.
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

// Matches a relative path token in script output. Anchored on `./` followed
// by a filename-ish run (letters/digits/_/-/./). Captures the whole `./X`.
var reRelativePathInOutput = regexp.MustCompile(`(\./[A-Za-z0-9_./-]+)`)

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

// Match script-self-locating patterns specifically. Plain `dirname` is too
// loose — scripts often call `dirname "$INPUT"` on user data and have nothing
// to do with locating the script itself. Require an explicit `$0` /
// `${BASH_SOURCE…}` reference somewhere in the file.
var reShellCwdAssumption = regexp.MustCompile(`\$0\b|\$\{?BASH_SOURCE\b`)

// warnLikelyNetworkUseInZeroConfig scans the script source for cheap, high-
// confidence indicators that it makes outbound network calls. When found, it
// emits a single-line preflight note so the warning lands ABOVE any traceback
// the script later produces. The post-run hint (emitPostRunHint) still fires
// on actual failure with the precise host name — this is just the heads-up.
//
// Restricted to shell and Python scripts (the source-scanning interpreters);
// ELF binaries get a parallel, source-blind notice (see below).
// Returns true when the preflight network warning was actually printed. The
// caller uses this to condense the post-run hint (which would otherwise repeat
// the same advice 60 lines below a Python traceback).
func warnLikelyNetworkUseInZeroConfig(w io.Writer, scriptPath, interp string) bool {
	// ELF binaries: bento can't source-scan, so we don't know whether the
	// binary calls out. Print a short, source-blind preflight note so the
	// Go/Rust/C user gets symmetric advice to the Python/shell case (where
	// they otherwise have to wait for the post-failure hint). One line; no
	// false-positive cost — it's framed as conditional.
	if isELFScript(scriptPath, interp) {
		fmt.Fprintln(w, "[bento] preflight: compiled binary — bento can't scan for network use; if it calls")
		fmt.Fprintf(w, "[bento]   out, zero-config has no network and the call will fail. Run `bento profile %s`\n", scriptPath)
		fmt.Fprintln(w, "[bento]   to capture observed hosts and emit a manifest.")
		return true
	}
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
	default:
		return false
	}
	if !pat.Match(src) {
		return false
	}
	fmt.Fprintln(w, "[bento] preflight: script appears to make outbound network calls, but zero-config has")
	fmt.Fprintln(w, "[bento]   no network access. The call will fail with a DNS or connection error. Run")
	fmt.Fprintf(w, "[bento]   `bento profile %s` to record observed hosts and emit a manifest.\n", scriptPath)
	return true
}

// warnLikelyFailureInManifest runs the same static script-shape detectors
// in manifest mode and surfaces a preflight note BEFORE the script's own
// traceback. The post-run hint still fires with the precise host/binary;
// this just ensures the actionable advice lands above the wall of script
// stderr rather than below it.
//
// Two cheap checks:
//   - script makes outbound calls AND manifest's network is empty → DNS failure
//   - shell script forks subprocesses AND manifest doesn't set allow_exec → EPERM
// Returns true when any preflight network/host warning was printed (the
// post-run hint uses this to avoid repeating itself below a wall of script
// stderr).
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
		// Restrict the wrong-host preflight to shell and python scripts (pat
		// non-nil) and gate on the same net-call detector so we don't grep
		// arbitrary binaries for URL substrings — ELF binaries commonly embed
		// Go runtime URLs (go.dev), Rust panic-handler URLs, certificate
		// authority issuer URLs, etc., none of which the binary actually
		// contacts at runtime.
		missing := scriptHostsMissingFromRules(src, m.Network)
		// Script source mentions a host that isn't in this manifest's rules.
		// The post-run hint also names the host (via the proxy DENY log), but
		// surfacing it preflight puts the advice above the script's traceback
		// rather than scrolled past it.
		fmt.Fprintln(w, "[bento] preflight: script source references host(s) that aren't in this manifest's")
		fmt.Fprintln(w, "[bento]   `network.rules`. The proxy will reject these with 403 and the script's network")
		fmt.Fprintln(w, "[bento]   call will fail (typically buried in a multi-line traceback):")
		for _, h := range missing {
			fmt.Fprintf(w, "[bento]   - %s\n", h)
		}
		fmt.Fprintln(w, "[bento]   add to network.rules or re-profile to capture them.")
		netFired = true
	}
	// Exec preflight only applies to shell scripts: Python `subprocess.run`
	// is too commonly used for non-fork purposes to flag reliably, and ELF
	// binaries can't be source-scanned.
	if isShellInterpreter(interp) && !m.AllowExec && reShellExecCall.Match(src) {
		fmt.Fprintln(w, "[bento] preflight: shell script forks external commands but the manifest leaves")
		fmt.Fprintln(w, "[bento]   `allow_exec: false` (the default). Every subprocess will fail with EPERM.")
		fmt.Fprintln(w, "[bento]   Add `allow_exec: true` to the manifest if those subprocesses are expected.")
	}
	return netFired
}

// reScriptHostRef extracts host-like tokens from script source: literal URLs
// (https://example.com/...) and quoted bare hostnames passed to shell network
// tools (curl example.com). The pattern is conservative — it favors false
// negatives over false positives because the resulting preflight message
// names a specific host. A bogus host in the warning would be worse than
// missing a real one.
var reScriptHostRef = regexp.MustCompile(`https?://([A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})`)

// scriptHostsMissingFromRules returns hostnames the script source mentions in
// URLs that aren't covered by any rule in net. Returns nil if net is nil or
// has no rules — the empty-rules case is handled by the caller's separate
// "no rules" preflight branch. Matches against rule.Host using the same
// wildcard semantics the proxy uses ("*" / ".suffix" / literal).
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
		if !ruleCoversHost(net.Rules, host) {
			out = append(out, host)
		}
	}
	return out
}

// ruleCoversHost matches the proxy's allowlist semantics: literal equality,
// suffix match for ".example.com", or wildcard "*".
func ruleCoversHost(rules []bento.NetworkRule, host string) bool {
	for _, r := range rules {
		h := strings.ToLower(r.Host)
		switch {
		case h == "*":
			return true
		case strings.HasPrefix(h, "."):
			if strings.HasSuffix(host, h) || host == strings.TrimPrefix(h, ".") {
				return true
			}
		case h == host:
			return true
		}
	}
	return false
}

// reShellExecCall matches shell commands that clearly fork an external
// binary. Intentionally NOT matching shell builtins like echo/cd/export.
// Tuned conservatively — false positives produce a noisy warning every run.
var reShellExecCall = regexp.MustCompile(
	`(?m)(?:^|[\s;|&$(` + "`" + `])` +
		`(?:` +
		`tar|gzip|gunzip|zip|unzip|` +
		`cp|mv|rm|mkdir|chmod|chown|ln|find|xargs|` +
		`ls|cat|head|tail|sort|uniq|wc|cut|tr|sed|awk|grep|` +
		`date|du|df|stat|file|basename|dirname|realpath|` +
		`ps|kill|sleep|env|whoami|id|uname|hostname|` +
		`git|make|cargo|go|npm|node|python3?|ruby|perl|java|` +
		`docker|kubectl|systemctl|journalctl|` +
		`curl|wget|nc|ssh|scp|rsync|ping|dig|host|nslookup` +
		`)\b`)

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

// warnProfileTimeEnvDivergence reads the `# --env NAME=VALUE` lines from the
// manifest's header comment block (written by `bento profile` when --env was
// used) and warns when the current run is about to use a different value
// than the profile trial recorded. This catches the common trap:
//
//	bento profile --env CITY=Paris weather.py    # works, writes /tmp/Paris.csv
//	bento run weather.manifest.yaml              # silently uses default, writes /tmp/London.csv
//
// CLI --env overrides suppress the warning per-variable; the user has clearly
// chosen a value. A host env that happens to match is also fine.
func warnProfileTimeEnvDivergence(w io.Writer, manifestPath string, cliEnv map[string]string) {
	profileEnv := readProfileTimeEnvComments(manifestPath)
	if len(profileEnv) == 0 {
		return
	}
	type diff struct{ name, profileVal, runtimeVal string }
	var diverged []diff
	names := make([]string, 0, len(profileEnv))
	for k := range profileEnv {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		profVal := profileEnv[name]
		if v, ok := cliEnv[name]; ok {
			if v != profVal {
				// User explicitly chose a different value — fine, but record.
				diverged = append(diverged, diff{name, profVal, v})
			}
			continue
		}
		if v, ok := os.LookupEnv(name); ok {
			if v != profVal {
				diverged = append(diverged, diff{name, profVal, v})
			}
			continue
		}
		// Not in CLI --env, not set on host: script will see empty string
		// (or its built-in default), which is almost certainly NOT what the
		// profile trial used.
		diverged = append(diverged, diff{name, profVal, ""})
	}
	if len(diverged) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] ──────────────── note ────────────────")
	fmt.Fprintln(w, "[bento] profile-time --env values differ from this run's environment:")
	for _, d := range diverged {
		if d.runtimeVal == "" {
			fmt.Fprintf(w, "[bento]   $%s: profile used %q, this run will see empty (script's default)\n", d.name, d.profileVal)
		} else {
			fmt.Fprintf(w, "[bento]   $%s: profile used %q, this run will see %q\n", d.name, d.profileVal, d.runtimeVal)
		}
	}
	fmt.Fprintln(w, "[bento] the manifest's `env:` allowlist only forwards a name; values are not preserved.")
	fmt.Fprintf(w, "[bento] pass `--env %s=%s` to match the profile run, or export in your shell first.\n",
		diverged[0].name, diverged[0].profileVal)
	fmt.Fprintln(w, "[bento] ──────────────────────────────────────")
}

// readProfileTimeEnvComments parses the `# --env NAME=VALUE` lines emitted by
// `bento profile` into the manifest's header comment block. Returns an empty
// map when the file is missing or the comment block isn't present.
func readProfileTimeEnvComments(manifestPath string) map[string]string {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil
	}
	out := make(map[string]string)
	for _, raw := range strings.Split(string(data), "\n") {
		// Only consider comment lines (the header is comment-only and the
		// YAML body starts with `interpreter:` or similar — once we hit
		// non-comment content, the header is over).
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			break
		}
		// Expected shape: `#   --env NAME=VALUE` (leading spaces vary).
		body := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		if !strings.HasPrefix(body, "--env ") {
			continue
		}
		kv := strings.TrimSpace(strings.TrimPrefix(body, "--env "))
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		name := kv[:eq]
		value := kv[eq+1:]
		if isEnvVarName(name) {
			out[name] = value
		}
	}
	return out
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
	if includeIdentity && isShellInterpreter(interp) {
		for _, tok := range identityShellTokens(src) {
			sandboxIdentityHits = appendUniqueStr(sandboxIdentityHits, tok)
		}
	}
	// Python equivalents that reach libc / /etc/passwd directly. Same surprise:
	// these return "sandbox", not the host user.
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

// pickOutputEnvName picks the most likely "where to write" env-var name from a
// script's referenced env vars, for the tmpfs-write fix scaffold. Heuristic:
// prefer names that look output-shaped (OUT, OUTPUT, DEST, FILE, PATH suffix);
// fall back to the first referenced name; fall back to a generic placeholder.
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

// reprofileCmd reconstructs a `bento profile` invocation that preserves the
// current run's flags and appends `extras` (typically the new flag the user
// needs — `--allow-exec`, an extra `--env KEY=VAL`). Without this, advisories
// that say "re-run with --allow-exec" leave the user re-typing every --env
// and --read flag they originally passed; with two failure modes in sequence
// (env, then exec) the command grows long and easy to misassemble.
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

// hasDotRead reports whether the manifest's `read:` list includes "." (the
// script directory). Used to decide whether to explain the entry in the
// generated header.
func hasDotRead(m *bento.Manifest) bool {
	if m == nil {
		return false
	}
	for _, p := range m.Read {
		if p == "." {
			return true
		}
	}
	return false
}

// isShellOrLibcIdentityCall reports whether name is one of the shell-command
// or libc-call identity tokens (whoami, id, getlogin, getpass.getuser, …) as
// opposed to an env-var name (USER, HOME, LOGNAME). The two flavors get
// different "how to override" advice in profile-generated manifests: env vars
// can be reinstated with `--env USER=$USER`, but shell/libc calls go through
// the synthetic /etc/passwd and can't.
func isShellOrLibcIdentityCall(name string) bool {
	switch name {
	case "USER", "LOGNAME", "HOME":
		return false
	}
	return true
}

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
//
// Includes defaulted forms (`os.environ.get("X", "y")`, `${X:-y}`) — at
// profile time the stub is purely informational; the user gets to see every
// referenced var and decide which to inherit. The runtime warning path uses
// the stricter referencedShellVars / referencedPythonEnvVars directly.
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
			continue // sandbox-managed; not user-settable
		}
		out = append(out, n)
	}
	return out
}

// referencedIdentityEnvVarsInScript returns the subset of env vars the script
// references that bento intentionally strips or replaces inside the sandbox
// (USER/LOGNAME) or hardcodes (HOME=/sandbox). These do NOT belong in the
// generated manifest's `env:` allowlist — adding them has no effect — but
// the profile-emitted header calls them out so a reviewer understands why
// the script will see empty/synthetic values for these names.
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
// referencedShellVarsAll is like referencedShellVars but does NOT filter out
// defaulted forms (${X:-y}, ${X-y}, etc.). Used at profile time for the
// manifest's commented env: stub — we want to surface every var the script
// reads, even ones with defaults, so the user can decide which to allowlist.
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
	out := all[:0]
	for _, n := range all {
		if assigned[n] {
			continue
		}
		out = append(out, n)
	}
	return out
}

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
// referencedPythonEnvVarsAll is like referencedPythonEnvVars but also returns
// defaulted forms (os.environ.get("X", default), os.getenv("X", default)).
// Used at profile time for the manifest's commented env: stub — at profile
// time we want to surface every var the script reads, even ones with defaults,
// so the user can decide which to allowlist.
// pythonEnvDefaultStrings extracts literal string defaults from
// `os.environ.get("X", "default")` and `os.getenv("X", "default")` calls.
// These are the values the script ran with when the host env var was unset
// — and the values that appear in any path the script interpolated from
// that var. Used by profile to flag write paths whose basename contains a
// default value (so the brittleness heads-up fires even when the user never
// set the var on the host).
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

// firstQuotedString returns the first '…' or "…" literal in s. Tolerates a
// leading comma + whitespace (the regex tail starts right after the first
// quoted name's closing quote). Doesn't handle escapes or f-strings — those
// don't show up as simple literal defaults in practice.
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
// Returns true if at least one lost write was reported, so the caller can
// surface this in the process exit code (an exit-0 run with silently
// vanished writes is the worst-of-both-worlds for CI).
func emitSilentWriteWarning(w io.Writer, opens []bento.FSOpen, declaredWrites []string, scriptTail string) bool {
	if len(opens) == 0 {
		return false
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
		return false
	}
	fmt.Fprintln(w, "[bento] ──────────────── warning ────────────────")
	fmt.Fprintln(w, "[bento] script wrote to paths not declared in `write:` — these landed in the")
	fmt.Fprintln(w, "[bento]   sandbox tmpfs and vanished on exit (no error was raised inside the script):")
	// Split the lost writes into two classes so the advice can be specific:
	//   - /sandbox/X: relative-path writes against the sandbox cwd. `write:`
	//     can't fix these — the script never tried to reach the host. The
	//     fix is to point the script at an absolute host path (or `cd
	//     $BENTO_SCRIPT_DIR`).
	//   - everything else: host-shaped paths the script DID try to reach but
	//     the manifest didn't grant. `write:` is the correct fix here.
	var sandboxLost, hostLost []string
	for _, p := range lost {
		fmt.Fprintln(w, "[bento]   "+p)
		if strings.HasPrefix(p, "/sandbox/") {
			sandboxLost = append(sandboxLost, p)
		} else {
			hostLost = append(hostLost, p)
		}
	}
	// Cross-reference the lost paths against the script's own output. When the
	// script printed "wrote ... ./releases.json" before exiting, the user reads
	// stdout-then-stderr as "success then failure" — call out the conflict so
	// the success print doesn't look authoritative.
	for _, p := range lost {
		base := filepath.Base(p)
		if base == "" || base == "/" {
			continue
		}
		if strings.Contains(scriptTail, base) {
			fmt.Fprintf(w, "[bento]   ↳ the script's output above mentions `%s` — that print referred to a discarded path.\n", base)
			break
		}
	}
	if len(sandboxLost) > 0 {
		fmt.Fprintln(w, "[bento] the /sandbox/* paths are relative writes resolved against the sandbox cwd")
		fmt.Fprintln(w, "[bento]   (`/sandbox` = tmpfs, NOT your host pwd). Adding to `write:` will not help —")
		fmt.Fprintln(w, "[bento]   the script never tried to reach the host. Fix one of:")
		fmt.Fprintln(w, "[bento]     - pass `--env NAME=/abs/host/path` and have the script use $NAME, OR")
		fmt.Fprintln(w, "[bento]     - `cd \"$BENTO_SCRIPT_DIR\"` at the top of the script (and add the script")
		fmt.Fprintln(w, "[bento]       directory to `write:` so the bind-mount is writable).")
	}
	if len(hostLost) > 0 {
		fmt.Fprintln(w, "[bento] for the host-shaped paths above, add the destination(s) to the manifest's")
		fmt.Fprintln(w, "[bento]   `write:` list to persist them on the host.")
	}
	fmt.Fprintln(w, "[bento] ─────────────────────────────────────────")
	return true
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
func emitPostRunHint(w io.Writer, mode hintMode, scriptPath string, m *bento.Manifest, stderrTail string, preflightNetworkFired bool) {
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
		// When the preflight network warning already fired BEFORE the script
		// ran, the post-run advice is identical advice — and is now sitting
		// under however many lines of script traceback. Collapse to a single
		// pointer line so the user is told once (above) and reminded once
		// (below) instead of buried in 60 lines of urllib internals.
		if preflightNetworkFired {
			s := []string{"[bento] network call failed — see the `preflight: ... no network access` note above for the fix."}
			if hostLine != "" {
				s = append(s, hostLine)
			}
			sections = append(sections, s)
		} else {
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
	// proxy:  `[bento] http-connect: DENY wttr.in:443`  (bento's own log line on
	//         a manifest with rules that don't cover the host — the script's own
	//         stderr only shows "Tunnel connection failed: 403 Forbidden")
	// proxy body / header from writeRejectStatus
	reNetBlock = regexp.MustCompile(`(?i)(name resolution|could not resolve|no such host|name or service not known|getaddrinfo|connection refused|http-connect: deny|tunnel connection failed|x-bento-reject-host|bento blocked outbound connection)`)
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
// We extract the URL host as the next-best signal, and synthesize a default
// port from the scheme so the hint matches the host:port shape a user adds
// to network.rules. Explicit ":port" in the URL wins over the scheme default.
var rePyTracebackURL = regexp.MustCompile(`(https?)://([A-Za-z0-9_.-]+)(?::([0-9]+))?`)

// reProxyDenyHost captures the host from bento's own proxy DENY log line and
// from the X-Bento-Reject-Host header / 403 body the proxy returns. These are
// the most reliable signal for the "manifest has rules but not the right ones"
// case: DNS resolution never happens (rules are checked first), so the
// gaierror/DNS-pattern matchers can't fire.
var reProxyDenyHost = regexp.MustCompile(
	`(?i)(?:http-connect: DENY\s+|x-bento-reject-host:\s*|bento blocked outbound connection to\s+)([A-Za-z0-9_.-]+)(?::([0-9]+))?`)

// extractDeniedHosts returns up to a few unique hostnames the script tried to
// resolve before the sandbox refused. Empty when nothing matches — the caller
// then prints the generic hint without naming a host.
func extractDeniedHosts(stderrTail string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(h, port string) {
		h = strings.Trim(h, "'\".:")
		if h == "" {
			return
		}
		key := h
		if port != "" {
			key = h + ":" + port
		}
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, key)
	}
	// Bento's own proxy DENY log line / 403 body is the most authoritative
	// source — it fires when the manifest has network rules that don't cover
	// the requested host (the wrong-host case), where DNS never gets to fail.
	// The proxy log includes the port; pass it through so the hint says
	// `host:port` (matching the shape a user adds to network.rules).
	for _, m := range reProxyDenyHost.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1], m[2])
		if len(out) >= 5 {
			return out
		}
	}
	for _, m := range reDeniedHost.FindAllStringSubmatch(stderrTail, -1) {
		add(m[1], "")
		if len(out) >= 5 {
			return out
		}
	}
	// Python fallback: gaierror doesn't name the host, but the traceback
	// frame that triggered it almost always does as a URL literal. The URL
	// scheme implies the port (https → 443, http → 80) — encode it so the
	// hint stays copy-pasteable. Explicit ":port" in the URL wins.
	for _, m := range rePyTracebackURL.FindAllStringSubmatch(stderrTail, -1) {
		scheme, host, port := m[1], m[2], m[3]
		if port == "" {
			if strings.EqualFold(scheme, "https") {
				port = "443"
			} else {
				port = "80"
			}
		}
		add(host, port)
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

// isELFScript reports whether scriptPath is an ELF binary serving as its own
// interpreter (the ResolveInterpreterDetailed → InterpreterFromELF case, which
// returns the script's absolute path as the interpreter). Two equivalent checks
// — string equality on path or absolute path — cover the common forms.
func isELFScript(scriptPath, interp string) bool {
	if interp == "" {
		return false
	}
	if interp == scriptPath {
		return true
	}
	if abs, err := filepath.Abs(scriptPath); err == nil && interp == abs {
		return true
	}
	return false
}

// priorManifestLacksAllowExec reports whether the manifest at path is missing
// (or explicitly disables) `allow_exec`. Used by the "already exists" hint to
// give a stronger --force nudge when the user is iterating with --allow-exec.
// Returns false on read/parse error — the hint is just a quality-of-life
// nudge and shouldn't fire on uncertainty.
func priorManifestLacksAllowExec(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var m struct {
		AllowExec bool `yaml:"allow_exec"`
	}
	if err := yaml.Unmarshal(b, &m); err != nil {
		return false
	}
	return !m.AllowExec
}

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
	warnUnsetEnvAllowlist(os.Stderr, m.Env, env)
	// Profile-time --env values are recorded as comments in the manifest (so
	// the YAML stays portable across hosts), but a junior re-running from a
	// fresh shell silently gets a different behavior than the profile run:
	// the script falls back to its default. Surface the divergence.
	warnProfileTimeEnvDivergence(os.Stderr, abs, env)
	var manifestPreflightNetFired bool
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
		// Manifest-driven run: suppress the sandbox-identity portion. The user
		// has already accepted the manifest (and the identity note fired during
		// zero-config / profile); re-printing it on every run is just noise.
		warnStrippedShellVars(os.Stderr, scriptForEnvScan, m.Interpreter, merged, false /* includeIdentity */)
		// Preflight: surface predictable failures (missing network rule, missing
		// allow_exec) ABOVE the script's own traceback. The post-run hint still
		// fires with the precise host/binary; this is the "scroll-saver" copy.
		manifestPreflightNetFired = warnLikelyFailureInManifest(os.Stderr, scriptForEnvScan, m)
	}
	// Echo the effective argv when the manifest bakes in args AND the user
	// is passing more at the CLI. The default is REPLACE (matches make / npm
	// run / cargo run); --append-args opts in to the pipeline case where
	// manifest args are a canonical invocation to extend.
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
	emitPostRunHint(os.Stderr, hintModeManifest, m.Script, m, tail.String(), manifestPreflightNetFired)
	// Silent-tmpfs writes are diagnostically a failure even if the script
	// itself exited 0 — the user's data didn't land on disk and CI shouldn't
	// see a green pipeline. Promote a clean exit to exit=1 in that case.
	if emitSilentWriteWarning(os.Stderr, fsOpens, resolveDeclaredWrites(m, filepath.Dir(abs)), tail.String()) && code == 0 {
		fmt.Fprintln(os.Stderr, "[bento] tmpfs writes are treated as errors; exiting non-zero.")
		code = 1
	}
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
