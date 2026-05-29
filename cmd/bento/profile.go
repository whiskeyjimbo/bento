package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"github.com/whiskeyjimbo/bento"
)

var (
	profileOut            string
	profileForce          bool
	profileInterpreter    string
	profilePinInterpreter bool
	profileVerbose        bool
	profileAllowExec      bool
	profileScaffold       bool
	profileEnv            = envFlag{}
	profilePreMountReads  stringSliceFlag
)

var profileCmd = &cobra.Command{
	Use:   "profile [flags] <script> [-- script-args...]",
	Short: "Record one trial run and emit <script>.manifest.yaml — start here",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: bento profile needs a script path")
			fmt.Fprintln(os.Stderr, "  bento profile <script> [args...]")
			fmt.Fprintln(os.Stderr, "  bento profile --help     # full flag list")
			os.Exit(2)
		}

		scriptPath := args[0]
		scriptArgs := args[1:]

		if len(scriptArgs) > 0 && scriptArgs[0] == "--" {
			scriptArgs = scriptArgs[1:]
		} else if msg := misplacedBentoFlag(scriptArgs); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
			fmt.Fprintf(os.Stderr, "  bento profile [flags] %s [-- script-args...]\n", scriptPath)
			fmt.Fprintln(os.Stderr, "  (if the token really is meant for the script, prefix it with `--` to disambiguate)")
			os.Exit(2)
		} else if note := noteForwardedFlags(scriptArgs); note != "" {
			fmt.Fprintln(os.Stderr, note)
		}

		warnEmptyEnv(os.Stderr, profileEnv)

		interp := profileInterpreter
		if interp == "" {
			var err error
			interp, err = bento.ResolveInterpreter(scriptPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
		}

		m, err := bento.PracticalStrictManifest(scriptPath, interp)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if profileAllowExec {
			m.AllowExec = true
		}
		if len(scriptArgs) > 0 {
			m.Args = append(m.Args, scriptArgs...)
		}

		for _, p := range profilePreMountReads {
			abs, err := filepath.Abs(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: --read %q: %v\n", p, err)
				os.Exit(2)
			}
			m.Read = appendUniqueStr(m.Read, abs)
		}

		outPath := profileOut
		if outPath == "" {
			outPath = strings.TrimSuffix(scriptPath, filepath.Ext(scriptPath)) + ".manifest.yaml"
		}
		outPath = filepath.Clean(outPath)

		if !profileForce {
			if _, err := os.Stat(outPath); err == nil {
				fmt.Fprintf(os.Stderr, "[bento] %s already exists. Options:\n", outPath)
				fmt.Fprintln(os.Stderr, "[bento]   --force                          overwrite (discards any hand-edits to read:/write:/env:)")
				sideBySide := sideBySidePath(outPath)
				fmt.Fprintf(os.Stderr, "[bento]   --out=%-25s write the new manifest alongside so you can diff first:\n", sideBySide)
				fmt.Fprintf(os.Stderr, "[bento]                                      diff %s %s\n", outPath, sideBySide)
				if profileAllowExec && priorManifestLacksAllowExec(outPath) {
					fmt.Fprintln(os.Stderr, "[bento]   the existing manifest doesn't set `allow_exec: true`; --allow-exec implies")
					fmt.Fprintln(os.Stderr, "[bento]   you want to overwrite that — add --force to do so.")
				}
				os.Exit(1)
			}
		}

		if profileScaffold {
			os.Exit(writeScaffoldManifest(outPath, scriptPath, interp, m))
		}

		netModeLabel := "permissive network"
		if isProfileTargetELF(scriptPath, interp) {
			netModeLabel = "permissive network: hostnames only intercepted for libc-routed traffic — ELF binaries get IP-level kernel trace instead"
		}
		fmt.Fprintf(os.Stderr, "[bento] profiling %q (%s)...\n", scriptPath, netModeLabel)

		tail := newTailBuffer(16 << 10)
		scriptTail := newTailBuffer(8 << 10)
		runOpts := []bento.Option{
			bento.WithLogger(log.New(io.MultiWriter(os.Stderr, tail), "", 0)),
			bento.WithVerbose(profileVerbose),
			bento.WithStdout(io.MultiWriter(os.Stdout, scriptTail, tail)),
			bento.WithStderr(io.MultiWriter(os.Stderr, scriptTail, tail)),
		}
		if len(profileEnv) > 0 {
			runOpts = append(runOpts, bento.WithExtraEnv(profileEnv))
		}
		result, err := bento.Profile(context.Background(), m, runOpts...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[bento] script exit code: %d\n\n", result.ExitCode)
		printObservations(os.Stderr, result.Observations)
		printFSObservations(os.Stderr, result.FSObservations)
		printFSWrites(os.Stderr, result.FSWrites, len(result.TmpfsWrites) > 0)
		printTmpfsWrites(os.Stderr, result.TmpfsWrites, filepath.Dir(absScriptPath(scriptPath)), pickEnvForLostWrite(result.TmpfsWrites, scriptEnvDefaults(scriptPath, interp), referencedEnvVarsInScript(scriptPath, interp)))
		printDeniedAttempts(os.Stderr, result.DeniedAttempts)
		printBlockedReads(os.Stderr, result.BlockedReads)
		printBlockedConnects(os.Stderr, result.BlockedConnects, isProfileTargetELF(scriptPath, interp), result.SuggestedManifest)
		noteSandboxPathIfReferenced(os.Stderr, tail.String())
		noteHostTmpBindIfRelevant(os.Stderr, result.FSWrites, result.FSObservations)

		execBlock := matchesExecBlock(tail.String())
		if execBlock && !profileAllowExec && result.ExitCode == 0 && !profileForce {
			fmt.Fprintln(os.Stderr, "[bento] ──────────────── warning ────────────────")
			fmt.Fprintln(os.Stderr, "[bento] script forked subprocesses that bento blocked, but it still exited 0.")
			fmt.Fprintln(os.Stderr, "[bento]   this usually means the script's output is incomplete (e.g. `{ … } > out`")
			fmt.Fprintln(os.Stderr, "[bento]   swallows subprocess failures, leaving empty fields in the captured file).")
			if bins := extractDeniedBinaries(tail.String()); len(bins) > 0 {
				fmt.Fprintf(os.Stderr, "[bento]   blocked: %s\n", strings.Join(bins, ", "))
			}
			fmt.Fprintln(os.Stderr, "[bento]   re-run with --allow-exec so subprocesses can execute and the manifest")
			fmt.Fprintln(os.Stderr, "[bento]   captures `allow_exec: true`:")
			fmt.Fprintf(os.Stderr, "[bento]     %s\n", reprofileCmd(scriptPath, scriptArgs, profileEnv, profilePreMountReads, profileAllowExec, []string{"--allow-exec"}))
			fmt.Fprintln(os.Stderr, "[bento]   (or pass --force to emit the manifest anyway; you'll likely need to hand-edit it.)")
			fmt.Fprintln(os.Stderr, "[bento] ─────────────────────────────────────────")
			os.Exit(1)
		}

		if result.ExitCode != 0 {
			if !execBlock {
				emitScriptOutputDiagnostic(os.Stderr, scriptTail.String(), scriptPath, interp)
			}
			sandboxBlocked := execBlock || matchesFSBlock(tail.String()) || matchesWriteBlock(tail.String())
			hasObservations := len(result.Observations) > 0 || len(result.FSWrites) > 0
			applicationFailure := !sandboxBlocked && hasObservations
			if !profileForce && !applicationFailure {
				if execBlock {
					fmt.Fprintln(os.Stderr, "[bento] the script tried to spawn a subprocess, which `bento profile` blocks by default")
					fmt.Fprintln(os.Stderr, "[bento]   (profile relaxes network, not exec). Re-run with --allow-exec to let")
					fmt.Fprintln(os.Stderr, "[bento]   subprocesses run during profiling; the generated manifest will have")
					fmt.Fprintln(os.Stderr, "[bento]   `allow_exec: true` set:")
					fmt.Fprintf(os.Stderr, "[bento]     %s\n", reprofileCmd(scriptPath, scriptArgs, profileEnv, profilePreMountReads, profileAllowExec, []string{"--allow-exec"}))
				} else {
					fmt.Fprintf(os.Stderr, "[bento] trial run exited %d — skipping manifest write.\n", result.ExitCode)
					if len(result.Observations) == 0 && len(result.FSWrites) == 0 {
						scriptDir := filepath.Dir(absScriptPath(scriptPath))
						if hit := detectRelativePathHostMiss(scriptTail.String(), scriptDir); hit != "" {
							fmt.Fprintf(os.Stderr, "[bento]   the script's output mentions `%s`, and that file exists on the host\n", hit)
							fmt.Fprintf(os.Stderr, "[bento]   at %s — but inside the sandbox `./` resolves to `/sandbox/` (a tmpfs),\n", filepath.Join(scriptDir, strings.TrimPrefix(hit, "./")))
							fmt.Fprintln(os.Stderr, "[bento]   not your host pwd. Fix one of:")
							absHit := filepath.Join(scriptDir, strings.TrimPrefix(hit, "./"))
							envName := inferEnvVarForRelativePath(absScriptPath(scriptPath), hit)
							if envName == "" {
								envName = "NAME"
							}
							fmt.Fprintln(os.Stderr, "[bento]     - re-profile with an absolute host path via --env, e.g.:")
							extraEnv := []string{"--env", shellQuote(envName + "=" + absHit)}
							siblings := siblingRelativePathEnvs(scriptPath, interp, envName)
							if len(siblings) > 0 {
								for _, s := range siblings {
									abs := filepath.Join(scriptDir, strings.TrimPrefix(s.def, "./"))
									extraEnv = append(extraEnv, "--env", shellQuote(s.name+"="+abs))
								}
							}
							fmt.Fprintf(os.Stderr, "[bento]         %s\n", reprofileCmd(scriptPath, scriptArgs, profileEnv, profilePreMountReads, profileAllowExec, extraEnv))
							if len(siblings) > 0 {
								names := []string{}
								for _, s := range siblings {
									names = append(names, "$"+s.name+" (default "+s.def+")")
								}
								fmt.Fprintf(os.Stderr, "[bento]       (script source also reads %s — passing both up front avoids a second profile pass.)\n", strings.Join(names, ", "))
							}
							fmt.Fprintln(os.Stderr, "[bento]     - `cd \"$BENTO_SCRIPT_DIR\"` at the top of the script (and add the script")
							fmt.Fprintln(os.Stderr, "[bento]       directory to `read:` if needed).")
						} else {
							fmt.Fprintln(os.Stderr, "[bento]   no network/write activity was recorded — the script likely failed before doing")
							fmt.Fprintln(os.Stderr, "[bento]   anything useful. If the failure is unrelated to sandboxing (a Python ImportError,")
							fmt.Fprintln(os.Stderr, "[bento]   a missing dependency, a syntax error), fix it outside bento first, then re-profile.")
						}
					} else {
						noteProfileVsRunTmpDivergence(os.Stderr, scriptPath, result.FSWrites)
					}
					noteShellCwdAssumption(os.Stderr, scriptPath, interp)
					fmt.Fprintln(os.Stderr, "[bento]   --force writes a partial manifest annotated with the failure (you'll likely")
					fmt.Fprintln(os.Stderr, "[bento]   need to hand-edit it).")
				}
				os.Exit(result.ExitCode)
			}
			if applicationFailure && !profileForce {
				fmt.Fprintln(os.Stderr, "[bento] ──────────────── note ────────────────")
				fmt.Fprintf(os.Stderr, "[bento] trial run exited %d, but the sandbox was not the blocker — captured\n", result.ExitCode)
				fmt.Fprintln(os.Stderr, "[bento]   network/filesystem observations are real. Writing the manifest anyway;")
				fmt.Fprintln(os.Stderr, "[bento]   the script's own error (HTTP 5xx, parse failure, upstream timeout, etc.)")
				fmt.Fprintln(os.Stderr, "[bento]   is independent and likely transient — fix it and `bento run` will work.")
				fmt.Fprintln(os.Stderr, "[bento] ──────────────────────────────────────")
			}
		}

		rewriteManifestForOutput(result.SuggestedManifest, outPath)

		if profilePinInterpreter && result.SuggestedManifest != nil && result.SuggestedManifest.Interpreter != "" {
			if resolved, err := exec.LookPath(result.SuggestedManifest.Interpreter); err == nil {
				result.SuggestedManifest.Interpreter = resolved
			}
		}

		if result.SuggestedManifest != nil && len(profileEnv) > 0 {
			for name := range profileEnv {
				result.SuggestedManifest.Env = appendUniqueStr(result.SuggestedManifest.Env, name)
			}
		}
		if result.SuggestedManifest != nil && len(profilePreMountReads) > 0 {
			for _, p := range profilePreMountReads {
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
			if hasDotRead(result.SuggestedManifest) {
				header.WriteString("# (`read: - .` below is the script directory — bento mounts it so the binary\n")
				header.WriteString("# is reachable for execve. Keep it as-is unless you've moved the binary.)\n")
			}
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
			var loadBearing string
			if len(result.TmpfsWrites) > 0 {
				loadBearing = pickEnvForLostWrite(result.TmpfsWrites, scriptEnvDefaults(scriptPath, interp), referenced)
			}
			var others []string
			if loadBearing != "" {
				for _, name := range stub {
					if name != loadBearing {
						others = append(others, name)
					}
				}
			} else {
				others = stub
			}
			activeEnvPresent := result.SuggestedManifest != nil && len(result.SuggestedManifest.Env) > 0
			if activeEnvPresent {
				header.WriteString("#\n# To inherit additional host env vars at run time — ADD names to the\n")
				header.WriteString("# `env:` block further down (bento strips host env by default). Or pass\n")
				header.WriteString("# `--env NAME=VALUE` ad-hoc. Do NOT create a second `env:` block at the\n")
				header.WriteString("# top of the file — YAML rejects duplicate top-level keys.\n")
				if loadBearing != "" {
					fmt.Fprintf(&header, "# Required for the Quick-apply fix below: add `- %s` to the existing `env:` block.\n", loadBearing)
				}
				if len(others) > 0 {
					header.WriteString("# Other candidates, optional — the script reads these but they didn't break this run\n")
					header.WriteString("# (add to the existing `env:` block to inherit, or pass `--env NAME=VALUE` ad-hoc):\n")
					for _, name := range others {
						fmt.Fprintf(&header, "#   - %s\n", name)
					}
				}
			} else {
				header.WriteString("#\n# To inherit these host env vars at run time — uncomment names under `env:`\n")
				header.WriteString("# below (bento strips host env by default). Or pass `--env NAME=VALUE` ad-hoc.\n")
				header.WriteString("# env:\n")
				if loadBearing != "" {
					fmt.Fprintf(&header, "#   - %s   # required for the Quick-apply fix below\n", loadBearing)
				} else {
					for _, name := range stub {
						fmt.Fprintf(&header, "#   - %s\n", name)
					}
				}
				if loadBearing != "" && len(others) > 0 {
					header.WriteString("# env (other candidates, optional — the script reads these but they didn't break this run):\n")
					for _, name := range others {
						fmt.Fprintf(&header, "#   - %s\n", name)
					}
				}
			}
		}
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
		if result.SuggestedManifest != nil {
			var inputValues []string
			for _, v := range profileEnv {
				if len(v) >= 2 {
					inputValues = append(inputValues, v)
				}
			}
			for _, name := range referenced {
				if v, ok := os.LookupEnv(name); ok && len(v) >= 2 {
					inputValues = append(inputValues, v)
				}
			}
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
		if len(profileEnv) > 0 {
			header.WriteString("#\n# Profile-time --env values (script used these defaults — pass them again at run\n")
			header.WriteString("# time with `--env NAME=VALUE`; the manifest's `env:` allowlist only forwards a\n")
			header.WriteString("# variable from your shell, it does not preserve the value):\n")
			names := make([]string, 0, len(profileEnv))
			for k := range profileEnv {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				v := profileEnv[k]
				if envValueLooksLikePath(v) {
					fmt.Fprintf(&header, "#   --env %s=<absolute-host-path>   (recorded at profile time: %s)\n", k, v)
				} else {
					fmt.Fprintf(&header, "#   --env %s=%s\n", k, v)
				}
			}
		}
		if len(result.TmpfsWrites) > 0 {
			scriptDir := filepath.Dir(absScriptPath(scriptPath))
			header.WriteString("#\n# ⚠ WARNING: the trial run wrote to relative paths that landed on the sandbox\n")
			header.WriteString("# tmpfs and were lost. `bento run <this manifest>` will exit non-zero with the\n")
			header.WriteString("# same diagnostic unless you apply one of the fixes below.\n")
			envDefaults := scriptEnvDefaults(scriptPath, interp)
			header.WriteString("# Lost writes:\n")
			for _, p := range result.TmpfsWrites {
				if v := envVarForLostPath(p, envDefaults); v != "" {
					fmt.Fprintf(&header, "#   - %s   ← controlled by $%s (pass `--env %s=/abs/host/path`)\n", p, v, v)
				} else {
					fmt.Fprintf(&header, "#   - %s\n", p)
				}
			}
			genericEnv := pickEnvForLostWrite(result.TmpfsWrites, envDefaults, referenced)
			header.WriteString("# Fix one of:\n")
			header.WriteString("#   (a) point the script at an absolute host path via --env, e.g.\n")
			fmt.Fprintf(&header, "#       bento run --env %s=%s/<file> <this manifest>\n", genericEnv, scriptDir)
			fmt.Fprintf(&header, "#       and add `%s` to `write:` below.\n", scriptDir)
			header.WriteString("#   (b) add `cd \"$BENTO_SCRIPT_DIR\"` at the top of the script so relative paths\n")
			fmt.Fprintf(&header, "#       land in the (writable) script directory, then add `%s` to `write:`.\n", scriptDir)
			header.WriteString("# Adding the host directory to `write:` ALONE will not help — the script must\n")
			header.WriteString("# also be pointed at the host path; otherwise it keeps writing to /sandbox.\n")
			envName := pickEnvForLostWrite(result.TmpfsWrites, envDefaults, referenced)
			header.WriteString("#\n# ── Quick-apply fix (a) ─ uncomment the `write:` block below")
			activeEnvPresent := result.SuggestedManifest != nil && len(result.SuggestedManifest.Env) > 0
			switch {
			case already[envName]:
				fmt.Fprintf(&header, ".\n#    `%s` is already in `env:` below. Then run with:\n", envName)
			case activeEnvPresent:
				fmt.Fprintf(&header, " AND add\n#    `- %s` to the existing `env:` block below (do NOT add a second `env:`\n#    block — YAML rejects duplicate top-level keys). Then run with:\n", envName)
			default:
				fmt.Fprintf(&header, " AND uncomment\n#    BOTH the `env:` line AND the `  - %s` line in the commented `env:`\n#    block above (uncommenting only the list item produces an invalid\n#    top-level list). Then run with:\n", envName)
			}
			fmt.Fprintf(&header, "#       bento run --env %s=%s/<file> <this manifest>\n", envName, scriptDir)
			fmt.Fprintf(&header, "# write:\n#   - %s\n", scriptDir)
		}
		header.WriteString("\n")

		yamlBytes, err := yaml.Marshal(result.SuggestedManifest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error marshaling suggested manifest:", err)
			os.Exit(1)
		}
		if result.SuggestedManifest != nil && len(result.SuggestedManifest.Args) > 0 {
			yamlBytes = annotateArgsBlock(yamlBytes)
		}
		if result.SuggestedManifest != nil && manifestHasRelativeReadWrite(result.SuggestedManifest) {
			yamlBytes = annotateRelativePaths(yamlBytes)
		}
		if result.SuggestedManifest != nil {
			hasBroadRead := manifestHasBroadDot(result.SuggestedManifest.Read)
			hasBroadWrite := manifestHasBroadDot(result.SuggestedManifest.Write)
			if len(result.FSObservations) > 0 || len(result.FSWrites) > 0 || hasBroadRead || hasBroadWrite {
				yamlBytes = annotateObservedPaths(yamlBytes, result.FSObservations, result.FSWrites, hasBroadRead, hasBroadWrite, result.SuggestedManifest.AllowExec)
			}
		}

		if err := os.WriteFile(outPath, append([]byte(header.String()), yamlBytes...), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error writing manifest:", err)
			os.Exit(1)
		}

		if result.ExitCode != 0 {
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
			var phrase string
			if n == 1 {
				phrase = "the network rule"
			} else {
				phrase = fmt.Sprintf("the %d network rules", n)
			}
			fmt.Fprintf(os.Stderr, "[bento] tip: review %s before committing — profile records what\n", phrase)
			fmt.Fprintln(os.Stderr, "[bento]   this one run touched; production paths may differ.")
		}
		os.Exit(result.ExitCode)
	},
}

func init() {
	profileCmd.Flags().StringVar(&profileOut, "out", "", "manifest output path (default: <script>.manifest.yaml)")
	profileCmd.Flags().BoolVar(&profileForce, "force", false, "overwrite the output file if it already exists")
	profileCmd.Flags().StringVar(&profileInterpreter, "interpreter", "", "override auto-detected interpreter")
	profileCmd.Flags().BoolVar(&profilePinInterpreter, "pin-interpreter", false, "write the resolved absolute interpreter path into the manifest")
	profileCmd.Flags().BoolVarP(&profileVerbose, "verbose", "v", false, "show sandbox argv and other diagnostic logging")
	profileCmd.Flags().BoolVar(&profileAllowExec, "allow-exec", false, "permit subprocess execve during profiling")
	profileCmd.Flags().BoolVar(&profileScaffold, "scaffold", false, "emit a commented manifest skeleton WITHOUT running the script")
	profileCmd.Flags().Var(profileEnv, "env", "extra env var KEY=VALUE for the script during profiling; the name is also added to the generated manifest's 'env:' allowlist (repeatable)")
	profileCmd.Flags().Var(&profilePreMountReads, "read", "extra read path to bind-mount during profiling (repeatable)")

	// Allow arbitrary command line arguments to bypass Cobra's strict flag validation after the script name is passed
	profileCmd.Flags().SetInterspersed(false)
}

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

func sideBySidePath(outPath string) string {
	dir, base := filepath.Split(outPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, stem+".next"+ext)
}

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

func annotateObservedPaths(yamlBytes []byte, observedReads, observedWrites []string, broadRead, broadWrite, allowExec bool) []byte {
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
		if what == "read" && allowExec {
			b.WriteString("\n# (allow_exec subprocesses are not traced for read paths; fs activity inside\n")
			b.WriteString("# spawned binaries is invisible to the profiler.)")
		}
		out := make([]string, 0, len(lines)+5)
		out = append(out, lines[:idx]...)
		out = append(out, b.String())
		out = append(out, lines[idx:]...)
		return out
	}
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

func manifestHasBroadDot(paths []string) bool {
	for _, p := range paths {
		if p == "." {
			return true
		}
	}
	return false
}

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

func envValueLooksLikePath(v string) bool {
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") {
		return true
	}
	if strings.Contains(v, "/") {
		return true
	}
	return false
}

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
		host := filepath.Join(scriptDir, filepath.Dir(rel))
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out
}

func absScriptPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

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

func printTmpfsWrites(w io.Writer, paths []string, scriptDir, envName string) {
	if len(paths) == 0 {
		return
	}
	if envName == "" {
		envName = "OUT"
	}
	fmt.Fprintln(w, "[bento] writes that landed on sandbox tmpfs (NOT persisted, no host destination):")
	for _, p := range paths {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintln(w, "[bento]   these were written to relative paths, which resolve against the sandbox cwd")
	fmt.Fprintln(w, "[bento]   `/sandbox` (a tmpfs) — NOT your shell's pwd. Adding the host directory to")
	fmt.Fprintln(w, "[bento]   `write:` will not help: the script never tries to reach the host path.")
	fmt.Fprintln(w, "[bento]   Two fixes (pick one):")
	if hosts := proposeHostWrites(paths, scriptDir); len(hosts) > 0 {
		fmt.Fprintln(w, "[bento]     (a) point the script at an absolute host path via env, e.g.:")
		fmt.Fprintf(w, "[bento]           bento run --env %s=%s/<file> ...\n", envName, hosts[0])
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

func emitScriptOutputDiagnostic(w io.Writer, scriptOutput, scriptPath, interp string) {
	lines := strings.Split(scriptOutput, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	const max = 15
	if len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	fmt.Fprintln(w, "[bento] script output tail (last 15 lines):")
	for _, l := range lines {
		fmt.Fprintf(w, "  %s\n", l)
	}
	fmt.Fprintln(w)
}

func hasDotRead(m *bento.Manifest) bool {
	for _, p := range m.Read {
		if p == "." {
			return true
		}
	}
	return false
}

