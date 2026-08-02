package profile

import (
	"os"
	"path/filepath"
	"strings"
)

// GuessInterpreter picks an interpreter for a script, along with the arguments the
// shebang passes it and where the guess came from - source is a phrase a frontend can
// print to say which rule answered. An empty interpreter means the script is its own
// interpreter (a compiled binary).
//
// The shebang wins over the extension because it is the script's own answer: a `.sh`
// file that asks for /bin/sh can behave differently under bash, and the manifest the
// user approves would record the interpreter bento chose over the one the author
// wrote. The extension is the fallback for a script with no shebang, which the kernel
// would refuse to exec on its own.
//
// This sits beside Synthesize, which takes the (entrypoint, interpreter) pair the guess
// produces. It is exported because a supervisor built on bento has to answer this the
// same way the CLI does: one that guesses differently writes a manifest whose `bento
// run` is not the run the human approved.
func GuessInterpreter(path string) (interpreter string, args []string, source string) {
	if interp, args := shebang(path); interp != "" {
		return interp, args, "the script's shebang"
	}
	ext := filepath.Ext(path)
	switch ext {
	case ".py":
		interpreter = "python3"
	case ".sh", ".bash":
		interpreter = "bash"
	case ".js":
		interpreter = "node"
	case ".rb":
		interpreter = "ruby"
	default:
		return "", nil, ""
	}
	return interpreter, nil, "the " + ext + " extension"
}

// shebang reads the interpreter a script names on its first line, along with the
// arguments the line passes it. It returns "" when the line names no interpreter -
// including an unreadable file, which every caller reports on for its own reasons.
//
// The two branches split the arguments differently because the two runners do. Linux
// does not tokenize a shebang: everything after the interpreter arrives as a single
// argv[1], so "#!/bin/sh -e -u" passes one argument "-e -u" - which is why a shebang
// wanting several must go through `env -S`, and why the direct branch returns the
// remainder whole. env -S does split, so that branch returns separate words.
//
// The env branch splits even where no -S is present, which is a case no runner really
// serves: a kernel exec of "#!/usr/bin/env python3 -u" hands env the single argument
// "python3 -u" and env finds no program by that name. bento execs the interpreter
// itself, so a guess at what the author meant is more use than refusing to read it.
func shebang(path string) (interpreter string, args []string) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil
	}
	defer f.Close()

	var buf [256]byte
	n, _ := f.Read(buf[:])
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	if !strings.HasPrefix(line, "#!") {
		return "", nil
	}
	rest := strings.TrimLeft(strings.TrimPrefix(line, "#!"), " \t")
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", nil
	}
	// "#!/usr/bin/env python3" runs the interpreter named after env. env may be
	// given options first - notably `-S`/`--split-string`, the standard way a
	// shebang passes multiple args to the interpreter (`env -S python3 -u`) - and
	// NAME=VALUE assignments; the interpreter is the first field that is neither, not
	// simply fields[1] (which would be `-S`).
	if filepath.Base(fields[0]) == "env" {
		for i := 1; i < len(fields); i++ {
			w := fields[i]
			// -S/--split-string may carry its payload attached as well as in the next
			// word. Unwrapping it rather than skipping the word puts the payload's first
			// token - where the interpreter or a leading assignment sits - through the
			// same tests as any other field, so `-Spython3` reads as python3 instead of
			// falling through to the extension guess.
			if p, ok := strings.CutPrefix(w, "--split-string="); ok {
				w = p
			} else if p, ok := strings.CutPrefix(w, "-S"); ok && p != "" {
				w = p
			}
			// Skip env's leading options and NAME=VALUE assignments; an interpreter
			// (a path or a bare name) contains neither, so any '='-bearing word is an
			// assignment, matching env's own handling. An empty payload (`-S` with
			// nothing after the `=`) names nothing and must not read as an interpreter.
			if w == "" || strings.Contains(w, "=") {
				continue
			}
			if strings.HasPrefix(w, "-") {
				// These take their argument as a separate word, so without consuming it
				// the variable name or directory reads as the interpreter. The
				// attached forms (-uNAME, --unset=NAME) are already covered above or by
				// the prefix test. A bare -S is not here: what follows it is the string
				// env splits, which begins with the interpreter.
				switch w {
				case "-u", "--unset", "-C", "--chdir":
					i++
				}
				continue
			}
			return w, fields[i+1:]
		}
		return "", nil
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, fields[0]))
	if rest == "" {
		return fields[0], nil
	}
	return fields[0], []string{rest}
}
