package spec

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// extensionInterpreters is the mapping from file extension to default
// interpreter name. Kept small + obvious — users with unusual setups
// override via the --interpreter CLI flag. Resolution happens at
// runtime via exec.LookPath so distro-specific paths work.
var extensionInterpreters = map[string]string{
	".py": "python3",
	".js": "node",
	".sh": "bash",
	".rb": "ruby",
	".pl": "perl",
}

// ResolveInterpreter picks an interpreter for the given script path.
// Tries (1) the extension table; (2) the script's shebang line if
// it has no extension or the extension isn't mapped. Returns an
// error with remediation hints when neither path succeeds.
func ResolveInterpreter(scriptPath string) (string, error) {
	ext := strings.ToLower(filepath.Ext(scriptPath))
	if interp, ok := extensionInterpreters[ext]; ok {
		return interp, nil
	}
	if shebang, ok := readShebang(scriptPath); ok {
		return shebang, nil
	}
	if ext != "" {
		return "", fmt.Errorf("no interpreter mapped for %q files; use --interpreter or add a shebang line", ext)
	}
	return "", fmt.Errorf("cannot determine interpreter for %q (no extension, no shebang); use --interpreter", scriptPath)
}

// readShebang returns the first token of the script's #! line if
// present, or ("", false) if the file is missing / has no shebang.
// Only the first 128 bytes are read.
func readShebang(scriptPath string) (string, bool) {
	f, err := os.Open(scriptPath)
	if err != nil {
		return "", false
	}
	defer f.Close()
	r := bufio.NewReader(f)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "#!") {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "#!"))
	if rest == "" {
		return "", false
	}
	// "#!/usr/bin/env python3" → use "python3" so $PATH resolution
	// works; "#!/usr/bin/python3" → use "/usr/bin/python3" verbatim.
	fields := strings.Fields(rest)
	if fields[0] == "/usr/bin/env" && len(fields) > 1 {
		return fields[1], true
	}
	return fields[0], true
}

// PracticalStrictManifest builds the zero-config default manifest for
// a script: the script can read its own directory (most scripts open
// sibling files); cannot write anywhere; has no network; cannot exec
// subprocesses. System reads (/usr, /lib, /etc/ssl, etc.) are
// auto-mounted by the runner regardless of manifest.
//
// The interpreter argument is required; pass [ResolveInterpreter]'s
// output. The script path is converted to absolute.
//
// Library callers wanting the same defaults as the CLI's
// `bento run script.py` use this.
func PracticalStrictManifest(scriptPath, interpreter string) (*Manifest, error) {
	if interpreter == "" {
		return nil, fmt.Errorf("PracticalStrictManifest: interpreter is required")
	}
	abs, err := filepath.Abs(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("PracticalStrictManifest: %w", err)
	}
	return &Manifest{
		Interpreter: interpreter,
		Script:      abs,
		Read:        []string{filepath.Dir(abs)},
		// Write, Network, Exec all zero-value → block by default.
	}, nil
}
