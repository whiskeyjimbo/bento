package spec

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	extensionInterpretersMu sync.RWMutex
	extensionInterpreters   = map[string]string{
		".py": "python3",
		".js": "node",
		".sh": "bash",
		".rb": "ruby",
		".pl": "perl",
	}
)

// RegisterExtensionInterpreter maps a file extension (e.g. ".ts") to a default
// interpreter name (e.g. "bun") globally. Thread-safe.
func RegisterExtensionInterpreter(ext, interpreter string) {
	extensionInterpretersMu.Lock()
	defer extensionInterpretersMu.Unlock()
	extensionInterpreters[ext] = interpreter
}

// ResolveOption configures an interpreter resolution.
type ResolveOption func(*resolveConfig)

type resolveConfig struct {
	customExtensions map[string]string
	disableShebang   bool
}

// WithCustomExtensions provides temporary/one-off extension-to-interpreter
// mappings for a single ResolveInterpreter call.
func WithCustomExtensions(mappings map[string]string) ResolveOption {
	return func(c *resolveConfig) { c.customExtensions = mappings }
}

// WithDisableShebang skips checking shebang (#!) lines during resolution.
func WithDisableShebang() ResolveOption {
	return func(c *resolveConfig) { c.disableShebang = true }
}

// InterpreterSource records *how* ResolveInterpreterDetailed picked the
// interpreter. The CLI uses this to warn when the inference was extension-only
// (so the user knows bento guessed and how to override).
type InterpreterSource string

const (
	InterpreterFromExtension InterpreterSource = "extension"
	InterpreterFromShebang   InterpreterSource = "shebang"
	InterpreterFromELF       InterpreterSource = "elf"
	InterpreterFromCustom    InterpreterSource = "custom"
)

// ResolveInterpreter picks an interpreter via (1) custom mappings, (2) the global
// extension table, (3) the script's shebang line.
func ResolveInterpreter(scriptPath string, opts ...ResolveOption) (string, error) {
	interp, _, err := ResolveInterpreterDetailed(scriptPath, opts...)
	return interp, err
}

// ResolveInterpreterDetailed is ResolveInterpreter plus the source of the
// pick (extension table, shebang, ELF, custom mapping). Callers that want to
// warn on extension-only inference use this variant.
func ResolveInterpreterDetailed(scriptPath string, opts ...ResolveOption) (string, InterpreterSource, error) {
	cfg := &resolveConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	ext := strings.ToLower(filepath.Ext(scriptPath))

	if cfg.customExtensions != nil {
		if interp, ok := cfg.customExtensions[ext]; ok {
			return interp, InterpreterFromCustom, nil
		}
	}

	extensionInterpretersMu.RLock()
	interp, ok := extensionInterpreters[ext]
	extensionInterpretersMu.RUnlock()
	if ok {
		return interp, InterpreterFromExtension, nil
	}

	if !cfg.disableShebang {
		if shebang, ok := readShebang(scriptPath); ok {
			return shebang, InterpreterFromShebang, nil
		}
	}
	if isExecutableELF(scriptPath) {
		abs, err := filepath.Abs(scriptPath)
		if err == nil {
			return abs, InterpreterFromELF, nil
		}
		return scriptPath, InterpreterFromELF, nil
	}
	if ext != "" {
		return "", "", fmt.Errorf("no interpreter mapped for %q files; use --interpreter or add a shebang line", ext)
	}
	return "", "", fmt.Errorf("cannot determine interpreter for %q (no extension, no shebang); pass `bento run --interpreter=BIN %s` (or `bento profile --interpreter=BIN ...`), or if this is a compiled binary, make sure it has the executable bit set", scriptPath, scriptPath)
}

// isExecutableELF reports whether the file at path is an ELF binary with the
// owner-execute bit set. Used by zero-config to recognize compiled programs
// (Go, Rust, C) that don't need a separate interpreter — they ARE the
// interpreter.
func isExecutableELF(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if info.Mode().Perm()&0o111 == 0 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
}

// readShebang returns the first token of the script's #! line, or ("", false).
// "#!/usr/bin/env X" returns "X" so $PATH resolution works.
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
	fields := strings.Fields(rest)
	if fields[0] == "/usr/bin/env" && len(fields) > 1 {
		return fields[1], true
	}
	return fields[0], true
}

// PracticalStrictManifest builds the zero-config default manifest: read access
// to the script's directory, no write/network/exec. System reads are auto-mounted.
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
	}, nil
}
