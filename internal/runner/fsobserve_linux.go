//go:build linux

package runner

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/whiskeyjimbo/bento/internal/fsshimbin"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// fsObserver records host paths the sandboxed script opens. Two backends:
// strace (preferred; wraps the bwrap process) and the LD_PRELOAD fsshim
// (used when strace is missing). nil means observation is disabled.
type fsObserver struct {
	mode string // "strace" or "shim"

	scriptAbs string
	interp    string

	// strace mode
	tracePath string

	// shim mode
	soHost         string // host-side path to the .so
	soSandbox      string // sandbox-side path to the .so
	fifoHost       string
	fifoSandbox    string
	fifoReader     *os.File // O_RDONLY, blocking once goroutine starts
	fifoWriterKeep *os.File // held open so reader doesn't EOF before sandbox exits
	pathsMu        sync.Mutex
	opens          map[string]bool // path -> OK (true if any open succeeded)
	readerDone     chan struct{}

	cleanups []func()
}

// newFSObserver chooses a backend based on host capabilities. Returns nil
// when observation is disabled or both backends are unavailable.
func newFSObserver(cfg *Config, scriptAbs, interp string) *fsObserver {
	if cfg.FSObserver == nil {
		return nil
	}
	if straceAvailable() {
		o, err := newStraceObserver(scriptAbs, interp)
		if err == nil {
			return o
		}
		if cfg.Logger != nil {
			cfg.Logger.Printf("[bento] strace setup failed (%v) — trying fsshim", err)
		}
	}
	o, err := newShimObserver(scriptAbs, interp)
	if err == nil {
		return o
	}
	if cfg.Logger != nil {
		cfg.Logger.Printf("[bento] filesystem profiling disabled: %v", err)
	}
	return nil
}

func newStraceObserver(scriptAbs, interp string) (*fsObserver, error) {
	f, err := os.CreateTemp("", "bento-fstrace-*.log")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	f.Close()
	return &fsObserver{
		mode:      "strace",
		scriptAbs: scriptAbs,
		interp:    interp,
		tracePath: path,
		cleanups:  []func(){func() { os.Remove(path) }},
	}, nil
}

func newShimObserver(scriptAbs, interp string) (*fsObserver, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, errors.New("fsshim only built for linux/amd64")
	}
	if len(fsshimbin.LinuxAMD64) == 0 {
		return nil, errors.New("fsshim binary not embedded (run `make fsshim`)")
	}

	o := &fsObserver{
		mode:       "shim",
		scriptAbs:  scriptAbs,
		interp:     interp,
		opens:      make(map[string]bool),
		readerDone: make(chan struct{}),
	}

	soDir, err := os.MkdirTemp("", "bento-fsshim-")
	if err != nil {
		return nil, err
	}
	o.cleanups = append(o.cleanups, func() { os.RemoveAll(soDir) })
	o.soHost = filepath.Join(soDir, "fsshim.so")
	if err := os.WriteFile(o.soHost, fsshimbin.LinuxAMD64, 0o755); err != nil {
		o.close()
		return nil, fmt.Errorf("write shim: %w", err)
	}
	o.soSandbox = spec.SandboxRoot + "/.bento-fsshim.so"

	fifoDir, err := os.MkdirTemp("", "bento-fsobs-")
	if err != nil {
		o.close()
		return nil, err
	}
	o.cleanups = append(o.cleanups, func() { os.RemoveAll(fifoDir) })
	o.fifoHost = filepath.Join(fifoDir, "fifo")
	if err := syscall.Mkfifo(o.fifoHost, 0o600); err != nil {
		o.close()
		return nil, fmt.Errorf("mkfifo: %w", err)
	}
	o.fifoSandbox = spec.SandboxRoot + "/.bento-fsobs.fifo"

	// Open reader O_NONBLOCK so we don't deadlock waiting for a writer.
	rd, err := os.OpenFile(o.fifoHost, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		o.close()
		return nil, fmt.Errorf("open fifo reader: %w", err)
	}
	o.fifoReader = rd
	o.cleanups = append(o.cleanups, func() { rd.Close() })

	// Pin a writer end so the reader's blocking-mode reads don't return EOF
	// until WE close it (post-Run). Without this, if the shim never opens
	// the fifo, the reader would block forever.
	wr, err := os.OpenFile(o.fifoHost, os.O_WRONLY, 0)
	if err != nil {
		o.close()
		return nil, fmt.Errorf("open fifo writer: %w", err)
	}
	o.fifoWriterKeep = wr
	// Switch reader to blocking now that we hold a writer end.
	if err := syscall.SetNonblock(int(rd.Fd()), false); err != nil {
		o.close()
		return nil, fmt.Errorf("set blocking: %w", err)
	}

	go o.shimReadLoop()
	return o, nil
}

func (o *fsObserver) shimReadLoop() {
	defer close(o.readerDone)
	sc := bufio.NewScanner(o.fifoReader)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		// Lines look like "O /path" (success) or "D /path" (denied/failed).
		if len(line) < 3 || line[1] != ' ' {
			continue
		}
		ok := line[0] == 'O'
		p := line[2:]
		o.pathsMu.Lock()
		// Promote to OK=true if any open of the same path succeeded.
		if prev, exists := o.opens[p]; !exists || (!prev && ok) {
			o.opens[p] = ok
		}
		o.pathsMu.Unlock()
	}
}

// injectArgs mutates the bwrap argv to bind the shim/fifo into the sandbox
// and chain LD_PRELOAD. The new flags are inserted BEFORE the entrypoint
// separator ("--") so they're parsed by bwrap, not the launcher.
func (o *fsObserver) injectArgs(args []string) []string {
	if o == nil || o.mode != "shim" {
		return args
	}
	extra := []string{
		"--ro-bind", o.soHost, o.soSandbox,
		"--bind", o.fifoHost, o.fifoSandbox,
		"--setenv", "BENTO_FSOBS_FIFO", o.fifoSandbox,
	}
	args = insertBeforeSeparator(args, extra)
	args = chainLDPreload(args, o.soSandbox)
	return args
}

// insertBeforeSeparator inserts `extra` immediately before the first "--"
// (bwrap's entrypoint separator). If "--" isn't found the items are appended.
func insertBeforeSeparator(args, extra []string) []string {
	for i, a := range args {
		if a == "--" {
			out := make([]string, 0, len(args)+len(extra))
			out = append(out, args[:i]...)
			out = append(out, extra...)
			out = append(out, args[i:]...)
			return out
		}
	}
	return append(args, extra...)
}

// chainLDPreload appends extra to an existing LD_PRELOAD --setenv if present,
// otherwise emits a fresh one BEFORE the entrypoint separator.
func chainLDPreload(args []string, extra string) []string {
	sep := indexOf(args, "--")
	scan := args
	if sep >= 0 {
		scan = args[:sep]
	}
	for i := 0; i+2 < len(scan); i++ {
		if scan[i] == "--setenv" && scan[i+1] == "LD_PRELOAD" {
			if !strings.Contains(scan[i+2], extra) {
				args[i+2] = args[i+2] + " " + extra
			}
			return args
		}
	}
	return insertBeforeSeparator(args, []string{"--setenv", "LD_PRELOAD", extra})
}

func indexOf(s []string, target string) int {
	for i, x := range s {
		if x == target {
			return i
		}
	}
	return -1
}

// wrapExec applies the strace wrapper (no-op for shim mode).
func (o *fsObserver) wrapExec(exe string, args []string) (string, []string) {
	if o == nil || o.mode != "strace" {
		return exe, args
	}
	return wrapWithStrace(exe, args, o.tracePath)
}

// collect returns every unique open attempt after the sandbox has exited.
// For shim mode this also drains the fifo by closing our writer end.
func (o *fsObserver) collect(cfg *Config) []FSOpen {
	if o == nil {
		return nil
	}
	switch o.mode {
	case "strace":
		var extra []string
		if pfx := interpreterPrefix(o.interp); pfx != "" {
			extra = append(extra, pfx)
		}
		opens, err := parseStraceOpens(o.tracePath, o.scriptAbs, extra)
		if err != nil && cfg.Logger != nil {
			cfg.Logger.Printf("[bento] parsing strace output failed: %v", err)
		}
		return opens

	case "shim":
		if o.fifoWriterKeep != nil {
			o.fifoWriterKeep.Close()
			o.fifoWriterKeep = nil
		}
		<-o.readerDone
		o.pathsMu.Lock()
		raw := make([]FSOpen, 0, len(o.opens))
		for p, ok := range o.opens {
			raw = append(raw, FSOpen{Path: p, OK: ok})
		}
		o.pathsMu.Unlock()
		if cfg.Verbose && cfg.Logger != nil {
			cfg.Logger.Printf("[fsshim] %d raw paths recorded", len(raw))
			for _, e := range raw {
				marker := "OK"
				if !e.OK {
					marker = "DENIED"
				}
				cfg.Logger.Printf("[fsshim]   %-6s %s", marker, e.Path)
			}
		}
		return filterShimOpens(raw, o.scriptAbs, o.interp)
	}
	return nil
}

func (o *fsObserver) close() {
	if o == nil {
		return
	}
	if o.fifoWriterKeep != nil {
		o.fifoWriterKeep.Close()
		o.fifoWriterKeep = nil
	}
	for i := len(o.cleanups) - 1; i >= 0; i-- {
		o.cleanups[i]()
	}
}

// filterShimOpens applies the same noise/system filters as the strace path
// (sandbox internals, /usr, /lib*, etc.) plus the interpreter prefix.
func filterShimOpens(opens []FSOpen, scriptAbs, interp string) []FSOpen {
	var extra []string
	if pfx := interpreterPrefix(interp); pfx != "" {
		extra = append(extra, pfx)
	}
	out := make([]FSOpen, 0, len(opens))
	for _, e := range opens {
		if !filepath_IsAbs(e.Path) {
			continue
		}
		if isNoisePath(e.Path, scriptAbs, extra) && !(e.Write && isUserWriteTarget(e.Path)) {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
