//go:build !(linux && amd64)

package observe

import (
	"fmt"
	"io"
)

// Access is one file the program opened.
type Access struct {
	Path   string
	Write  bool
	Absent bool
}

// Result is what a traced run observed.
type Result struct {
	Accesses      []Access
	Execed        bool
	ExitCode      int
	Signaled      bool
	Signal        int
	Dropped       int
	SeccompKilled bool
}

// Supported reports whether this build has the ptrace observation backend. The
// decoder is written for amd64 syscall numbers and register layout, so this build
// has none and callers must refuse to profile rather than launch a run they cannot
// observe.
func Supported() bool { return false }

// Trace is unavailable: the ptrace observer is implemented for linux/amd64 only.
func Trace(argv, env []string, stdin io.Reader, stdout, stderr io.Writer) (Result, error) {
	return Result{}, fmt.Errorf("observe: profiling is only supported on linux/amd64")
}
