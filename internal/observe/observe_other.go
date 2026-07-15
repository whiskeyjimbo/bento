//go:build !(linux && amd64)

package observe

import (
	"fmt"
	"io"
)

// Access is one file the program opened.
type Access struct {
	Path  string
	Write bool
}

// Result is what a traced run observed.
type Result struct {
	Accesses []Access
	Execed   bool
	ExitCode int
}

// Trace is unavailable: the ptrace observer is implemented for linux/amd64 only.
func Trace(argv, env []string, stdin io.Reader, stdout, stderr io.Writer) (Result, error) {
	return Result{}, fmt.Errorf("observe: profiling is only supported on linux/amd64")
}
