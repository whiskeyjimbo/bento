// Package fsshimbin embeds the LD_PRELOAD shim used as the strace fallback
// for filesystem profiling. Built from internal/fsshim/fsshim.c by the
// Makefile's `fsshim` target.
package fsshimbin

import _ "embed"

//go:embed fsshim-linux-amd64.so
var LinuxAMD64 []byte
