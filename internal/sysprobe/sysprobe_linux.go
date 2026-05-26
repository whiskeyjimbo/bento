//go:build linux

// Package sysprobe holds platform probes shared between the runner
// (which needs to find host binaries/libraries) and the doctor (which
// needs to report whether they're present). Centralised here to avoid
// duplication and drift.
package sysprobe

import (
	"os"
	"path/filepath"
	"syscall"
)

// FindSocat returns the absolute path to socat if present on the host,
// or "" if not found. Used by the bridge network mode (kernel <6.7
// fallback) to bridge unix sockets ↔ TCP inside the sandbox.
func FindSocat() string {
	for _, p := range []string{"/usr/bin/socat", "/usr/local/bin/socat", "/bin/socat"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// FindProxychainsLib returns the path to libproxychains.so.4 if present
// on the host, or "" if not found.
func FindProxychainsLib() string {
	for _, p := range []string{
		"/usr/lib/x86_64-linux-gnu/libproxychains.so.4",
		"/usr/lib/x86_64-linux-gnu/libproxychains4.so",
		"/usr/lib64/libproxychains.so.4",
		"/usr/lib/libproxychains.so.4",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	matches, _ := filepath.Glob("/usr/lib*/**/libproxychains*.so*")
	for _, m := range matches {
		if _, err := os.Stat(m); err == nil {
			return m
		}
	}
	return ""
}

// LandlockABI returns the supported Landlock ABI version, or -1 if the
// syscall is unavailable (kernel <5.13).
//
// ABI 1: filesystem; ABI 2: refer; ABI 3: truncate; ABI 4: TCP network;
// ABI 5: ioctl_dev; ABI 6: abstract unix socket + signal scoping.
func LandlockABI() int {
	const (
		sysLandlockCreateRuleset = 444
		flagVersionQuery         = 1 << 0
	)
	v, _, errno := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, flagVersionQuery)
	if errno != 0 {
		return -1
	}
	return int(v)
}
