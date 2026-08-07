//go:build !osusergo && cgo

package main

// See passwd_pure.go: this build resolves the passwd entry through libc NSS.
var pureUserLookup = false
