// Package i386 issues a syscall through the x86 compat ABI, so a test can prove
// the foreign-arch guard refuses it. Go cannot emit `int 0x80`, so the call is a
// hand-written amd64 stub; it lives in its own package because assembly belongs to
// the package it is declared in, and internal/seccomp itself must not carry a
// probe the shipped binary would link.
package i386
