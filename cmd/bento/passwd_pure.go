//go:build osusergo || !cgo

package main

// pureUserLookup reports whether this build resolves the uid's passwd entry with Go's
// own reader rather than libc NSS. The credential shields anchor on that entry, so a
// build routing the lookup through NSS puts it back under caller control - which is why
// the Makefile pins CGO_ENABLED=0 and -tags osusergo. Nothing at runtime can observe
// which resolver os/user compiled in, so the build constraint is what reports it.
//
// It is a var so a test can watch both answers: a test binary is one build, and which
// one depends on whether the runner had a C toolchain.
var pureUserLookup = true
