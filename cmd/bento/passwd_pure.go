//go:build osusergo || !cgo

package main

// pureUserLookup reports whether this build resolves the uid's passwd entry with Go's
// own reader rather than libc NSS. The credential shields anchor on that entry, so a
// build routing the lookup through NSS puts it back under caller control - which is why
// the Makefile pins CGO_ENABLED=0 and -tags osusergo. Nothing at runtime can observe
// which resolver os/user compiled in, so the build constraint is what reports it. The
// constraint is os/user's own selection rule on Linux; on darwin os/user reaches the
// platform database whenever the tag is absent, which this would call pure - harmless
// only because no darwin build confines anything.
//
// It is a var so a test can watch both answers: a test binary is one build, and which
// one depends on whether the runner had a C toolchain.
var pureUserLookup = true
