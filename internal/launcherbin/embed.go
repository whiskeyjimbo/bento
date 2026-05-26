// Package launcherbin embeds the platform-specific launcher binaries.
//
// The launcher is built by `make launcher` (CGO disabled, statically
// linked) and the resulting blob is embedded at compile time via
// go:embed. At runtime the parent package extracts it to a temp path
// with mode 0755 and uses that path as the bwrap entrypoint.
//
// Why embed and not require an external binary on PATH? Because library
// users would otherwise need a separate install step ("brew install
// bento-launcher", "go install ..."). Embedding makes `go install
// github.com/whiskeyjimbo/bento/cmd/bento` Just Work, and means library
// consumers don't have to think about it.
package launcherbin

import _ "embed"

//go:embed bento-launcher-linux-amd64
var LinuxAMD64 []byte
