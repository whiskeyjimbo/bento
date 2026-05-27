// Package launcherbin embeds platform-specific launcher binaries.
// Embedding (instead of requiring an external binary on PATH) keeps
// `go install` a single step for library users.
package launcherbin

import _ "embed"

//go:embed bento-launcher-linux-amd64
var LinuxAMD64 []byte
