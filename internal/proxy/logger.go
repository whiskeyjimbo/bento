package proxy

import "github.com/whiskeyjimbo/bento/internal/spec"

// Logger is the minimum interface the proxies use for diagnostic
// output. Re-exported from the spec package so the same value flows
// through runner → proxy without conversion.
type Logger = spec.Logger
