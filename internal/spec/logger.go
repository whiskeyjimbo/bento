package spec

// Logger is the minimum logging interface bento needs. *log.Logger
// satisfies it; slog or zap users can supply a one-method adapter.
// Defined in the spec package so runner, proxy, and (eventually) any
// other internal subsystem reference the same canonical type.
type Logger interface {
	Printf(format string, args ...any)
}
