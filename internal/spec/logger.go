package spec

// Logger is the minimum logging interface bento needs; *log.Logger satisfies it.
type Logger interface {
	Printf(format string, args ...any)
}
