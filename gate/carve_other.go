//go:build !unix

package gate

// writableDir answers "writable" off unix, so ShieldCarveProblems refuses nothing there.
// There is no access(2) to ask, and bento has no backend on such a host either, so the
// run this refusal exists to anticipate cannot start. Answering "not writable" instead
// would invent a refusal on every grant, which is the one direction this package rules
// out; the narrowing goes the way the package doc permits.
func writableDir(string) bool {
	return true
}
