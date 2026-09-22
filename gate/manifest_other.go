//go:build !unix

package gate

// linkCount cannot answer off unix, where there is no link count to read; bento has no
// backend there either, so the run it guards cannot start.
func linkCount(string) (uint64, bool) { return 0, false }
