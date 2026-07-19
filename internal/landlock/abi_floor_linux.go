//go:build !landlocktsync

package landlock

// minRequiredABI mirrors go-landlock's own minimum-ABI floor so bento's availability
// gate detects the same effective ABI the enforcement path (BestEffort) does. Without
// the landlocktsync build tag go-landlock imposes no floor.
func minRequiredABI() int { return 0 }
