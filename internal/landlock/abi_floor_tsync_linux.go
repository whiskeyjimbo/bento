//go:build landlocktsync

package landlock

// minRequiredABI mirrors go-landlock's landlocktsync floor: built with that tag,
// go-landlock refuses to enforce below ABI v8 (it needs the thread-sync restrict), so a
// kernel below v8 makes BestEffort a silent no-op. Matching the floor here keeps the
// availability gate in step, so the gate refuses exactly when enforcement would.
func minRequiredABI() int { return 8 }
