//go:build unix

package gate

import "golang.org/x/sys/unix"

// writableDir reports whether this uid may create entries in an existing directory. It
// asks the kernel the same way the backend's hostWritable does, so an ACL or a group
// grant answers here exactly as it will at the mkdir bwrap is about to attempt - a mode-
// bits comparison would refuse grants the run honors, the one direction this package
// rules out.
func writableDir(dir string) bool {
	return unix.Access(dir, unix.W_OK) == nil
}
