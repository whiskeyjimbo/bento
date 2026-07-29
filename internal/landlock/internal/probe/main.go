// Command probe confines itself to a single directory with Landlock, then
// reports whether an inside and an outside path are readable, so a test can
// observe Landlock's real effect in a fresh process (Landlock is irreversible
// for the process that applies it).
//
// Usage: probe <allowed-dir> <inside-path> <outside-path> [extra-write-file]
// Prints "inside=OK|DENIED outside=OK|DENIED". extra-write-file is added to the
// writable set as a regular FILE: Landlock's directory rules reject a non-directory
// with EINVAL and the ruleset is applied all-or-nothing, so a caller that routed it
// to a directory rule would confine nothing at all - which shows up here as
// outside=OK.
//
// Usage: probe otherthread <allowed-dir> <inside-path> <outside-path>
// Prints "otherthread_inside=... otherthread_outside=...", read from a thread that
// already existed when the ruleset was applied.
//
// Usage: probe unixconnect <allowed-dir> <socket-path>
// Confines itself to allowed-dir, then connects to a pathname AF_UNIX socket that
// lives outside it and prints "unixconnect=OK|DENIED". Landlock ABI 9 can restrict
// that connect, and it is restricted whenever the ruleset HANDLES the right, whether
// or not any rule grants it - so this observes what the handled set is, from outside
// the package.
//
// Usage: probe degraded <read-dir> <write-dir> <outside-path> <socket-path>
// Applies the DEGRADED ruleset - which handles resolve_unix and grants it back on the
// write set - then prints "degraded_outside=OK|DENIED degraded_unixconnect=OK|DENIED
// degraded_ownsocket=OK|DENIED". The outside read is the load-bearing one: the write
// rules ask for a right the handled set no longer carries once BestEffort downgrades
// below ABI 9, and a downgrade that collapsed the ruleset instead of intersecting the
// right away would return no error while confining nothing.
//
// Usage: probe available
// Prints "available=true|false" - so a test can observe Available() in a process
// whose /sys/kernel/security has been masked, reproducing a container.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/whiskeyjimbo/bento/internal/landlock"
)

func main() {
	if len(os.Args) == 5 && os.Args[1] == "otherthread" {
		otherThread(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "unixconnect" {
		unixConnect(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) == 6 && os.Args[1] == "degraded" {
		degraded(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "available" {
		fmt.Printf("available=%v\n", landlock.Available())
		return
	}
	if len(os.Args) != 4 && len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: probe <allowed-dir> <inside-path> <outside-path> [extra-write-file]")
		os.Exit(2)
	}
	allowed := os.Args[1]
	write := []string{allowed}
	if len(os.Args) == 5 {
		write = append(write, os.Args[4])
	}
	if err := landlock.RestrictTo([]string{allowed}, write); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	fmt.Printf("inside=%s outside=%s\n", readable(os.Args[2]), readable(os.Args[3]))
}

func readable(path string) string {
	if _, err := os.ReadFile(path); err != nil {
		return "DENIED"
	}
	return "OK"
}

// unixConnect confines itself away from socket, then dials it. The socket's server was
// bound before this process existed, so it is outside the Landlock domain - which is
// exactly the case ABI 9's resolve_unix right covers.
func unixConnect(allowed, socket string) {
	if err := landlock.RestrictTo([]string{allowed}, []string{allowed}); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	fmt.Printf("unixconnect=%s\n", dial(socket))
}

// degraded applies the degraded ruleset, then reports three things the tier's posture
// rests on: a path outside every grant is still denied (so the ruleset was applied at
// all), a pathname socket bound outside the domain and outside the grants, and a socket
// this process creates under its own write grant - which must stay reachable, since that
// is what the resolve_unix grant on the write rules is for.
func degraded(read, write, outside, socket string) {
	if err := landlock.RestrictDegraded([]string{read}, []string{write}, nil); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	fmt.Printf("degraded_outside=%s degraded_unixconnect=%s degraded_ownsocket=%s\n",
		readable(outside), dial(socket), dial(ownSocket(write)))
}

// ownSocket binds a listener under the write grant after the ruleset is applied, so its
// server is inside the Landlock domain - the case resolve_unix leaves alone - and returns
// its path. An empty path makes dial report DENIED, which is the right answer: failing to
// create the socket at all is the same confinement failure from the target's view.
func ownSocket(write string) string {
	path := filepath.Join(write, "own.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		return ""
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return path
}

func dial(socket string) string {
	if socket == "" {
		return "DENIED"
	}
	//nolint:gosec // G704: the socket path is this test probe's own argument, and dialing
	// an attacker-chosen path is the point - what is under test is whether Landlock denies it.
	c, err := net.Dial("unix", socket)
	if err != nil {
		return "DENIED"
	}
	c.Close()
	return "OK"
}

// otherThread applies the ruleset while a second OS thread is already parked, then
// has THAT thread do the reads. Landlock is per-thread, and go-landlock reaches the
// others by a mechanism that differs between the cgo and no-cgo builds - libpsx
// versus syscall.AllThreadsSyscall. A thread started after the restrict call would
// inherit it through clone under either one and prove nothing, so the thread here is
// locked and synchronized to exist first.
func otherThread(allowed, inside, outside string) {
	// Both ends pinned so the two tids below are stable and the check that they differ
	// is not a race: without it a scheduler that ran the reads on the restricting
	// thread would make this pass while proving nothing.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	self := syscall.Gettid()

	parked, restricted := make(chan struct{}), make(chan struct{})
	tid := make(chan int)
	result := make(chan string)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid <- syscall.Gettid()
		close(parked)
		<-restricted
		result <- fmt.Sprintf("otherthread_inside=%s otherthread_outside=%s", readable(inside), readable(outside))
	}()
	if other := <-tid; other == self {
		fmt.Fprintln(os.Stderr, "the probe thread is the restricting thread")
		os.Exit(2)
	}
	<-parked
	if err := landlock.RestrictTo([]string{allowed}, []string{allowed}); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	close(restricted)
	fmt.Println(<-result)
}
