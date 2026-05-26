package proxy

import (
	"io"
	"net"
)

// splice bidirectionally copies between two connections until either
// side closes. Returns when both copy goroutines have finished or one
// of them errors and the other unblocks.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}
