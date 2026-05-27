package proxy

import (
	"io"
	"net"
)

// splice bidirectionally copies between two connections until either side closes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}
