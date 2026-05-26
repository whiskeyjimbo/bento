// Static Go binary that does raw TCP connects bypassing LD_PRELOAD.
// In an unsandboxed shell this reaches anything; under the sandbox
// with Landlock active, both should fail (port 443 isn't in the
// allowed list of proxy ports).
package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

func tryDial(addr string) {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		fmt.Printf("  dial %-30s -> %v\n", addr, err)
		return
	}
	fmt.Printf("  dial %-30s -> OK\n", addr)
	c.Close()
}

func tryRawConnect(name string, ip [4]byte, port int) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Printf("  raw  %-30s -> socket: %v\n", name, err)
		return
	}
	defer syscall.Close(fd)
	err = syscall.Connect(fd, &syscall.SockaddrInet4{Port: port, Addr: ip})
	if err != nil {
		fmt.Printf("  raw  %-30s -> %v\n", name, err)
		return
	}
	fmt.Printf("  raw  %-30s -> OK\n", name)
}

func main() {
	fmt.Println("== via net.Dial (Go's http stack) ==")
	tryDial("example.com:443")
	tryDial("api.github.com:443")

	fmt.Println("== via raw syscall.Connect (bypasses any proxy magic) ==")
	tryRawConnect("example.com:443", [4]byte{93, 184, 215, 14}, 443)
	tryRawConnect("api.github.com:443", [4]byte{140, 82, 121, 6}, 443)
	tryRawConnect("1.1.1.1:443", [4]byte{1, 1, 1, 1}, 443)

	fmt.Println("(in the sandbox, all 443 connects should EACCES because Landlock allows only the proxy ports)")
}
