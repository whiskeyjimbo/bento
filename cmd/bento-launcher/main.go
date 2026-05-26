//go:build linux && amd64

// bento-launcher: tiny shim that installs seccomp (block execve, allow
// execveat) and Landlock TCP rules, then execveat()s into the target
// interpreter. We use execveat (different syscall number than execve)
// so our own transition isn't blocked by the seccomp filter we just
// installed.
//
// Usage: bento-launcher <interpreter-path> [args...]
//
// Environment:
//
//	BENTO_ALLOW_PORTS  comma-separated TCP ports the script may connect to
//	                   (typically the bento HTTP CONNECT + SOCKS5 proxy
//	                   ports). Empty/unset → all TCP blocked.
//
// Architecture: linux/amd64 only — the syscall numbers below
// (sysExecveat, sysSeccomp, sysLandlock*) are amd64-specific. arm64
// support requires a separate file with the arm64 numbers and matching
// build tags.
//

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

// Syscall numbers (amd64; see arch/x86/entry/syscalls/syscall_64.tbl).
const (
	sysSeccomp               = 317
	sysExecveat              = 322
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446
)

// prctl options (see <linux/prctl.h>).
const (
	prSetNoNewPrivs = 38
)

// execveat flags (see <linux/fcntl.h>).
const (
	atEmptyPath = 0x1000
)

// Syscalls we filter on (see arch/x86/entry/syscalls/syscall_64.tbl).
const (
	nrExecve = 59
)

// Landlock constants (see <linux/landlock.h>).
const (
	landlockAccessNetBindTCP    = 1 << 0
	landlockAccessNetConnectTCP = 1 << 1
	landlockRuleNetPort         = 2
)

// seccomp constants (see <linux/seccomp.h> + <linux/bpf_common.h>).
const (
	seccompSetModeFilter = 1

	// Classic BPF opcodes we use.
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfK   = 0x00
	bpfRET = 0x06

	// seccomp return values.
	seccompRetAllow = 0x7fff0000
	seccompRetEperm = 0x00050001 // SECCOMP_RET_ERRNO | EPERM(1)
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bento-launcher <interpreter> [args...]")
		os.Exit(2)
	}
	interp := os.Args[1]

	fd, err := syscall.Open(interp, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		die("open interpreter: %v", err)
	}

	if err := applyFDLimit(); err != nil {
		die("fd limit: %v", err)
	}
	if err := installSeccomp(); err != nil {
		die("seccomp: %v", err)
	}
	if err := installLandlock(parsePorts(os.Getenv(spec.EnvAllowedPorts))); err != nil {
		die("landlock: %v", err)
	}

	argv := os.Args[1:]
	argvPtrs := make([]*byte, 0, len(argv)+1)
	for _, a := range argv {
		p, err := syscall.BytePtrFromString(a)
		if err != nil {
			die("argv: %v", err)
		}
		argvPtrs = append(argvPtrs, p)
	}
	argvPtrs = append(argvPtrs, nil)

	envp := os.Environ()
	envpPtrs := make([]*byte, 0, len(envp)+1)
	for _, e := range envp {
		p, err := syscall.BytePtrFromString(e)
		if err != nil {
			die("envp: %v", err)
		}
		envpPtrs = append(envpPtrs, p)
	}
	envpPtrs = append(envpPtrs, nil)

	empty, _ := syscall.BytePtrFromString("")
	_, _, errno := syscall.Syscall6(
		sysExecveat,
		uintptr(fd),
		uintptr(unsafe.Pointer(empty)),
		uintptr(unsafe.Pointer(&argvPtrs[0])),
		uintptr(unsafe.Pointer(&envpPtrs[0])),
		atEmptyPath,
		0,
	)
	die("execveat: %v", errno)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "bento-launcher: "+format+"\n", args...)
	os.Exit(1)
}

// applyFDLimit caps RLIMIT_NOFILE if BENTO_FD_LIMIT is set. systemd's
// LimitNOFILE= isn't honored for --scope units; setrlimit is.
// Applied BEFORE seccomp because the seccomp filter could
// theoretically block prlimit64 in the future.
func applyFDLimit() error {
	s := os.Getenv(spec.EnvFDLimit)
	if s == "" {
		return nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return nil // ignore malformed
	}
	lim := syscall.Rlimit{Cur: n, Max: n}
	return syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
}

func parsePorts(s string) []uint64 {
	if s == "" {
		return nil
	}
	var ports []uint64
	for p := range strings.SplitSeq(s, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16)
		if err == nil && n > 0 {
			ports = append(ports, n)
		}
	}
	return ports
}

func installLandlock(allowedPorts []uint64) error {
	type rulesetAttr struct {
		handledAccessFS  uint64
		handledAccessNet uint64
	}
	type netPortAttr struct {
		allowedAccess uint64
		port          uint64
	}
	attr := rulesetAttr{handledAccessNet: landlockAccessNetBindTCP | landlockAccessNetConnectTCP}
	fd, _, errno := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return nil // older kernel (<6.7), degrade silently
	}
	for _, port := range allowedPorts {
		rule := netPortAttr{allowedAccess: landlockAccessNetConnectTCP, port: port}
		if _, _, errno := syscall.Syscall6(sysLandlockAddRule, fd, landlockRuleNetPort, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
			return fmt.Errorf("add_rule port=%d: %v", port, errno)
		}
	}
	if _, _, errno := syscall.Syscall(sysLandlockRestrictSelf, fd, 0, 0); errno != 0 {
		return fmt.Errorf("restrict_self: %v", errno)
	}
	syscall.Close(int(fd))
	return nil
}

// sockFilter is the on-the-wire BPF instruction (see <linux/filter.h>).
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// sockFprog is the BPF program pointer + length passed to seccomp().
type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// installSeccomp installs a BPF filter that EPERMs execve(2) but allows
// execveat(2) (and everything else). The launcher itself uses execveat
// to transition into the interpreter, so it's not blocked by its own
// filter.
func installSeccomp() error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %v", errno)
	}
	prog := []sockFilter{
		// 0: load syscall nr from seccomp_data[0]
		{code: bpfLD | bpfW | bpfABS, k: 0},
		// 1: if nr == execve, jump to insn 3 (eperm); else fall through
		{code: bpfJMP | bpfJEQ | bpfK, jt: 1, jf: 0, k: nrExecve},
		// 2: ret ALLOW
		{code: bpfRET | bpfK, k: seccompRetAllow},
		// 3: ret ERRNO|EPERM
		{code: bpfRET | bpfK, k: seccompRetEperm},
	}
	prog2 := sockFprog{len: uint16(len(prog)), filter: &prog[0]}
	if _, _, errno := syscall.Syscall(sysSeccomp, seccompSetModeFilter, 0, uintptr(unsafe.Pointer(&prog2))); errno != 0 {
		return fmt.Errorf("seccomp: %v", errno)
	}
	return nil
}
