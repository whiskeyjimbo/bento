//go:build linux && amd64

// bento-launcher: installs seccomp (block execve, allow execveat) and Landlock
// TCP rules, then execveats into the target interpreter. execveat is used so
// our own transition isn't blocked by the seccomp filter we just installed.
//
// Usage: bento-launcher <interpreter-path> [args...]
// Env BENTO_ALLOW_PORTS: comma-separated TCP ports; empty → all TCP blocked.
// linux/amd64 only — syscall numbers below are amd64-specific.

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
	if errno == syscall.ENOENT {
		// The interpreter file exists (we just opened it), so ENOENT from
		// execveat almost always means the ELF program interpreter (e.g.
		// /lib64/ld-linux-x86-64.so.2 or a /nix/store/... ld-linux) is
		// missing inside the sandbox.
		if ldPath, ok := readElfInterp(interp); ok {
			die("interpreter %s loaded but its ELF program interpreter %s is missing in the sandbox.\n"+
				"  This usually means a managed-runtime (Nix, mise, asdf, conda) install whose dynamic\n"+
				"  linker and shared libraries weren't bind-mounted. Add the closure to the manifest's\n"+
				"  `read:` list, or use a system interpreter (e.g. /usr/bin/python3, /bin/bash).", interp, ldPath)
		}
		die("execveat: %v — interpreter %s could not be loaded (likely missing dynamic-linker dependency)", errno, interp)
	}
	die("execveat: %v", errno)
}

// readElfInterp returns the ELF program-interpreter path embedded in the
// PT_INTERP segment of an ELF binary, if any. It returns ("", false) for
// scripts, static binaries, or unreadable files.
func readElfInterp(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	var ident [16]byte
	if _, err := f.ReadAt(ident[:], 0); err != nil {
		return "", false
	}
	if ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
		return "", false
	}
	is64 := ident[4] == 2
	le := ident[5] == 1
	read16 := func(b []byte) uint16 {
		if le {
			return uint16(b[0]) | uint16(b[1])<<8
		}
		return uint16(b[1]) | uint16(b[0])<<8
	}
	read32 := func(b []byte) uint32 {
		if le {
			return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
		}
		return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	}
	read64 := func(b []byte) uint64 {
		if le {
			return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
				uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
		}
		return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
			uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	}
	var phoff uint64
	var phentsize, phnum uint16
	if is64 {
		var ehdr [64]byte
		if _, err := f.ReadAt(ehdr[:], 0); err != nil {
			return "", false
		}
		phoff = read64(ehdr[32:40])
		phentsize = read16(ehdr[54:56])
		phnum = read16(ehdr[56:58])
	} else {
		var ehdr [52]byte
		if _, err := f.ReadAt(ehdr[:], 0); err != nil {
			return "", false
		}
		phoff = uint64(read32(ehdr[28:32]))
		phentsize = read16(ehdr[42:44])
		phnum = read16(ehdr[44:46])
	}
	const ptInterp = 3
	ph := make([]byte, int(phentsize))
	for i := uint16(0); i < phnum; i++ {
		if _, err := f.ReadAt(ph, int64(phoff)+int64(i)*int64(phentsize)); err != nil {
			return "", false
		}
		ptype := read32(ph[0:4])
		if ptype != ptInterp {
			continue
		}
		var off, sz uint64
		if is64 {
			off = read64(ph[8:16])
			sz = read64(ph[32:40])
		} else {
			off = uint64(read32(ph[4:8]))
			sz = uint64(read32(ph[16:20]))
		}
		if sz == 0 || sz > 4096 {
			return "", false
		}
		buf := make([]byte, sz)
		if _, err := f.ReadAt(buf, int64(off)); err != nil {
			return "", false
		}
		s := strings.TrimRight(string(buf), "\x00")
		return s, s != ""
	}
	return "", false
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "bento-launcher: "+format+"\n", args...)
	os.Exit(1)
}

// applyFDLimit caps RLIMIT_NOFILE if BENTO_FD_LIMIT is set. systemd's
// LimitNOFILE= isn't honored for --scope units; setrlimit is. Applied
// before seccomp in case the filter ever blocks prlimit64.
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
