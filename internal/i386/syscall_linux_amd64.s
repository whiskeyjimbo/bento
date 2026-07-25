#include "textflag.h"

// func Getpid()
//
// seccomp keys on the syscall ABI, not the code segment, so this is a foreign-arch
// syscall even though the process is 64-bit. The result is discarded: the caller
// asserts on whether control returns here at all.
TEXT ·Getpid(SB), NOSPLIT, $0-0
	MOVL	$20, AX	// i386 __NR_getpid
	INT	$0x80
	RET

// func Readlink(path, buf, size uintptr)
//
// The i386 ABI passes its arguments in ebx/ecx/edx - the low halves of the
// registers loaded here. path also goes into DI, which the syscall itself ignores:
// it is where an amd64 decoder reading this stop against the wrong table looks for
// creat's argument, and in a real 32-bit program that register holds whatever the
// program last put there. Loading it with a valid path is what makes the misdecode
// land on a nameable path instead of an unreadable address.
TEXT ·Readlink(SB), NOSPLIT, $0-24
	MOVQ	path+0(FP), BX
	MOVQ	buf+8(FP), CX
	MOVQ	size+16(FP), DX
	MOVQ	path+0(FP), DI
	MOVL	$85, AX	// i386 __NR_readlink
	INT	$0x80
	RET
