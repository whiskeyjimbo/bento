package i386

// Getpid issues i386 getpid (syscall 20) through `int 0x80` from a 64-bit process.
// getpid rather than a syscall with an effect, because the guard is proven by
// whether the process survives the instruction: under the foreign-arch filter it
// dies on SIGSYS, and without it the call returns - which is the bypass the filter
// exists to close. i386 exit would end the calling thread and leave nothing to
// compare against.
//
// On a kernel built without CONFIG_IA32_EMULATION (or booted ia32_emulation=0)
// there is no compat entry point and the instruction raises SIGSEGV instead,
// reaching no filter at all. Callers must tell the two deaths apart.
func Getpid()

// Readlink issues i386 readlink (syscall 85) through `int 0x80` with the given
// path argument. 85 is the number the observe decoder's amd64 table reads as
// creat(2), so a foreign readlink that reaches a ptrace stop would be decoded as a
// WRITE to whatever path it names unless the decoder checks the dispatch arch - the
// fabricated grant that check exists to prevent, and the reason a test needs this
// specific syscall rather than a harmless one.
//
// It also parks path in rdi, the register amd64 creat takes its argument in, so a
// wrong-table decode names a path rather than failing to read one - see the stub.
//
// The arguments are raw addresses, not Go pointers: they must point below 4 GiB
// because the compat ABI truncates them to 32 bits, which no Go allocation can be
// made to satisfy - the caller maps the memory itself.
func Readlink(path, buf, size uintptr)
