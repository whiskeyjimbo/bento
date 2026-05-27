/*
 * bento fsshim: LD_PRELOAD shim that reports open()/openat() paths to a
 * host-provided fd. Used as the filesystem-observation fallback when strace
 * isn't available on the host.
 *
 * Opens BENTO_FSOBS_FIFO O_WRONLY|O_NONBLOCK and writes "<path>\n" per
 * successful open. Best-effort; failures (full pipe, no reader, write error)
 * are silently dropped.
 *
 * Build: gcc -shared -fPIC -O2 -o fsshim-linux-amd64.so fsshim.c -ldl
 */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <pthread.h>

static int report_fd = -1;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

typedef int (*open_fn)(const char *, int, ...);
typedef int (*openat_fn)(int, const char *, int, ...);

static open_fn real_open;
static open_fn real_open64;
static openat_fn real_openat;
static openat_fn real_openat64;

static void resolve_open(void)    { if (!real_open)    real_open    = (open_fn)dlsym(RTLD_NEXT, "open"); }
static void resolve_open64(void)  { if (!real_open64)  real_open64  = (open_fn)dlsym(RTLD_NEXT, "open64"); }
static void resolve_openat(void)  { if (!real_openat)  real_openat  = (openat_fn)dlsym(RTLD_NEXT, "openat"); }
static void resolve_openat64(void){ if (!real_openat64)real_openat64= (openat_fn)dlsym(RTLD_NEXT, "openat64"); }

static void init_report_fd(void) {
	const char *path = getenv("BENTO_FSOBS_FIFO");
	if (!path || !*path) return;
	resolve_open();
	if (!real_open) return;
	/* Non-blocking so we never deadlock if the host reader closed early. */
	report_fd = real_open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
}

static void report(const char *path, int ok) {
	if (!path || !*path) return;
	pthread_once(&init_once, init_report_fd);
	if (report_fd < 0) return;
	size_t n = strlen(path);
	if (n >= 4093) return; /* leave room for "O " prefix + newline */
	char buf[4096];
	buf[0] = ok ? 'O' : 'D';
	buf[1] = ' ';
	memcpy(buf + 2, path, n);
	buf[n + 2] = '\n';
	/* Single write keeps lines atomic on pipes up to PIPE_BUF (4096). */
	(void)write(report_fd, buf, n + 3);
}

int open(const char *path, int flags, ...) {
	resolve_open();
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
	}
	int rc = real_open(path, flags, mode);
	if (path && path[0] == '/') report(path, rc >= 0);
	return rc;
}

int open64(const char *path, int flags, ...) {
	resolve_open64();
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
	}
	int rc = real_open64 ? real_open64(path, flags, mode) : real_open(path, flags, mode);
	if (path && path[0] == '/') report(path, rc >= 0);
	return rc;
}

int openat(int dirfd, const char *path, int flags, ...) {
	resolve_openat();
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
	}
	int rc = real_openat(dirfd, path, flags, mode);
	if (dirfd == AT_FDCWD && path[0] == '/') {
		report(path, rc >= 0);
	}
	return rc;
}

int openat64(int dirfd, const char *path, int flags, ...) {
	resolve_openat64();
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
	}
	int rc = real_openat64 ? real_openat64(dirfd, path, flags, mode) : real_openat(dirfd, path, flags, mode);
	if (dirfd == AT_FDCWD && path[0] == '/') {
		report(path, rc >= 0);
	}
	return rc;
}
