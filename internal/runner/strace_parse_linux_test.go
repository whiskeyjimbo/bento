//go:build linux

package runner

import "testing"

func TestExtractOpenatAttempt(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantPath  string
		wantOK    bool
		wantWrite bool
		wantFound bool
	}{
		{
			name:      "openat read success",
			line:      `1234 openat(AT_FDCWD, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 3`,
			wantPath:  "/etc/hostname",
			wantOK:    true,
			wantFound: true,
		},
		{
			name:      "openat write success",
			line:      `openat(AT_FDCWD, "/tmp/out.json", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4`,
			wantPath:  "/tmp/out.json",
			wantOK:    true,
			wantWrite: true,
			wantFound: true,
		},
		{
			name:      "openat failure ENOENT",
			line:      `openat(AT_FDCWD, "/missing", O_RDONLY) = -1 ENOENT (No such file or directory)`,
			wantPath:  "/missing",
			wantOK:    false,
			wantFound: true,
		},
		// Regression: GNU tar opens its destination via the creat(2) syscall.
		// Before this case existed in the test, the parser only knew openat
		// and silently dropped tar's write — leading to profile manifests
		// missing the most obvious "where did the tarball go" entry.
		{
			name:      "creat is a write",
			line:      `3448424 creat("/tmp/backup.tar.gz", 0666) = 3`,
			wantPath:  "/tmp/backup.tar.gz",
			wantOK:    true,
			wantWrite: true,
			wantFound: true,
		},
		{
			name:      "legacy open read",
			line:      `5555 open("/etc/passwd", O_RDONLY) = 3`,
			wantPath:  "/etc/passwd",
			wantOK:    true,
			wantFound: true,
		},
		{
			name:      "legacy open write",
			line:      `open("/tmp/log", O_WRONLY|O_APPEND) = 5`,
			wantPath:  "/tmp/log",
			wantOK:    true,
			wantWrite: true,
			wantFound: true,
		},
		// "reopen(" must not be misread as "open(": the parse guard checks
		// the preceding character isn't an identifier char.
		{
			name:      "reopen is not open",
			line:      `1234 reopen("/foo") = 0`,
			wantFound: false,
		},
		{
			name:      "ignored unrelated syscall",
			line:      `1234 read(3, "...", 4096) = 1024`,
			wantFound: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, ok, write, found := extractOpenatAttempt(tc.line)
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if !tc.wantFound {
				return
			}
			if path != tc.wantPath {
				t.Errorf("path = %q, want %q", path, tc.wantPath)
			}
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if write != tc.wantWrite {
				t.Errorf("write = %v, want %v", write, tc.wantWrite)
			}
		})
	}
}
