//go:build linux

package runner

import (
	"bytes"
	"io"
	"os"
	"strings"
)

// bwrapStderrTee captures bwrap's stderr while passing it through to the
// caller's writer. The tail buffer is small — we only need enough to match
// against known userns/uid-map failure signatures.
type bwrapStderrTee struct {
	passthrough io.Writer
	tail        bytes.Buffer
}

func newBwrapStderrTee(passthrough io.Writer) *bwrapStderrTee {
	if passthrough == nil {
		passthrough = io.Discard
	}
	return &bwrapStderrTee{passthrough: passthrough}
}

func (t *bwrapStderrTee) Write(p []byte) (int, error) {
	// Cap the tail at 4 KiB; bwrap errors are short.
	if t.tail.Len() < 4096 {
		room := 4096 - t.tail.Len()
		if room >= len(p) {
			t.tail.Write(p)
		} else {
			t.tail.Write(p[:room])
		}
	}
	return t.passthrough.Write(p)
}

// maybeHintContainer prints a one-line hint when bwrap's stderr looks like
// a userns failure and we appear to be inside a container. Silent in every
// other case.
func (t *bwrapStderrTee) maybeHintContainer(cfg *Config) {
	if !looksLikeUsernsFailure(t.tail.String()) {
		return
	}
	kind, ok := detectContainer()
	if !ok {
		return
	}
	cfg.warn("bwrap userns setup failed inside a %s container. Try running the container with "+
		"`--security-opt seccomp=unconfined --security-opt apparmor=unconfined`, "+
		"or run `bento doctor` for details.", kind)
}

// looksLikeUsernsFailure matches the bwrap error shapes that come from
// container-imposed restrictions on user namespaces.
func looksLikeUsernsFailure(s string) bool {
	if s == "" {
		return false
	}
	lower := strings.ToLower(s)
	signatures := []string{
		"setting up uid map",
		"setting up gid map",
		"unshare user",
		"unshare(",
		"creating new user namespace",
		"no permitted",
		"operation not permitted",
	}
	for _, sig := range signatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

// detectContainer mirrors doctor.detectContainer so the runner doesn't need
// to import doctor (which would create a cycle). Same checks, same returns.
func detectContainer() (string, bool) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker", true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return "podman", true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		switch {
		case strings.Contains(s, "/docker/"), strings.Contains(s, "docker-"):
			return "docker", true
		case strings.Contains(s, "/lxc/"):
			return "lxc", true
		case strings.Contains(s, "containerd"):
			return "containerd", true
		case strings.Contains(s, "kubepods"):
			return "kubernetes", true
		}
	}
	return "", false
}
