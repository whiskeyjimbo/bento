//go:build linux

package launcher

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The whole point of reading this from inside the sandbox is that a bwrap whose --tmpfs
// /tmp was filtered out of argv answers the pre-run probe identically. So the verdict has
// to name a host filesystem for what it is. EXT4_SUPER_MAGIC stands in for "whatever the
// host's /tmp is on"; the check is an equality against tmpfs, not a denylist.
func TestIsTmpfsRejectsAHostFilesystem(t *testing.T) {
	if isTmpfs(unix.EXT4_SUPER_MAGIC) {
		t.Error("isTmpfs accepted ext4; a --bind of the host's /tmp would go unnoticed")
	}
	if !isTmpfs(unix.TMPFS_MAGIC) {
		t.Error("isTmpfs rejected tmpfs, which is what a sandboxed run's /tmp is")
	}
}

const sentinelVerifyRun = "BENTO_TEST_VERIFY_RUN"

// The check is worth nothing if Run stops calling it, and a fixture test on the predicate
// cannot see that. This runs a launch stage in a sandbox weakened in exactly one place -
// the host's /tmp bound in where the fresh tmpfs belongs, which is what the shim under
// bv2-uuzlm left behind - and requires the refusal. In a child because Run makes the
// process permanently non-dumpable.
func TestRunRefusesTheHostsTmp(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "tmp")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Run proceeded on the host's /tmp:\n%s", out)
	}
	if !strings.Contains(string(out), "is not the fresh tmpfs") {
		t.Errorf("Run failed without the scratch-mount refusal: %q", out)
	}
}

// The other half of the same claim: a sandbox bento really did build must not be refused.
// Without this the refusal above passes just as well with the check wired to always fail.
func TestRunAcceptsTheSandboxBentoBuilds(t *testing.T) {
	if os.Getenv(sentinelVerifyRun) != "" {
		if _, err := Run(Config{Target: []string{"/bin/true"}}); err != nil {
			os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sentinelVerifyRun+"=1")
	inSandbox(t, cmd, "")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Run refused the sandbox bento itself asks bwrap for: %v\n%s", err, out)
	}
}
