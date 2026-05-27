//go:build linux

package installer

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/sysprobe"
)

// Init runs the install steps and writes progress to w.
// Returns the number of steps that ran and an error on first failure.
func Init(ctx context.Context, w io.Writer, opts ...InitOption) (int, error) {
	cfg := &initOpts{}
	for _, opt := range opts {
		opt(cfg)
	}

	if os.Geteuid() == 0 {
		fmt.Fprintln(w, "warn: running as root; bento installs are normally invoked unprivileged with sudo on individual steps")
	}

	steps, err := planStepsWithConfig(w, cfg)
	if err != nil {
		return 0, err
	}
	if len(steps) == 0 {
		fmt.Fprintln(w, "nothing to do — host is ready")
		return 0, nil
	}

	fmt.Fprintf(w, "\nplan (%d step%s):\n", len(steps), plural(len(steps)))
	for _, s := range steps {
		fmt.Fprintf(w, "  • %s\n", s.description)
	}
	if cfg.dryRun {
		fmt.Fprintln(w, "\n--dry-run: no changes made")
		return 0, nil
	}

	fmt.Fprintln(w, "\nexecuting:")
	for i, s := range steps {
		fmt.Fprintf(w, "  [%d/%d] %s ... ", i+1, len(steps), s.description)
		if err := s.exec(ctx); err != nil {
			fmt.Fprintln(w, "FAILED")
			return i, fmt.Errorf("step %d (%s): %w", i+1, s.description, err)
		}
		fmt.Fprintln(w, "ok")
	}
	fmt.Fprintln(w, "\ndone. run `bento doctor` to verify.")
	return len(steps), nil
}

type step struct {
	description string
	exec        func(context.Context) error
}

func planStepsWithConfig(w io.Writer, cfg *initOpts) ([]step, error) {
	distro := cfg.distroOverride
	var err error
	if distro == "" {
		distro, err = detectDistro()
		if err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(w, "detected distro: %s\n", distro)

	pm, err := packageManagerFor(distro, cfg)
	if err != nil {
		return nil, err
	}

	var steps []step

	if _, err := exec.LookPath("bwrap"); err != nil {
		steps = append(steps, pm.installStep("bubblewrap"))
	}
	if _, err := exec.LookPath("socat"); err != nil {
		steps = append(steps, pm.installStep("socat"))
	}
	if sysprobe.FindProxychainsLib() == "" {
		steps = append(steps, pm.installStep(pm.proxychainsPkg))
	}

	// AppArmor profile (Ubuntu 24.04+ / WSL2).
	if !cfg.skipAppArmor && needsAppArmorProfile() {
		steps = append(steps, step{
			description: "install AppArmor profile for bwrap (/etc/apparmor.d/bwrap)",
			exec:        installAppArmorProfile,
		})
	}
	return steps, nil
}

func detectDistro() (string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", fmt.Errorf("cannot detect distro (no /etc/os-release): %w", err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if after, ok := strings.CutPrefix(line, "ID="); ok {
			return strings.Trim(after, `"`), nil
		}
	}
	return "", fmt.Errorf("/etc/os-release has no ID= field")
}

type packageManager struct {
	cmd            []string // e.g. ["sudo", "apt-get", "install", "-y"]
	proxychainsPkg string
}

func (p packageManager) installStep(pkg string) step {
	args := append(append([]string{}, p.cmd...), pkg)
	return step{
		description: fmt.Sprintf("install %s via %s", pkg, p.cmd[1]),
		exec: func(ctx context.Context) error {
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			cmd.Stdin = os.Stdin
			return cmd.Run()
		},
	}
}

func packageManagerFor(distro string, cfg *initOpts) (packageManager, error) {
	if cfg != nil && cfg.customManagers != nil {
		if cpm, ok := cfg.customManagers[distro]; ok {
			return packageManager(cpm), nil
		}
	}
	switch distro {
	case "ubuntu", "debian":
		return packageManager{
			cmd:            []string{"sudo", "apt-get", "install", "-y"},
			proxychainsPkg: "proxychains4",
		}, nil
	case "fedora", "rhel", "centos", "rocky", "almalinux":
		return packageManager{
			cmd:            []string{"sudo", "dnf", "install", "-y"},
			proxychainsPkg: "proxychains-ng",
		}, nil
	case "arch", "manjaro", "endeavouros":
		return packageManager{
			cmd:            []string{"sudo", "pacman", "-S", "--needed", "--noconfirm"},
			proxychainsPkg: "proxychains-ng",
		}, nil
	}
	return packageManager{}, fmt.Errorf("unsupported distro %q — install bubblewrap + socat + proxychains4 manually and re-run `bento doctor`", distro)
}

// needsAppArmorProfile returns true when the kernel restricts
// unprivileged userns AND bwrap can't currently use them.
func needsAppArmorProfile() bool {
	data, _ := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	if len(data) == 0 || strings.TrimSpace(string(data)) != "1" {
		return false
	}
	out, err := exec.Command("bwrap", "--unshare-user", "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--", "/bin/true").CombinedOutput()
	return err != nil && strings.Contains(string(out), "Permission denied")
}

// apparmorProfile grants bwrap the permissions it needs under the Ubuntu 24.04+
// unprivileged_userns restriction (same shape Flatpak ships).
const apparmorProfile = `abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
`

func installAppArmorProfile(ctx context.Context) error {
	tmp, err := os.CreateTemp("", "bwrap.apparmor-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(apparmorProfile); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	// sudo install + reload
	if err := runSudo(ctx, "install", "-m", "644", tmp.Name(), "/etc/apparmor.d/bwrap"); err != nil {
		return fmt.Errorf("install profile: %w", err)
	}
	if err := runSudo(ctx, "apparmor_parser", "-r", "/etc/apparmor.d/bwrap"); err != nil {
		return fmt.Errorf("reload apparmor: %w", err)
	}
	return nil
}

func runSudo(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "sudo", args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
