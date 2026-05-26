//go:build linux

package doctor

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/spec"
	"github.com/whiskeyjimbo/bento/internal/sysprobe"
)

// platformRegistry returns the built-in Linux checks tagged with their
// categories. Run() filters and executes them.
func platformRegistry() []registeredCheck {
	checks := []registeredCheck{
		{checkBwrap, CategoryCore},
		{checkUnprivilegedUserns, CategoryCore},
		{checkAppArmorProfile, CategoryCore},
		{checkLandlockTCP, CategoryNetwork},
		{checkLibproxychains, CategoryNetwork},
		{checkSocat, CategoryNetwork},
		{checkSystemdRun, CategoryLimits},
		{checkDangerousPaths, CategoryCore},
	}
	for _, interp := range []string{"python3", "bash", "node"} {
		name := interp // capture
		checks = append(checks, registeredCheck{
			run:      func() CheckResult { return checkInterpreter(name) },
			category: CategoryInterpreter,
		})
	}
	return checks
}

func checkBwrap() CheckResult {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return CheckResult{
			Name: "bwrap binary", Status: StatusFail,
			Detail:      "not in PATH",
			Remediation: "apt install bubblewrap (or distro equivalent)",
		}
	}
	out, _ := exec.Command("bwrap", "--version").Output()
	return CheckResult{
		Name: "bwrap binary", Status: StatusPass,
		Detail: strings.TrimSpace(string(out)) + " at " + path,
	}
}

func checkUnprivilegedUserns() CheckResult {
	data, _ := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone")
	if len(data) > 0 && strings.TrimSpace(string(data)) == "0" {
		return CheckResult{
			Name: "unprivileged user namespaces", Status: StatusFail,
			Detail:      "/proc/sys/kernel/unprivileged_userns_clone = 0",
			Remediation: "sudo sysctl -w kernel.unprivileged_userns_clone=1",
		}
	}
	return CheckResult{Name: "unprivileged user namespaces", Status: StatusPass}
}

func checkAppArmorProfile() CheckResult {
	data, _ := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	if !(len(data) > 0 && strings.TrimSpace(string(data)) == "1") {
		return CheckResult{Name: "bwrap AppArmor profile", Status: StatusPass, Detail: "userns restriction not active"}
	}
	out, err := exec.Command("bwrap", "--unshare-user", "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--", "/bin/true").CombinedOutput()
	if err != nil && strings.Contains(string(out), "Permission denied") {
		return CheckResult{
			Name: "bwrap AppArmor profile", Status: StatusFail,
			Detail:      "apparmor_restrict_unprivileged_userns=1 and bwrap has no profile",
			Remediation: "install /etc/apparmor.d/bwrap (see testdata/bwrap.apparmor)",
		}
	}
	return CheckResult{Name: "bwrap AppArmor profile", Status: StatusPass, Detail: "userns restriction active but bwrap is allowed"}
}

func checkLandlockTCP() CheckResult {
	abi := sysprobe.LandlockABI()
	switch {
	case abi < 0:
		return CheckResult{
			Name: "Landlock", Status: StatusWarn,
			Detail:      "syscall unavailable (kernel <5.13)",
			Remediation: "without Landlock, static binaries can bypass the proxy",
		}
	case abi < 4:
		return CheckResult{
			Name: "Landlock TCP", Status: StatusWarn,
			Detail:      "kernel ABI=" + strconv.Itoa(abi) + " (need ≥4 for TCP rules)",
			Remediation: "upgrade kernel to ≥6.7 for static-binary network enforcement",
		}
	}
	return CheckResult{Name: "Landlock TCP", Status: StatusPass, Detail: "ABI=" + strconv.Itoa(abi)}
}

func checkLibproxychains() CheckResult {
	lib := sysprobe.FindProxychainsLib()
	if lib == "" {
		return CheckResult{
			Name: "libproxychains.so", Status: StatusWarn,
			Detail:      "not found",
			Remediation: "apt install proxychains4 (needed for non-HTTP network filtering)",
		}
	}
	return CheckResult{Name: "libproxychains.so", Status: StatusPass, Detail: lib}
}

func checkSystemdRun() CheckResult {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return CheckResult{
			Name: "systemd-run", Status: StatusWarn,
			Detail:      "not available",
			Remediation: "resource limits will not be enforced",
		}
	}
	return CheckResult{Name: "systemd-run", Status: StatusPass}
}

func checkSocat() CheckResult {
	if path := sysprobe.FindSocat(); path != "" {
		return CheckResult{Name: "socat", Status: StatusPass, Detail: path}
	}
	return CheckResult{
		Name: "socat", Status: StatusWarn,
		Detail:      "not found",
		Remediation: "apt install socat (only needed for NetworkModeBridge / kernel <6.7 fallback)",
	}
}

func checkDangerousPaths() CheckResult {
	home, _ := os.UserHomeDir()
	if home == "" {
		return CheckResult{
			Name: "mandatory-deny paths", Status: StatusWarn,
			Detail:      "HOME unset — cannot expand ~ paths",
			Remediation: "set HOME so dangerous-paths lists can resolve",
		}
	}
	read := spec.ExpandDangerousPaths(home)
	write := spec.ExpandDangerousWritePaths(home)
	readExisting, writeExisting := 0, 0
	for _, p := range read {
		if _, err := os.Stat(p); err == nil {
			readExisting++
		}
	}
	for _, p := range write {
		if _, err := os.Stat(p); err == nil {
			writeExisting++
		}
	}
	return CheckResult{
		Name: "mandatory-deny paths", Status: StatusPass,
		Detail: strconv.Itoa(len(read)) + " read-protect (" + strconv.Itoa(readExisting) + " present), " +
			strconv.Itoa(len(write)) + " write-protect (" + strconv.Itoa(writeExisting) + " present)",
	}
}

func checkInterpreter(name string) CheckResult {
	if path, err := exec.LookPath(name); err == nil {
		return CheckResult{Name: name, Status: StatusPass, Detail: path}
	}
	return CheckResult{Name: name, Status: StatusWarn, Detail: "not in PATH"}
}
