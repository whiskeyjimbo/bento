//go:build darwin

package doctor

import "os/exec"

func platformRegistry() []registeredCheck {
	checks := []registeredCheck{
		{checkSandboxExec, CategoryCore},
	}
	for _, interp := range []string{"python3", "bash", "node"} {
		name := interp
		checks = append(checks, registeredCheck{
			run:      func() CheckResult { return checkInterpreter(name) },
			category: CategoryInterpreter,
		})
	}
	return checks
}

func checkSandboxExec() CheckResult {
	path, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return CheckResult{
			Name: "sandbox-exec", Status: StatusFail,
			Detail:      "not found",
			Remediation: "ships with macOS — if missing, OS install is broken",
		}
	}
	return CheckResult{Name: "sandbox-exec", Status: StatusPass, Detail: path}
}

func checkInterpreter(name string) CheckResult {
	if path, err := exec.LookPath(name); err == nil {
		return CheckResult{Name: name, Status: StatusPass, Detail: path}
	}
	return CheckResult{Name: name, Status: StatusWarn, Detail: "not in PATH"}
}
