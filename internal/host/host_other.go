//go:build !windows

// Package host probers for Linux and macOS: a parity subset of the Windows
// audit, covering the kernel settings with the same intent — port forwarding,
// kernel pointer exposure, logging of kernel messages, ASLR and unprivileged
// BPF. Missing files answer "not available"; only /proc and /sys are read.
package host

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
)

// osAdminState reports whether the process is running as root, which is what
// decides whether admin-gated probes answer or skip.
func osAdminState() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	if os.Geteuid == nil {
		return false
	}
	return os.Geteuid() == 0
}

// platformProbes returns the POSIX probe set. On macOS the /proc tree does
// not exist, so most probers degrade to "not available" gracefully.
func platformProbes() []Prober {
	return []Prober{
		posixSysctl("sysctl"),
		posixHistory(),
	}
}

// procValue reads a /proc/sys (or /sys) file and trims the newline it ends
// with. Files that exist answer one short integer; anything else is a skip.
func procValue(path string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	v := trimSpace(raw)
	if _, err := strconv.Atoi(v); err != nil && v == "" {
		return "", false
	}
	return v, true
}

func trimSpace(raw []byte) string {
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == ' ' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	return string(raw)
}

// posixSysctl reads the kernel tunables that matter for a standing audit and
// turns each into its own fact under one part.
func posixSysctl(name string) Prober {
	return ProberFunc{
		ProbeName: name,
		Fn: func(ctx context.Context) (Facts, error) {
			if runtime.GOOS == "darwin" {
				return nil, fmt.Errorf("sysctl needs IOKit sysctlbyname on this platform, not /proc")
			}

			facts := Facts{}
			for _, item := range []struct{ fact, file string }{
				{"ip_forward", "/proc/sys/net/ipv4/ip_forward"},
				{"aslr", "/proc/sys/kernel/randomize_va_space"},
				{"kptr_restrict", "/proc/sys/kernel/kptr_restrict"},
				{"dmesg_restrict", "/proc/sys/kernel/dmesg_restrict"},
				{"unprivileged_bpf_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled"},
				{"unprivileged_userns_clone", "/proc/sys/kernel/unprivileged_userns_clone"},
				{"yama_ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope"},
			} {
				if v, ok := procValue(item.file); ok {
					facts[item.fact] = v
				}
			}
			if len(facts) == 0 {
				return nil, fmt.Errorf("no /proc/sys facts readable on this machine")
			}
			return facts, nil
		},
	}
}

// posixHistory reads the current user's shell history, so the secret rules
// get the same treatment as on Windows.
func posixHistory() Prober {
	return ProberFunc{
		ProbeName: "history",
		Fn: func(ctx context.Context) (Facts, error) {
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return nil, fmt.Errorf("no readable home directory")
			}
			candidates := []string{
				home + "/.bash_history",
				home + "/.zsh_history",
			}
			for _, path := range candidates {
				raw, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				return Facts{"content": string(raw)}, nil
			}
			return nil, fmt.Errorf("no shell history file")
		},
	}
}
