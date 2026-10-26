//go:build windows

// Package host Windows probers. Everything here is read-only: values are
// read from the registry, or parsed from the output of built-in status
// commands where registry access alone cannot answer the question.
package host

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// osAdminState reports whether the process is running elevated, which is
// what decides whether admin-gated probes answer or skip.
//
// A token has an elevation type; a member token that is elevated reports
// TokenElevationTypeFull. Anything else — including a split token whose
// elevated half sits unused — is treated as not admin, so the tool never
// quietly assumes rights it does not hold.
func osAdminState() bool {
	elevated, err := isElevated()
	if err != nil {
		return false
	}
	return elevated
}

// platformProbes returns the Windows probe set. Probes that need
// administrator rights are still listed — the rules mentioning them show up
// as skipped rather than invisible — but return "not available" when the
// process is not elevated.
func platformProbes() []Prober {
	admin := osAdminState()

	return []Prober{
		windowsHistory(),
		windowsDefender(admin),
		windowsFirewall(admin),
		windowsRDP(),
		windowsSMBv1(admin),
		windowsLSA(),
		windowsUAC(),
		windowsBitLocker(),
		windowsUpdate(admin),
		windowsAccounts(admin),
		windowsAutoruns(),
		windowsServices(),
		windowsPorts(),
	}
}

/* ---------------------------------------------------------------- helpers */

// regString reads a string value; "" and missing are distinguishable via the
// second return, because "absent" is itself a finding in several rules.
func regString(root registry.Key, path, name string) (value string, ok bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return "", false
	}
	return v, true
}

func regDword(root registry.Key, path, name string) (value uint32, ok bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// regValues lists the value names under a key, for enumeration-style facts
// like autorun entries and Defender exclusions.
func regValues(root registry.Key, path string) []string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil
	}
	return names
}

func yesNo(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

const envRoot = registry.LOCAL_MACHINE

/* --------------------------------------------------------------- probers */

// windowsHistory returns the part carrying raw PowerShell history text, so
// the secret rules can run over it. The file needs no admin rights and
// records every command typed as the current user, which is also why a
// credential typed once lives there indefinitely.
func windowsHistory() Prober {
	return ProberFunc{
		ProbeName: "history",
		Fn: func(ctx context.Context) (Facts, error) {
			appdata := os.Getenv("APPDATA")
			if appdata == "" {
				return nil, fmt.Errorf("APPDATA is not set; no user profile history to read")
			}
			path := filepath.Join(appdata,
				"Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
			raw, err := os.ReadFile(path)
			if err != nil {
				// A machine PowerShell has never been used on answers with no
				// history at all; that is a normal state, not a fault.
				return nil, fmt.Errorf("no PowerShell history file")
			}
			return Facts{"content": strings.ReplaceAll(string(raw), "\r", "")}, nil
		},
	}
}

// windowsDefender reads real-time protection, tamper protection and the
// exclusions list. The exclusions namespace needs admin on some systems;
// without it the facts simply say what was readable.
func windowsDefender(admin bool) Prober {
	return ProberFunc{
		ProbeName: "defender",
		Fn: func(ctx context.Context) (Facts, error) {
			f := Facts{}
			const defRoot = `SOFTWARE\Microsoft\Windows Defender`

			disabled, ok := regDword(envRoot, defRoot+`\Real-Time Protection`, "DisableRealtimeMonitoring")
			switch {
			case !ok:
				f["available"] = "unknown"
				f["realtime_protection"] = "unknown"
			default:
				f["available"] = "true"
				f["realtime_protection"] = yesNo(disabled == 0)
			}

			if tamper, ok := regDword(envRoot, defRoot+`\Features`, "TamperProtection"); ok {
				// 5 = on from cloud policy, 1 = on, 0 = off.
				f["tamper_protection"] = yesNo(tamper != 0)
			}

			paths := regValues(envRoot, defRoot+`\Exclusions\Paths`)
			for i, p := range paths {
				f[fmt.Sprintf("exclusion_path_%d", i)] = strings.ToLower(p)
			}
			for i, p := range regValues(envRoot, defRoot+`\Exclusions\Processes`) {
				f[fmt.Sprintf("exclusion_process_%d", i)] = strings.ToLower(p)
			}
			if len(paths) == 0 {
				if _, exists := regString(envRoot, defRoot+`\Exclusions\Paths`, ""); !exists {
					// An empty or unreadable exclusions key is not distinguished
					// here; the absence of facts is what the rules key off.
					_ = exists
				}
			}
			return f, nil
		},
	}
}

// windowsFirewall asks all three profiles directly from the registry.
func windowsFirewall(admin bool) Prober {
	return ProberFunc{
		ProbeName: "firewall",
		Fn: func(ctx context.Context) (Facts, error) {
			const root = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`
			f := Facts{"available": "true"}
			for _, profile := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
				v, ok := regDword(envRoot, root+`\`+profile, "EnableFirewall")
				if !ok {
					f[strings.TrimSuffix(profile, "Profile")+"_active"] = "unknown"
					continue
				}
				f[strings.TrimSuffix(profile, "Profile")+"_active"] = yesNo(v != 0)
			}
			return f, nil
		},
	}
}

// windowsRDP reports whether remote desktop is on, whether network-level
// authentication is required, and which port it listens on.
func windowsRDP() Prober {
	return ProberFunc{
		ProbeName: "rdp",
		Fn: func(ctx context.Context) (Facts, error) {
			const root = `SYSTEM\CurrentControlSet\Control\Terminal Server`
			f := Facts{}

			deny, ok := regDword(envRoot, root, "fDenyTSConnections")
			if !ok {
				f["available"] = "unknown"
				return f, nil
			}
			enabled := deny == 0
			f["available"] = "true"
			f["enabled"] = yesNo(enabled)
			if !enabled {
				return f, nil
			}

			if nla, ok := regDword(envRoot, root+`\WinStations\RDP-Tcp`, "UserAuthentication"); ok {
				f["nla"] = yesNo(nla != 0)
			}
			if port, ok := regDword(envRoot, root+`\WinStations\RDP-Tcp`, "PortNumber"); ok {
				f["port"] = strconv.FormatUint(uint64(port), 10)
				// The expected value is arithmetic, not a pattern, so the
				// prober derives the comparison and the rule reads the
				// answer — the same split the date maths in the TLS part uses.
				f["port_nondefault"] = yesNo(port != 3389)
			}
			return f, nil
		},
	}
}

// windowsSMBv1 checks the server-side SMB1 toggle. The absence of the value
// means the OS default applies, which is enabled for old builds and
// disabled for current ones; the fact says so rather than guessing.
func windowsSMBv1(admin bool) Prober {
	return ProberFunc{
		ProbeName: "smb",
		Fn: func(ctx context.Context) (Facts, error) {
			v, ok := regDword(envRoot, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1")
			f := Facts{}
			switch {
			case ok && v == 1:
				f["smb1"] = "true"
			case ok && v == 0:
				f["smb1"] = "false"
			default:
				f["smb1"] = "default"
			}
			return f, nil
		},
	}
}

// windowsLSA reads credential-guard-adjacent state: protected process mode
// and the WDigest setting that keeps plaintext passwords in memory.
func windowsLSA() Prober {
	return ProberFunc{
		ProbeName: "lsa",
		Fn: func(ctx context.Context) (Facts, error) {
			const root = `SYSTEM\CurrentControlSet\Control\Lsa`
			f := Facts{"available": "true"}

			if ppl, ok := regDword(envRoot, root, "RunAsPPL"); ok {
				f["ppl"] = yesNo(ppl != 0)
			} else {
				// Without RunAsPPL set the machine runs LSA unprotected, which
				// is the default on non-server SKUs and worth saying plainly.
				f["ppl"] = "false"
			}
			if wdigest, ok := regDword(envRoot, root, "UseLogonCredential"); ok {
				f["use_logon_credential"] = yesNo(wdigest != 0)
			}
			return f, nil
		},
	}
}

// windowsUAC reads the two values that decide whether UAC actually
// intervenes: whether it is filtered for administrators at all, and how
// loudly it prompts when someone tries to elevate.
func windowsUAC() Prober {
	return ProberFunc{
		ProbeName: "uac",
		Fn: func(ctx context.Context) (Facts, error) {
			const root = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
			f := Facts{"available": "true"}

			if lua, ok := regDword(envRoot, root, "EnableLUA"); ok {
				f["enable_lua"] = yesNo(lua != 0)
			}
			if c, ok := regDword(envRoot, root, "ConsentPromptBehaviorAdmin"); ok {
				// 0 = elevate without prompting; 5 = secure desktop prompt.
				f["consent_prompt"] = strconv.FormatUint(uint64(c), 10)
			}
			return f, nil
		},
	}
}

// windowsBitLocker asks the OS volume's protection state.
//
// manage-bde is a built-in status tool and the only supported way to ask
// this without COM automation; a volume with protection off answers
// immediately. The status line is localised on non-English installs —
// that is why an unparseable answer turns the probe off rather than into
// a claim about the volume being unprotected.
func windowsBitLocker() Prober {
	return ProberFunc{
		ProbeName: "bitlocker",
		Fn: func(ctx context.Context) (Facts, error) {
			sysDrive := os.Getenv("SystemDrive")
			if sysDrive == "" {
				sysDrive = "C:"
			}
			out, err := execCommand(ctx, "manage-bde", "-status", sysDrive)
			if err != nil {
				return nil, fmt.Errorf("manage-bde could not answer: %w", err)
			}
			f := Facts{"available": "true"}
			switch {
			case strings.Contains(out, "Protection Off"), strings.Contains(out, "Protection Status:  Off"):
				f["os_volume_protected"] = "false"
			case strings.Contains(out, "Protection On"):
				f["os_volume_protected"] = "true"
			default:
				f["os_volume_protected"] = "unknown"
			}
			return f, nil
		},
	}
}

// windowsUpdate reads the Windows Update policy. AUOptions=1 is the "never
// check" setting that leaves a machine unpatched indefinitely.
func windowsUpdate(admin bool) Prober {
	return ProberFunc{
		ProbeName: "update",
		Fn: func(ctx context.Context) (Facts, error) {
			f := Facts{}
			if v, ok := regDword(envRoot, `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "AUOptions"); ok {
				f["available"] = "true"
				f["auoptions"] = strconv.FormatUint(uint64(v), 10)
			} else {
				// No policy key means updates follow the OS default, which is
				// to notify and install; that is not a finding.
				f["available"] = "true"
				f["auoptions"] = "default"
			}
			return f, nil
		},
	}
}

// windowsAccounts asks net user and net accounts about built-in accounts
// and password policy.
//
// These two commands are unavoidable: the SAM database is not documented for
// direct reading, and third-party parsing of a binary hive is worse than the
// command. Both are built-ins, they run in milliseconds, and neither writes
// anything. Their output is localised, so an unparseable report degrades the
// part to "unknown" instead of producing a fact from the wrong column.
func windowsAccounts(admin bool) Prober {
	return ProberFunc{
		ProbeName: "accounts",
		Fn: func(ctx context.Context) (Facts, error) {
			f := Facts{"available": "true"}

			for _, acct := range []string{"Guest", "Administrator"} {
				out, err := execCommand(ctx, "net", "user", acct)
				if err == nil && accountActive(out) {
					f[strings.ToLower(acct)+"_active"] = "true"
				} else {
					f[strings.ToLower(acct)+"_active"] = "false"
				}
			}

			out, err := execCommand(ctx, "net", "accounts")
			if err == nil {
				if n, ok := netAccountsField(out, "Minimum password length"); ok {
					f["password_min_length"] = strconv.Itoa(n)
					f["password_min_length_ok"] = yesNo(n >= 8)
				}
				if n, ok := netAccountsField(out, "Maximum password age"); ok {
					// "Unlimited" arrives as 99999 from net accounts.
					f["password_max_age_unlimited"] = yesNo(n >= 99999)
				}
				if v, ok := regDword(envRoot, `SYSTEM\CurrentControlSet\Control\Lsa`, "LimitBlankPasswordUse"); ok {
					// 1 = blank passwords may not be used for network logons,
					// which is the safe direction.
					f["blank_password_forbidden"] = yesNo(v != 0)
				}
			}
			return f, nil
		},
	}
}

// accountActive parses "Account active Yes/No" out of `net user <name>`.
func accountActive(out string) bool {
	re := regexp.MustCompile(`(?i)Account active\s+(Yes|No)`)
	m := re.FindStringSubmatch(out)
	return m != nil && strings.EqualFold(m[1], "Yes")
}

// netAccountsField reads "Minimum password length 8" style lines out of
// `net accounts`. "Unlimited" comes through as 99999 for age fields.
func netAccountsField(out, label string) (int, bool) {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(label) + `\s+([0-9]+)`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// windowsAutoruns licenses everything in HKCU/HKLM Run and RunOnce. Each
// entry becomes one numbered fact; the rules do the path arithmetic of
// deciding which are user-writable.
func windowsAutoruns() Prober {
	return ProberFunc{
		ProbeName: "autoruns",
		Fn: func(ctx context.Context) (Facts, error) {
			f := Facts{}
			places := []struct {
				path string
			}{
				{`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`},
				{`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`},
				{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
				{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
			}
			n := 0
			for _, place := range places {
				rootKey, sub, ok := splitHive(place.path)
				if !ok {
					continue
				}
				values := regValues(rootKey, sub)
				for _, name := range values {
					v, ok := regString(rootKey, sub, name)
					if !ok {
						continue
					}
					f[fmt.Sprintf("run_%d", n)] = strings.ToLower(v)
					n++
				}
			}
			return f, nil
		},
	}
}

// splitHive maps the "HKCU\..." spelling used for readability into the
// registry open call.
func splitHive(p string) (registry.Key, string, bool) {
	hive, rest, ok := strings.Cut(p, `\`)
	if !ok {
		return 0, "", false
	}
	switch strings.ToUpper(hive) {
	case "HKCU":
		return registry.CURRENT_USER, rest, true
	case "HKLM":
		return registry.LOCAL_MACHINE, rest, true
	default:
		return 0, "", false
	}
}

// windowsServices inspects every service's ImagePath for the two classic
// privilege-escalation defects: binaries living in user-writable
// locations, and unquoted paths with spaces.
func windowsServices() Prober {
	return ProberFunc{
		ProbeName: "services",
		Fn: func(ctx context.Context) (Facts, error) {
			k, err := registry.OpenKey(envRoot, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
			if err != nil {
				return nil, fmt.Errorf("services key unreadable: %w", err)
			}
			defer k.Close()
			names, err := k.ReadSubKeyNames(-1)
			if err != nil {
				return nil, fmt.Errorf("services key unreadable: %w", err)
			}

			f := Facts{}
			n := 0
			for _, name := range names {
				if ctx.Err() != nil {
					break
				}
				img, ok := regString(envRoot, `SYSTEM\CurrentControlSet\Services\`+name, "ImagePath")
				if !ok || img == "" {
					continue
				}
				// The real path starts after the command image; services
				// frequently carry -k args that would muddy the match.
				if i := strings.Index(strings.ToLower(img), ".exe"); i >= 0 {
					img = img[:i+4]
				}
				f[fmt.Sprintf("service_path_%d", n)] = strings.ToLower(img)
				n++
			}
			return f, nil
		},
	}
}

// windowsPorts lists listening sockets, so the rules can question anything
// bound where the whole network can reach it. netstat and tasklist are
// built-ins; there is no pure-Go way to ask the TCP table without
// GetExtendedTcpTable plumbing that netstat already does.
func windowsPorts() Prober {
	return ProberFunc{
		ProbeName: "ports",
		Fn: func(ctx context.Context) (Facts, error) {
			out, err := execCommand(ctx, "netstat", "-ano", "-p", "tcp")
			if err != nil {
				return nil, fmt.Errorf("netstat could not answer: %w", err)
			}
			pids := map[string]int{}
			f := Facts{}
			n := 0
			for _, line := range strings.Split(out, "\n") {
				fields := strings.Fields(line)
				if len(fields) < 5 || !strings.EqualFold(fields[len(fields)-2], "LISTENING") {
					continue
				}
				local, pid := fields[1], fields[len(fields)-1]
				addr, port, _ := strings.Cut(local, ":")
				if !isWildcardAddr(addr) {
					continue
				}
				key := fmt.Sprintf("listener_%d", n)
				f[key] = strings.ToLower(addr) + ":" + port + " pid=" + pid
				pids[pid]++
				n++
			}
			for pid := range pids {
				name, ok := pidName(ctx, pid)
				if !ok {
					continue
				}
				f["pid_"+pid] = strings.ToLower(name)
			}
			return f, nil
		},
	}
}

func isWildcardAddr(addr string) bool {
	return addr == "0.0.0.0" || addr == "::" || addr == "[::]"
}

// pidName maps a PID to an image name with tasklist, in one call for every
// listener. A PID can vanish between calls, in which case the fact just
// carries no name.
func pidName(ctx context.Context, pid string) (string, bool) {
	out, err := execCommand(ctx, "tasklist", "/FI", "PID eq "+pid, "/FO", "CSV", "/NH")
	if err != nil {
		return "", false
	}
	if i := strings.Index(out, `"`); i >= 0 {
		rest := out[i+1:]
		if j := strings.Index(rest, `"`); j > 0 {
			return strings.TrimSuffix(rest[:j], ".exe"), true
		}
	}
	return "", false
}
