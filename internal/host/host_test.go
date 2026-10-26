package host

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nasafuriy/qalqon"
	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/template"
)

func builtin(t *testing.T) *template.Set {
	t.Helper()
	set, errs := template.Load(qalqon.Templates, "templates")
	for _, err := range errs {
		t.Fatalf("templates failed to load: %v", err)
	}
	return set
}

func hostTemplates(t *testing.T) *template.Set {
	t.Helper()
	return builtin(t).OfKind(template.KindHost)
}

// probersFrom turns fixture facts into a probe set: every part answers, on
// every machine, exactly what the fixture says. This is what makes the host
// audit testable without a Windows system to run it on.
func probersFrom(parts map[string]Facts) []Prober {
	var out []Prober
	for name, facts := range parts {
		name, facts := name, facts
		out = append(out, ProberFunc{
			ProbeName: name,
			Fn: func(ctx context.Context) (Facts, error) {
				return facts, nil
			},
		})
	}
	return out
}

func runFixture(t *testing.T, name string, hostSet, secretSet *template.Set, drop ...string) []engine.Finding {
	t.Helper()

	parts, err := LoadFixture(filepath.Join("..", "..", "testdata", "host", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	for _, part := range drop {
		delete(parts, part)
	}

	findings, _, _, err := Run(context.Background(), hostSet, secretSet, Options{
		Probers: probersFrom(parts),
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	return findings
}

func idsFor(findings []engine.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if !seen[f.TemplateID] {
			seen[f.TemplateID] = true
			out = append(out, f.TemplateID)
		}
	}
	return out
}

func assertSetsEqual(t *testing.T, what string, got, want []string) {
	t.Helper()
	gotSet, wantSet := map[string]bool{}, map[string]bool{}
	for _, id := range got {
		gotSet[id] = true
	}
	for _, id := range want {
		wantSet[id] = true
	}
	for _, id := range want {
		if !gotSet[id] {
			t.Errorf("%s did not fire: %s", what, id)
		}
	}
	for _, id := range got {
		if !wantSet[id] {
			t.Errorf("%s fired unexpectedly: %s", what, id)
		}
	}
}

// The deliberately insecure Windows machine must trip exactly the rules it
// was built for, once each, and nothing else.
func TestWindowsVulnerableFixture(t *testing.T) {
	// The windows fixture intentionally omits sysctl, so the Linux rules skip
	// — asserted by the exact expectation below. The shared want list is what
	// TestEveryHostRuleIsCoveredByAFixture checks new rules against.
	want := windowsWant
	got := idsFor(runFixture(t, "windows-vulnerable.yaml", hostTemplates(t), nil))
	assertSetsEqual(t, "windows-vulnerable", got, want)
}

var windowsWant = []string{
	"host-defender-realtime-off",
	"host-defender-tamper-protection-off",
	"host-defender-whole-drive-exclusion",
	"host-defender-developer-dirs-exclusion",
	"host-firewall-profile-off",
	"host-rdp-without-nla",
	"host-rdp-nondefault-port",
	"host-rdp-enabled",
	"host-smb1-enabled",
	"host-lsa-not-protected",
	"host-lsa-wdigest-plaintext",
	"host-uac-disabled",
	"host-uac-prompt-suppressed",
	"host-bitlocker-os-volume-off",
	"host-update-auto-discovery-off",
	"host-guest-account-active",
	"host-administrator-account-active",
	"host-blank-passwords-usable",
	"host-password-minimum-too-short",
	"host-password-max-age-unlimited",
	"host-autorun-in-temp",
	"host-autorun-in-appdata",
	"host-service-unquoted-path",
	"host-service-binaries-in-user-writable-path",
	"host-listener-on-wildcard",
}

// The false-positive guard for the host audit: a hardened machine answers
// many of the same keys with safe values, and nothing may fire.
func TestWindowsCleanFixture(t *testing.T) {
	got := runFixture(t, "windows-clean.yaml", hostTemplates(t), nil)
	if len(got) != 0 {
		for _, f := range got {
			t.Errorf("false positive on the hardened machine: %s", f.TemplateID)
		}
		t.Fatalf("expected zero findings, got %d", len(got))
	}
}

// The Linux parity subset, same two directions.
func TestLinuxVulnerableFixture(t *testing.T) {
	want := linuxWant
	got := idsFor(runFixture(t, "linux-vulnerable.yaml", hostTemplates(t), nil))
	assertSetsEqual(t, "linux-vulnerable", got, want)
}

var linuxWant = []string{
	"host-lin-ip-forward",
	"host-lin-aslr-off",
	"host-lin-kernel-pointers-exposed",
	"host-lin-dmesg-readable",
	"host-lin-unprivileged-bpf",
	"host-lin-unprivileged-userns",
	"host-lin-ptrace-unrestricted",
}

// A host rule with no fixture is a rule nobody has checked, exactly like a
// file rule with no case in the vulnerable tree. Every rule shipped must be
// expected in one of the two fixtures — otherwise it is untested.
func TestEveryHostRuleIsCoveredByAFixture(t *testing.T) {
	expected := map[string]bool{}
	for _, id := range append(append([]string{}, windowsWant...), linuxWant...) {
		expected[id] = true
	}
	for _, tpl := range hostTemplates(t).Templates {
		if !expected[tpl.ID] {
			t.Errorf("%s never fires — add it to a fixture expectation in testdata/host (%s)",
				tpl.ID, tpl.Source)
		}
	}
}

func TestLinuxCleanFixture(t *testing.T) {
	got := runFixture(t, "linux-clean.yaml", hostTemplates(t), nil)
	if len(got) != 0 {
		for _, f := range got {
			t.Errorf("false positive on the hardened machine: %s", f.TemplateID)
		}
		t.Fatalf("expected zero findings, got %d", len(got))
	}
}

// Dropping a part makes its rules skip with an explanation, and nothing
// else. This is the admin-degradation contract: an elevation-less run tells
// the user which probes it could not answer rather than reporting on
// strings it invented.
func TestDroppedPartsSkipQuietly(t *testing.T) {
	findings, skipped, err := runAll(t, "windows-vulnerable.yaml", []string{"defender", "accounts"})
	if err != nil {
		t.Fatal(err)
	}
	fired := map[string]bool{}
	for _, f := range findings {
		fired[f.TemplateID] = true
	}
	for _, id := range []string{
		"host-defender-realtime-off", "host-defender-tamper-protection-off",
		"host-defender-whole-drive-exclusion", "host-defender-developer-dirs-exclusion",
		"host-guest-account-active", "host-administrator-account-active",
		"host-blank-passwords-usable", "host-password-minimum-too-short",
		"host-password-max-age-unlimited",
	} {
		if fired[id] {
			t.Errorf("%s fired despite its probe being unavailable", id)
		}
	}
	labels := map[string]bool{}
	for _, s := range skipped {
		labels[s.Part] = true
	}
	for _, part := range []string{"defender", "accounts"} {
		if !labels[part] {
			t.Errorf("the skipped list does not mention %q: %v", part, skipped)
		}
	}
	// Everything else still ran.
	if got := idsFor(findings); len(got) < 10 {
		t.Errorf("expected the rest of the audit to still run, got %d findings", len(findings))
	}
}

// runAll is runFixture with the skip list returned, for tests that drive
// the drop list themselves.
func runAll(t *testing.T, name string, drop []string) ([]engine.Finding, []Skipped, error) {
	t.Helper()
	hostSet := hostTemplates(t)
	parts, err := LoadFixture(filepath.Join("..", "..", "testdata", "host", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	for _, part := range drop {
		delete(parts, part)
	}
	f, _, skipped, err := Run(context.Background(), hostSet, nil, Options{
		Probers: probersFrom(parts),
	})
	return f, skipped, err
}

// PowerShell history is ordinary text, so the secret rules from the file
// library run over it — the same credential scan you get from `history`.
func TestHistorySecrets(t *testing.T) {
	secretSet := builtin(t).OfKind(template.KindFile).Filter("", nil, []string{"secret"}, nil)
	if secretSet.Len() == 0 {
		t.Fatal("no secret templates loaded")
	}

	parts, err := LoadFixture(filepath.Join("..", "..", "testdata", "host", "ps-history.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	findings, _, _, err := Run(context.Background(), hostTemplates(t), secretSet, Options{
		Probers: probersFrom(parts),
	})
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, f := range findings {
		if f.TemplateID == "aws-access-key-id" {
			found = true
			if f.Part != "history" {
				t.Errorf("history finding carries part %q", f.Part)
			}
			if !strings.Contains(f.File, "history") {
				t.Errorf("history finding names file %q", f.File)
			}
		}
	}
	if !found {
		t.Errorf("the access key in the fixture history was not reported: %v", idsFor(findings))
	}
}

func TestHistoryCleanProducesNothing(t *testing.T) {
	secretSet := builtin(t).OfKind(template.KindFile).Filter("", nil, []string{"secret"}, nil)
	parts, err := LoadFixture(filepath.Join("..", "..", "testdata", "host", "ps-history-clean.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	findings, _, _, err := Run(context.Background(), hostTemplates(t), secretSet, Options{Probers: probersFrom(parts)})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Part == "history" {
			t.Errorf("false positive in history: %s", f.TemplateID)
		}
	}
}

// Every host rule must say where its fact came from, so the reader can go
// check the machine themselves.
func TestHostFindingsCarryTheirPart(t *testing.T) {
	findings := runFixture(t, "windows-vulnerable.yaml", hostTemplates(t), nil)
	for _, f := range findings {
		if f.Part == "" {
			t.Errorf("%s has no part named", f.TemplateID)
		}
		if f.Line == 0 && f.Match == "" {
			t.Errorf("%s points at nothing: no line and no matched fact", f.TemplateID)
		}
	}
}
