package qalqon_test

import (
	"context"
	"sort"
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
		t.Fatalf("built-in templates failed to load: %v", err)
	}
	if set.Len() == 0 {
		t.Fatal("no built-in templates were loaded")
	}
	return set
}

func scan(t *testing.T, root string) []engine.Finding {
	t.Helper()
	findings, _, err := engine.Run(context.Background(), builtin(t), engine.Options{Root: root})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	return findings
}

// byFile groups finding ids per file so expectations read like the fixture tree.
func byFile(findings []engine.Finding) map[string][]string {
	out := map[string][]string{}
	for _, f := range findings {
		out[f.File] = append(out[f.File], f.TemplateID)
	}
	for file, ids := range out {
		sort.Strings(ids)
		out[file] = dedupe(ids)
	}
	return out
}

func dedupe(in []string) []string {
	var out []string
	for i, v := range in {
		if i == 0 || in[i-1] != v {
			out = append(out, v)
		}
	}
	return out
}

func TestBuiltinTemplatesLoadAndValidate(t *testing.T) {
	set := builtin(t)
	t.Logf("%d built-in templates", set.Len())

	seen := map[string]bool{}
	for _, tpl := range set.Templates {
		if seen[tpl.ID] {
			t.Errorf("duplicate template id %q", tpl.ID)
		}
		seen[tpl.ID] = true

		if tpl.Info.Description == "" {
			t.Errorf("%s: description is required — it is what the user reads", tpl.ID)
		}
		if tpl.Info.Remediation == "" {
			t.Errorf("%s: remediation is required — a finding without a fix wastes the reader's time", tpl.ID)
		}
		if len(tpl.Info.Tags) == 0 {
			t.Errorf("%s: at least one tag is required so -tags can select it", tpl.ID)
		}
	}
}

// The clean fixtures are the false-positive guard. A scanner that cries wolf
// gets switched off, so this test matters more than the detection one.
func TestCleanFixturesProduceNoFindings(t *testing.T) {
	findings := scan(t, "testdata/clean")
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("false positive: %s:%d %s (%s)", f.File, f.Line, f.TemplateID, f.Name)
		}
		t.Fatalf("expected a clean tree, got %d findings", len(findings))
	}
}

func TestVulnerableFixturesAreDetected(t *testing.T) {
	want := map[string][]string{
		"Dockerfile": {
			"docker-add-remote-url",
			"docker-apt-no-version-pin",
			"docker-curl-pipe-shell",
			"docker-latest-tag",
			"docker-missing-user",
			"docker-secret-in-layer",
		},
		"docker-compose.yml": {
			"compose-docker-socket-mount",
			"compose-hardcoded-password",
			"compose-host-network",
			"compose-privileged-container",
			"compose-restart-always-no-healthcheck",
		},
		"deployment.yaml": {
			"k8s-allow-privilege-escalation",
			"k8s-container-runs-as-root",
			"k8s-host-namespace",
			"k8s-host-path-volume",
			"k8s-image-latest-tag",
			"k8s-missing-resource-limits",
			"k8s-privileged-container",
		},
		"nginx.conf": {
			"nginx-missing-hsts",
			"nginx-proxy-missing-host-header",
			"nginx-server-tokens-on",
			"nginx-weak-tls-protocols",
		},
		".github/workflows/bad.yml": {
			"actions-excessive-token-permissions",
			"actions-pull-request-target-checkout",
			"actions-script-injection",
			"actions-unpinned-version",
		},
		".env": {
			"aws-access-key-id",
			"env-file-committed",
			"hardcoded-credential-assignment",
		},
		"sshd_config": {
			"sshd-empty-passwords",
			"sshd-password-authentication",
			"sshd-permit-root-login",
			"sshd-protocol-1",
			"sshd-weak-ciphers",
			"sshd-x11-forwarding",
		},
		"main.tf": {
			"terraform-hardcoded-credential",
			"terraform-plaintext-state-backend",
			"terraform-public-storage-bucket",
			"terraform-security-group-open-to-world",
			"terraform-unencrypted-storage",
		},
		"httpd.conf": {
			"apache-allow-override-all",
			"apache-directory-listing",
			"apache-server-tokens-verbose",
			"apache-trace-method",
			"apache-weak-ssl-protocols",
		},
		"app.service": {
			"systemd-dangerous-capabilities",
			"systemd-missing-sandboxing",
			"systemd-service-runs-as-root",
		},
		"php.ini": {
			"php-allow-url-include",
			"php-dangerous-functions-enabled",
			"php-display-errors-enabled",
			"php-expose-php-enabled",
		},
	}

	got := byFile(scan(t, "testdata/vulnerable"))

	for file, expected := range want {
		actual := got[file]
		if strings.Join(actual, ",") != strings.Join(expected, ",") {
			t.Errorf("%s\n  want: %v\n  got:  %v", file, expected, actual)
		}
		delete(got, file)
	}
	for file, ids := range got {
		t.Errorf("unexpected findings in %s: %v", file, ids)
	}
}

func TestEveryFindingCarriesAPosition(t *testing.T) {
	for _, f := range scan(t, "testdata/vulnerable") {
		// "absent" rules legitimately have no line to point at.
		if f.Line == 0 && f.Match != "" {
			t.Errorf("%s in %s has a match but no line number", f.TemplateID, f.File)
		}
		if f.Line < 0 || f.Column < 0 {
			t.Errorf("%s in %s has a negative position", f.TemplateID, f.File)
		}
	}
}

func TestSeverityFilteringNarrowsTheSet(t *testing.T) {
	all := builtin(t)
	critical := all.Filter(template.SeverityCritical, nil, nil, nil)

	if critical.Len() == 0 {
		t.Fatal("expected at least one critical template")
	}
	if critical.Len() >= all.Len() {
		t.Fatalf("filtering to critical kept %d of %d templates", critical.Len(), all.Len())
	}
	for _, tpl := range critical.Templates {
		if tpl.Info.Severity != template.SeverityCritical {
			t.Errorf("%s leaked through a critical-only filter with severity %s", tpl.ID, tpl.Info.Severity)
		}
	}
}

func TestTagFilteringSelectsOneTechnology(t *testing.T) {
	set := builtin(t).Filter("", nil, []string{"nginx"}, nil)
	if set.Len() == 0 {
		t.Fatal("expected nginx templates")
	}
	for _, tpl := range set.Templates {
		found := false
		for _, tag := range tpl.Info.Tags {
			if tag == "nginx" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s has no nginx tag but survived the filter", tpl.ID)
		}
	}
}

// The rule library lives in the repository, and templates/compose.yaml matches
// the glob for a real compose file. Without a guard, scanning this project
// reports every example pattern in its own rules as a finding.
func TestRuleLibraryIsNotScannedAsConfiguration(t *testing.T) {
	findings := scan(t, "templates")
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("template file scanned as config: %s:%d %s", f.File, f.Line, f.TemplateID)
		}
		t.Fatalf("expected the rule library to be skipped, got %d findings", len(findings))
	}
}

func TestScanningASingleFileWorks(t *testing.T) {
	findings := scan(t, "testdata/vulnerable/Dockerfile")
	if len(findings) == 0 {
		t.Fatal("expected findings when pointing at one file")
	}
}
