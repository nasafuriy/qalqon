package qalqon_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nasafuriy/qalqon"
	"github.com/nasafuriy/qalqon/internal/compliance"
	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/fix"
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
		".env": {
			"aws-access-key-id",
			"connection-string-with-password",
			"env-file-committed",
			"hardcoded-credential-assignment",
			"jwt-token-committed",
			"provider-token-committed",
			"slack-webhook-committed",
			"stripe-live-key",
		},
		".github/workflows/bad.yml": {
			"actions-excessive-token-permissions",
			"actions-pull-request-target-checkout",
			"actions-script-injection",
			"actions-self-hosted-on-public-trigger",
			"actions-unpinned-version",
		},
		".github/workflows/release.yml": {
			"actions-curl-pipe-shell",
			"actions-secret-echoed",
			"actions-secrets-inherit",
			"actions-workflow-run-untrusted-checkout",
		},
		".gitlab-ci.yml": {
			"gitlab-ci-curl-pipe-shell",
			"gitlab-ci-docker-tls-disabled",
			"gitlab-ci-hardcoded-credential",
			"gitlab-ci-image-latest-tag",
			"gitlab-ci-tls-verification-disabled",
			"gitlab-ci-unpinned-remote-include",
		},
		"Caddyfile": {
			"caddy-auto-https-disabled",
			"caddy-directory-listing",
			"caddy-tls-verification-disabled",
		},
		"Chart.yaml": {
			"helm-chart-dependency-unpinned",
		},
		"Dockerfile": {
			"docker-add-remote-url",
			"docker-apt-no-version-pin",
			"docker-chmod-world-writable",
			"docker-curl-pipe-shell",
			"docker-latest-tag",
			"docker-missing-user",
			"docker-pip-no-version-pin",
			"docker-secret-in-layer",
			"docker-ssh-key-copied",
			"docker-untagged-base-image",
		},
		"ansible.cfg": {
			"ansible-host-key-checking-disabled",
		},
		"app.service": {
			"systemd-dangerous-capabilities",
			"systemd-missing-sandboxing",
			"systemd-service-runs-as-root",
		},
		"cloud.tf": {
			"terraform-azure-insecure-transfer",
			"terraform-azure-network-open-to-world",
			"terraform-database-publicly-accessible",
			"terraform-gcp-firewall-open-to-world",
			"terraform-iam-wildcard-policy",
			"terraform-module-source-unpinned",
		},
		"cloudformation.yaml": {
			"cfn-database-unencrypted",
			"cfn-hardcoded-credential",
			"cfn-iam-wildcard-policy",
			"cfn-s3-bucket-public-access",
			"cfn-security-group-open-to-world",
		},
		"crlf/nginx.conf": {
			"nginx-autoindex-enabled",
			"nginx-missing-content-type-options",
			"nginx-missing-hsts",
			"nginx-proxy-missing-host-header",
			"nginx-server-tokens-on",
			"nginx-weak-ssl-ciphers",
			"nginx-weak-tls-protocols",
		},
		"deployment.yaml": {
			"k8s-allow-privilege-escalation",
			"k8s-capabilities-not-dropped",
			"k8s-container-runs-as-root",
			"k8s-host-namespace",
			"k8s-host-path-volume",
			"k8s-image-latest-tag",
			"k8s-missing-resource-limits",
			"k8s-privileged-container",
			"k8s-service-account-token-automounted",
			"k8s-writable-root-filesystem",
		},
		"docker-compose.yml": {
			"compose-dangerous-capabilities",
			"compose-database-port-published",
			"compose-docker-socket-mount",
			"compose-hardcoded-password",
			"compose-host-network",
			"compose-host-pid-namespace",
			"compose-image-latest-tag",
			"compose-privileged-container",
			"compose-restart-always-no-healthcheck",
		},
		"envoy.yaml": {
			"envoy-admin-interface-exposed",
			"envoy-tls-verification-disabled",
			"envoy-weak-tls-version",
		},
		"haproxy.cfg": {
			"haproxy-missing-forwarded-proto",
			"haproxy-ssl-verify-none",
			"haproxy-stats-without-auth",
			"haproxy-weak-tls-version",
		},
		"httpd.conf": {
			"apache-allow-override-all",
			"apache-directory-listing",
			"apache-missing-hsts",
			"apache-server-signature-on",
			"apache-server-status-exposed",
			"apache-server-tokens-verbose",
			"apache-trace-method",
			"apache-weak-ssl-ciphers",
			"apache-weak-ssl-protocols",
		},
		"ingress.yaml": {
			"k8s-ingress-without-tls",
		},
		"main.tf": {
			"terraform-hardcoded-credential",
			"terraform-plaintext-state-backend",
			"terraform-public-storage-bucket",
			"terraform-security-group-open-to-world",
			"terraform-unencrypted-storage",
		},
		"mongod.conf": {
			"mongodb-authorization-disabled",
			"mongodb-bound-to-all-interfaces",
			"mongodb-tls-disabled",
		},
		"my.cnf": {
			"mysql-bound-to-all-interfaces",
			"mysql-local-infile-enabled",
			"mysql-plaintext-password-in-config",
			"mysql-skip-grant-tables",
		},
		"nginx.conf": {
			"nginx-autoindex-enabled",
			"nginx-missing-content-type-options",
			"nginx-missing-hsts",
			"nginx-proxy-missing-host-header",
			"nginx-server-tokens-on",
			"nginx-weak-ssl-ciphers",
			"nginx-weak-tls-protocols",
		},
		"pg_hba.conf": {
			"postgres-trust-authentication",
		},
		"php.ini": {
			"php-allow-url-fopen",
			"php-allow-url-include",
			"php-cgi-fix-pathinfo",
			"php-dangerous-functions-enabled",
			"php-display-errors-enabled",
			"php-expose-php-enabled",
			"php-session-cookie-not-httponly",
			"php-session-cookie-not-secure",
		},
		"playbook.yml": {
			"ansible-become-without-user",
			"ansible-plaintext-credential",
			"ansible-validate-certs-disabled",
		},
		"postgresql.conf": {
			"postgres-listening-on-all-interfaces",
			"postgres-ssl-disabled",
			"postgres-weak-password-encryption",
		},
		"private.pem": {
			"private-key-committed",
		},
		"rbac.yaml": {
			"k8s-cluster-admin-binding",
			"k8s-rbac-wildcard-permissions",
		},
		"redis-cache.conf": {
			"redis-default-password",
		},
		"redis.conf": {
			"redis-bound-to-all-interfaces",
			"redis-no-authentication",
			"redis-protected-mode-disabled",
		},
		"roles/web/tasks/main.yml": {
			"ansible-shell-without-changed-when",
			"ansible-world-writable-mode",
		},
		"service-account.json": {
			"gcp-service-account-key",
		},
		"sshd_config": {
			"sshd-agent-forwarding",
			"sshd-empty-passwords",
			"sshd-gateway-ports",
			"sshd-password-authentication",
			"sshd-permit-root-login",
			"sshd-permit-user-environment",
			"sshd-protocol-1",
			"sshd-strict-modes-disabled",
			"sshd-weak-ciphers",
			"sshd-x11-forwarding",
		},
		"traefik.yml": {
			"traefik-api-insecure",
			"traefik-tls-verification-disabled",
			"traefik-weak-tls-version",
		},
		"values.yaml": {
			"helm-values-hardcoded-credential",
			"helm-values-host-namespace",
			"helm-values-image-tag-latest",
			"helm-values-privileged-container",
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

// A template with no fixture is a template nobody has checked. It will still
// load, still appear in "qalqon templates", and still be wrong in a way that
// only shows up on somebody's repository.
func TestEveryFileTemplateFiresOnTheVulnerableTree(t *testing.T) {
	fired := map[string]bool{}
	for _, f := range scan(t, "testdata/vulnerable") {
		fired[f.TemplateID] = true
	}

	for _, tpl := range builtin(t).OfKind(template.KindFile).Templates {
		if !fired[tpl.ID] {
			t.Errorf("%s never fires — add a case to testdata/vulnerable (%s)", tpl.ID, tpl.Source)
		}
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

// The CRLF fixtures exist because almost every Windows checkout butts every
// scanned file with \r\n. Line endings are folded once at read time, so the
// same content with CRLF endings must produce exactly the same findings —
// and the clean CRLF fixture must stay quiet with the rest of the tree.
// A fix that leaves its rule firing is worse than no fix at all: it shows a
// diff, the user applies it, and the finding comes back on the next scan. So
// for every fixable rule that fires on the vulnerable tree, the declared fix
// is applied to the fixture in memory and the rule must go quiet. Overlapping
// rules are allowed to keep firing — each fix verifies its own finding.
func TestEveryDeclaredFixSilencesItsRule(t *testing.T) {
	byID := map[string]*template.Template{}
	for _, tpl := range builtin(t).Templates {
		byID[tpl.ID] = tpl
	}

	checked := map[string]bool{}
	for _, f := range scan(t, "testdata/vulnerable") {
		tpl := byID[f.TemplateID]
		if tpl == nil || tpl.Fix == nil || tpl.Fix.HostFix() || checked[f.TemplateID] {
			continue
		}
		checked[f.TemplateID] = true

		raw, err := os.ReadFile(filepath.Join("testdata", "vulnerable", filepath.FromSlash(f.File)))
		if err != nil {
			t.Fatalf("%s: fixture %q disappeared: %v", f.TemplateID, f.File, err)
		}
		// The scan folds CRLF at read time and the fix engine patches the
		// folded content, so the test does the same.
		content := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))

		patched, err := fix.Patch(tpl.Fix, content)
		if err != nil {
			t.Fatalf("%s: patch failed: %v", f.TemplateID, err)
		}
		if bytes.Equal(patched, content) {
			t.Errorf("%s: fix changes nothing on %s", f.TemplateID, f.File)
			continue
		}
		if tpl.MayMatch(patched) {
			if _, still := tpl.Match(patched); still {
				t.Errorf("%s: rule still matches %s after its own fix", f.TemplateID, f.File)
			}
		}
	}
}

// Rules that need a value the tool cannot invent — the real password, the
// real pinned version, the real certificate holder — deliberately carry no
// fix: a fabricated value would be a broken file, not a fix. Thirty is the
// floor of the shipped library, not a decorative number.
func TestFixLibraryCoversAtLeastThirtyFileTemplates(t *testing.T) {
	count := 0
	for _, tpl := range builtin(t).OfKind(template.KindFile).Templates {
		if tpl.Fixable() && !tpl.Fix.HostFix() {
			count++
		}
	}
	if count < 30 {
		t.Fatalf("only %d file templates declare a safe fix; the accepted library floor is 30", count)
	}
}

// Framework documents ship inside the binary, so a mapping that names a rule
// the library no longer has would score a broken check at every user.
func TestEmbeddedFrameworksResolveAgainstTheLibrary(t *testing.T) {
	fileSet := builtin(t).OfKind(template.KindFile)

	frames, errs := compliance.Load(qalqon.Compliance)
	if len(errs) != 0 {
		t.Fatalf("embedded frameworks failed to load: %v", errs)
	}
	if len(frames) < 3 {
		t.Fatalf("expected at least three embedded frameworks, got %d", len(frames))
	}
	for _, fw := range frames {
		if err := compliance.ValidateAgainst(fw, fileSet); err != nil {
			t.Errorf("%v", err)
		}
	}
}

// The scorer against the real fixture trees: the vulnerable tree must fail a
// control in every framework, and the clean tree must fail none.
func TestComplianceScoresTheFixtureTrees(t *testing.T) {
	set := builtin(t)
	fileSet := set.OfKind(template.KindFile)

	for _, root := range []string{"testdata/vulnerable", "testdata/clean"} {
		findings, _, err := engine.Run(context.Background(), fileSet, engine.Options{Root: root})
		if err != nil {
			t.Fatalf("%s: %v", root, err)
		}
		files, err := engine.WalkFiles(context.Background(), engine.Options{Root: root})
		if err != nil {
			t.Fatalf("%s: %v", root, err)
		}

		frames, _ := compliance.Load(qalqon.Compliance)
		for _, fw := range frames {
			res := compliance.Evaluate(fw, fileSet, findings, files)
			if root == "testdata/vulnerable" && res.Failed == 0 {
				t.Errorf("%s: no control failed on the vulnerable tree", fw.ID)
			}
			if root == "testdata/clean" && res.Failed > 0 {
				for _, c := range res.Controls {
					if c.Status == compliance.Fail {
						for _, f := range c.Findings {
							t.Errorf("%s: false compliance failure: %s → %s (via %s)", fw.ID, c.ID, f.Where(), f.TemplateID)
						}
					}
				}
			}
		}
	}
}

func TestCRLFContentProducesTheSameFindings(t *testing.T) {
	idsFor := func(findings []engine.Finding) map[string]bool {
		out := map[string]bool{}
		for _, f := range findings {
			out[f.TemplateID] = true
		}
		return out
	}

	lf, crlf := idsFor(scan(t, "testdata/vulnerable/nginx.conf")), idsFor(scan(t, "testdata/vulnerable/crlf/nginx.conf"))
	if len(lf) == 0 {
		t.Fatal("the LF fixture produced no findings — the test case is broken")
	}
	if len(crlf) != len(lf) {
		t.Errorf("CRLF content changed the rule count: LF %v, CRLF %v", lf, crlf)
	}
	for id := range lf {
		if !crlf[id] {
			t.Errorf("CRLF content lost the finding %q", id)
		}
	}
}
