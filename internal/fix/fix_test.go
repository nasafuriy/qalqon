package fix

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nasafuriy/qalqon/internal/template"
)

// The helpers build a tiny validated template set per scenario, the way a
// real set arrives: matchers that describe the file and a fix that claims to
// end the situation the matcher describes.
func build(t *testing.T, tpl template.Template) *template.Set {
	t.Helper()
	if err := tpl.Validate(); err != nil {
		t.Fatalf("test template does not validate: %v", err)
	}
	return &template.Set{Templates: []*template.Template{&tpl}}
}

func replaceSet(t *testing.T) *template.Set {
	t.Helper()
	return build(t, template.Template{
		ID:   "demo-debug-flag",
		Type: template.KindFile,
		Info: template.Info{
			Name: "Debug left on", Severity: template.SeverityMedium,
			Description: "test", Remediation: "test", Tags: []string{"demo"},
		},
		Files: []string{"app.conf"},
		Matchers: []template.Matcher{
			{Type: template.MatchRegex, Patterns: []string{`(?im)^\s*debug\s+on\b`}},
		},
		Fix: &template.Fix{Op: template.FixReplace, Find: `(?im)^([ \t]*)debug\s+on\b[^\n]*$`, Replace: "${1}debug off"},
	})
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDryRunShowsADiffAndWritesNothing(t *testing.T) {
	const (
		before = "listen 80\ndebug on\n"
	)
	root := writeTree(t, map[string]string{"app.conf": before})

	set := replaceSet(t)
	results := Collect(New(Options{Root: root}).Run(set, []Target{{File: "app.conf", TemplateID: "demo-debug-flag"}}))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Status != StatusDryRun {
		t.Fatalf("want %q, got %q", StatusDryRun, r.Status)
	}
	if !strings.Contains(r.Diff, "-debug on") || !strings.Contains(r.Diff, "+debug off") {
		t.Errorf("diff does not show the change:\n%s", r.Diff)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "app.conf")); string(got) != before {
		t.Errorf("dry run wrote to disk: %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, ".qalqon-backups")); !os.IsNotExist(err) {
		t.Errorf("dry run created a backup directory: %v", err)
	}
}

func TestApplyWritesTheFixBacksUpAndVerifies(t *testing.T) {
	const before = "listen 80\ndebug on\n"
	root := writeTree(t, map[string]string{"app.conf": before})
	set := replaceSet(t)

	results := Collect(New(Options{Root: root, Apply: true}).Run(set,
		[]Target{{File: "app.conf", TemplateID: "demo-debug-flag"}}))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Status != StatusApplied {
		t.Fatalf("want %q, got %q (%s)", StatusApplied, r.Status, r.Reason)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "app.conf")); string(got) != "listen 80\ndebug off\n" {
		t.Errorf("applied content is %q", got)
	}
	backup, err := readBackup(t, root, "app.conf")
	if err != nil {
		t.Fatalf("backup is missing: %v", err)
	}
	if string(backup) != before {
		t.Errorf("backup holds %q, not the original", backup)
	}
}

func TestApplyRollsBackWhenTheRuleStillFires(t *testing.T) {
	// The fix inserts the wrong text: the rule looks for the *absence* of
	// strict-transport-security, so an unrelated line does not silence it.
	set := build(t, template.Template{
		ID:   "demo-missing-hsts",
		Type: template.KindFile,
		Info: template.Info{
			Name: "No HSTS", Severity: template.SeverityMedium,
			Description: "test", Remediation: "test", Tags: []string{"demo"},
		},
		Files: []string{"app.conf"},
		Matchers: []template.Matcher{
			{Type: template.MatchAbsent, Patterns: []string{`(?i)Strict-Transport-Security`}},
		},
		Fix: &template.Fix{Op: template.FixInsertAfter, Find: `(?im)^[ \t]*listen[ \t]+`, Replace: "add_header Wrong-Header always;"},
	})

	const before = "listen 80 ssl;\n"
	root := writeTree(t, map[string]string{"app.conf": before})

	results := Collect(New(Options{Root: root, Apply: true}).Run(set,
		[]Target{{File: "app.conf", TemplateID: "demo-missing-hsts"}}))
	r := results[0]
	if r.Status != StatusRolledBack {
		t.Fatalf("want %q, got %q (%s)", StatusRolledBack, r.Status, r.Reason)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "app.conf")); string(got) != before {
		t.Errorf("rollback left %q on disk", got)
	}
}

func TestPatchThatNoLongerMatchesIsSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{"app.conf": "listen 80\ndebug off\n"})
	set := replaceSet(t)

	results := Collect(New(Options{Root: root}).Run(set, []Target{{File: "app.conf", TemplateID: "demo-debug-flag"}}))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Status != StatusSkipped || results[0].Reason != "the fix pattern no longer matches this content" {
		t.Errorf("status %q reason %q", results[0].Status, results[0].Reason)
	}
}

// Windows files reach the fix engine as CRLF bytes. The patch folds them,
// writes them back folded, and re-encodes — a Windows file must still be a
// Windows file afterwards.
func TestCRLFEndingsSurviveAnApply(t *testing.T) {
	const before = "listen 80\r\ndebug on\r\n"
	root := writeTree(t, map[string]string{"app.conf": before})
	set := replaceSet(t)

	results := Collect(New(Options{Root: root, Apply: true}).Run(set,
		[]Target{{File: "app.conf", TemplateID: "demo-debug-flag"}}))
	if results[0].Status != StatusApplied {
		t.Fatalf("status %q (%s)", results[0].Status, results[0].Reason)
	}
	got, _ := os.ReadFile(filepath.Join(root, "app.conf"))
	if !bytes.Contains(got, []byte("\r\n")) {
		t.Errorf("CRLF endings were not preserved: %q", got)
	}
	if bytes.Contains(got, []byte("debug on")) {
		t.Errorf("the fix did not land: %q", got)
	}
}

func TestBinaryAndOversizedAndUnreachableTargetsAreRefused(t *testing.T) {
	set := replaceSet(t)

	root := writeTree(t, map[string]string{"binary.env": "\x00\x01\x02secret\x00"})
	oversized := writeTree(t, map[string]string{"big.env": strings.Repeat("x\n", 64)})

	for _, tc := range []struct {
		name   string
		opts   Options
		target Target
		reason string
	}{
		{"binary", Options{Root: root}, Target{File: "binary.env", TemplateID: "demo-debug-flag"}, "binary file"},
		{"oversized", Options{Root: oversized, MaxFileSize: 8}, Target{File: "big.env", TemplateID: "demo-debug-flag"}, "larger than the fix size cap"},
		{"escape", Options{Root: root}, Target{File: "../outside.conf", TemplateID: "demo-debug-flag"}, "refusing to write outside the scan root"},
	} {
		results := Collect(New(tc.opts).Run(set, []Target{tc.target}))
		if len(results) != 1 || results[0].Status != StatusSkipped || !strings.Contains(results[0].Reason, tc.reason) {
			for _, r := range results {
				t.Errorf("%s: status %q reason %q, want skip because %q", tc.name, r.Status, r.Reason, tc.reason)
			}
		}
	}
}

// A run stamps exactly one backup directory. The timestamp is the engine's
// private business, so tests reach the original bytes by walking it.
func readBackup(t *testing.T, root, name string) ([]byte, error) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, ".qalqon-backups"))
	if err != nil {
		return nil, err
	}
	if len(entries) != 1 {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(filepath.Join(root, ".qalqon-backups", entries[0].Name(), name))
}

func TestTargetsForTheSameFixCollapseToOne(t *testing.T) {
	root := writeTree(t, map[string]string{"app.conf": "debug on\n"})
	set := replaceSet(t)

	dup := []Target{
		{File: "app.conf", TemplateID: "demo-debug-flag"},
		{File: "app.conf", TemplateID: "demo-debug-flag"},
	}
	results := Collect(New(Options{Root: root}).Run(set, dup))
	if len(results) != 1 {
		t.Fatalf("want 1 deduped result, got %d", len(results))
	}
}

func TestTargetForARuleWithNoFixIsSilentlyDropped(t *testing.T) {
	root := writeTree(t, map[string]string{"app.conf": "debug on\n"})
	set := build(t, template.Template{
		ID: "demo-no-fix", Type: template.KindFile,
		Info:     template.Info{Name: "n", Severity: template.SeverityLow, Description: "d", Remediation: "r", Tags: []string{"demo"}},
		Files:    []string{"app.conf"},
		Matchers: []template.Matcher{{Type: template.MatchRegex, Patterns: []string{`debug`}}},
	})
	results := Collect(New(Options{Root: root}).Run(set, []Target{{File: "app.conf", TemplateID: "demo-no-fix"}}))
	if len(results) != 0 {
		t.Fatalf("no-fix rules must produce no result, got %v", results)
	}
}

// The inserted line takes the matched line's indentation, so the diff a user
// reads looks like it was written by someone who edits the file for a living.
func TestInsertsInheritTheMatchedLineIndentation(t *testing.T) {
	f := &template.Fix{Op: template.FixInsertAfter, Find: `(?m)^[ \t]*listen\b`, Replace: "server_tokens off;"}
	patched, err := Patch(f, []byte("server {\n    listen 80;\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := "server {\n    listen 80;\n    server_tokens off;\n}\n"
	if string(patched) != want {
		t.Errorf("got %q, want %q", patched, want)
	}
}
