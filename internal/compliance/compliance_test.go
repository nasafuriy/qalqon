package compliance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/template"
)

func testSet(t *testing.T) *template.Set {
	t.Helper()

	// Three rules that look at three different file kinds, the way the real
	// library spans a tree.
	make := func(id, file, pattern string) *template.Template {
		tpl := template.Template{
			ID: id, Type: template.KindFile,
			Info:     template.Info{Name: id, Severity: template.SeverityHigh, Description: "d", Remediation: "r", Tags: []string{"demo"}},
			Files:    []string{file},
			Matchers: []template.Matcher{{Type: template.MatchRegex, Patterns: []string{pattern}}},
		}
		if err := tpl.Validate(); err != nil {
			t.Fatalf("%s does not validate: %v", id, err)
		}
		return &tpl
	}
	return &template.Set{Templates: []*template.Template{
		make("demo-nginx-version", "nginx.conf", `(?m)^\s*server_tokens\s+on\s*;`),
		make("demo-sh-root", "*.sh", `#!\s*/bin/sh`),
		make("demo-makefile", "makefile", `(?m)^\.PHONY:`),
	}}
}

func fwFile(doc string) fstest.MapFS {
	return fstest.MapFS{"fw.yaml": &fstest.MapFile{Data: []byte(doc)}}
}

func TestLoadRejectsIncompleteDocuments(t *testing.T) {
	for _, doc := range []string{
		`framework: f`,                                               // no title, no controls
		"framework: f\ntitle: T\ncontrols: []",                       // no controls
		"framework: f\ntitle: T\ncontrols:\n  - id: A",               // no title, no rules
		"framework: f\ntitle: T\ncontrols:\n  - id: A\n    title: T", // no rules
		"framework: f\ntitle: T\ncontrols:\n  - id: A\n    title: T\n    rules: [x]\n  - id: A\n    title: T2\n    rules: [y]", // duplicate control
	} {
		frames, errs := Load(fwFile(doc))
		if len(frames) != 0 || len(errs) == 0 {
			t.Errorf("doc %q loaded %d frameworks with %d errors", doc, len(frames), len(errs))
		}
	}
}

func TestLoadAcceptsGoodDocuments(t *testing.T) {
	frames, errs := Load(fwFile(`framework: demo
title: Demo benchmark
controls:
  - id: C1
    title: First control
    rules: [demo-nginx-version]
`))
	if len(frames) != 1 {
		t.Fatalf("want 1 framework ... errs: %v", errs)
	}
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if frames[0].ID != "demo" {
		t.Fatalf("framework not loaded as expected: %+v", frames[0])
	}
}

func TestEvaluateFailsPassesAndReviews(t *testing.T) {
	set := testSet(t)
	fw := Framework{
		ID: "demo", Title: "Demo benchmark",
		Controls: []Control{
			{ID: "C1", Title: "nginx quiet", Rules: []string{"demo-nginx-version"}},
			{ID: "C2", Title: "shell quiet", Rules: []string{"demo-sh-root"}},
			{ID: "C3", Title: "half covered", Rules: []string{"demo-sh-root", "demo-makefile"}},
		},
	}

	findings := []engine.Finding{{TemplateID: "demo-nginx-version", File: "nginx.conf", Line: 3}}
	files := []string{"nginx.conf"} // no shell script or makefile walked

	res := Evaluate(fw, set, findings, files)

	if res.Controls[0].Status != Fail {
		t.Errorf("C1: status %q, want fail", res.Controls[0].Status)
	}
	if res.Controls[1].Status != Review {
		t.Errorf("C2: status %q, want review — no *.sh was walked", res.Controls[1].Status)
	}
	if res.Controls[2].Status != Review {
		t.Errorf("C3: status %q, want review — one of two rules uncovered", res.Controls[2].Status)
	}
	if res.Failed != 1 || res.Reviewed != 2 || res.Passed != 0 {
		t.Errorf("counts %d/%d/%d", res.Passed, res.Failed, res.Reviewed)
	}
	if len(res.Controls[0].Findings) != 1 || res.Controls[0].Findings[0].Line != 3 {
		t.Errorf("failures did not reach the control: %+v", res.Controls[0])
	}

	// Now the shell script is in the tree: C2 stands and C3 is still half
	// uncovered, so the score is pass(C2) over fail(C1) — fifty percent.
	res = Evaluate(fw, set, findings, []string{"nginx.conf", "build.sh"})
	if res.Controls[1].Status != Pass {
		t.Errorf("C2 %q, want pass", res.Controls[1].Status)
	}
	if res.Controls[2].Status != Review {
		t.Errorf("C3 %q, want review — makefile still absent", res.Controls[2].Status)
	}
	if res.Score != 50 {
		t.Errorf("score %d, want 50", res.Score)
	}

	// With the makefile present too, everything C3 maps to has run.
	res = Evaluate(fw, set, findings, []string{"nginx.conf", "build.sh", "makefile"})
	if res.Controls[2].Status != Pass || res.Score != 66 {
		t.Errorf("C3 %q score %d, want pass and 66", res.Controls[2].Status, res.Score)
	}
}

func TestScoreExcludesReviewedControls(t *testing.T) {
	set := testSet(t)
	fw := Framework{ID: "d", Title: "t", Controls: []Control{
		{ID: "C1", Title: "pass", Rules: []string{"demo-nginx-version"}},
		{ID: "C2", Title: "not applicable", Rules: []string{"demo-sh-root"}},
	}}
	res := Evaluate(fw, set, nil, []string{"nginx.conf", "other.txt"})
	if res.Score != 100 {
		t.Errorf("score %d with a review beside it, want 100", res.Score)
	}

	res = Evaluate(fw, set, nil, nil)
	if res.Score != -1 || res.Controls[0].Status != Review {
		t.Errorf("empty tree: score %d, want -1 and review", res.Score)
	}
}

func TestValidateAgainstNamesUnknownRules(t *testing.T) {
	fw := Framework{ID: "f", Title: "t", Controls: []Control{
		{ID: "C1", Title: "x", Rules: []string{"demo-nginx-version", "no-such-rule"}},
	}}
	err := ValidateAgainst(fw, testSet(t))
	if err == nil || !strings.Contains(err.Error(), "no-such-rule") {
		t.Errorf("err = %v, want it to name the unknown rule", err)
	}
	if err := ValidateAgainst(fw, &template.Set{Templates: []*template.Template{
		mustTpl(t, "demo-nginx-version"),
		mustTpl(t, "no-such-rule"),
	}}); err != nil {
		t.Errorf("all rules known: %v", err)
	}
}

func mustTpl(t *testing.T, id string) *template.Template {
	t.Helper()
	tpl := template.Template{
		ID: id, Type: template.KindFile,
		Info:     template.Info{Name: id, Severity: template.SeverityLow, Description: "d", Remediation: "r", Tags: []string{"t"}},
		Files:    []string{"*.conf"},
		Matchers: []template.Matcher{{Type: template.MatchRegex, Patterns: []string{"x"}}},
	}
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}
	return &tpl
}

func TestJSONResultMarshalsFindings(t *testing.T) {
	res := Result{ID: "d", Title: "t", Score: 0, Controls: []Assessed{
		{ID: "C1", Title: "t", Rules: []string{"r"}, Status: Fail,
			Findings: []engine.Finding{{TemplateID: "r", File: "a.conf", Line: 2}}},
	}}
	body, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, frag := range []string{`"status":"fail"`, `"template_id":"r"`, `"score":0`, `"line":2`} {
		if !bytes.Contains(body, []byte(frag)) {
			t.Errorf("JSON missing %s:\n%s", frag, body)
		}
	}
}
