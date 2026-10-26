package report

import (
	"bytes"
	"html"
	"strings"
	"testing"

	"github.com/nasafuriy/qalqon/internal/compliance"
	"github.com/nasafuriy/qalqon/internal/engine"
)

func sampleResult() compliance.Result {
	return compliance.Result{
		ID: "demo", Title: "Demo & Benchmark", Score: 66, Passed: 2, Failed: 1, Reviewed: 1,
		Controls: []compliance.Assessed{
			{ID: "C-fail", Title: "the failing <one>", Rules: []string{"rule-a"}, Status: compliance.Fail,
				Findings: []engine.Finding{{
					TemplateID: "rule-a", Name: "A rule", File: "src/main?x=1.conf", Line: 7,
				}}},
			{ID: "C-pass", Title: "the passing one", Rules: []string{"rule-b"}, Status: compliance.Pass},
			{ID: "C-review", Title: "the reviewed one", Rules: []string{"rule-c"}, Status: compliance.Review,
				Reason: "no file in this tree matches"},
		},
	}
}

func TestHTMLGroupsTheThreeStatusesAndEscapesData(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	body := buf.String()

	for _, want := range []string{
		"Demo &amp; Benchmark",
		"Not supporting the requirement",
		"Supporting the requirement",
		"Requires review outside this scan",
		"66%",
		html.EscapeString("src/main?x=1.conf") + ":7",
		"the failing &lt;one&gt;",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("HTML missing %q", want)
		}
	}

	// A finding never becomes markup.
	if strings.Count(body, "the failing <one>") != 0 {
		t.Error("unescaped control title in HTML")
	}

	// Empty status groups collapse; there is nothing to show them.
	if strings.Contains(body, ">0 · <") {
		t.Error("an empty status group section is printed")
	}
}

func TestTextSumsUpWithLocationsAndRepairHints(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleResult())
	out := buf.String()

	for _, want := range []string{
		"compliance · Demo & Benchmark",
		"score 66% — 2 pass, 1 fail, 1 review",
		"FAIL  C-fail",
		"PASS  C-pass",
		"REVIEW  C-review",
		"rule-a → src/main?x=1.conf:7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text missing %q:\n%s", want, out)
		}
	}
	// PASS and REVIEW controls carry no finding dump.
	if strings.Count(out, "rule-a →") != 1 {
		t.Errorf("the failure list is not confined to the failing control:\n%s", out)
	}
}

func TestTextUsesTheIDWhenNoTitleIsSet(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, compliance.Result{ID: "bare", Score: 100, Passed: 1,
		Controls: []compliance.Assessed{{ID: "C1", Title: "x", Rules: []string{"r"}, Status: compliance.Pass}}})
	if !strings.Contains(buf.String(), "compliance · bare") {
		t.Errorf("fallback to the id is missing:\n%s", buf.String())
	}
}

func TestTextHandlesAnEmptyTree(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, compliance.Result{ID: "demo", Title: "t", Score: -1,
		Controls: []compliance.Assessed{{ID: "C1", Title: "x", Rules: []string{"r"}, Status: compliance.Review}}})
	if !strings.Contains(buf.String(), "nothing in this tree applies") {
		t.Errorf("empty-tree summary missing:\n%s", buf.String())
	}
}
