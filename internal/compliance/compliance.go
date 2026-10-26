// Package compliance scores a scan against a published security framework.
//
// A framework is a YAML list of controls, each anchored to one or more
// qalqon rule ids. Nothing here interprets the rules again: the evaluator
// takes findings an ordinary scan already produced and maps them onto
// controls. A control's status is deliberately three-valued:
//
//	FAIL   — at least one of its rules fired on this tree.
//	PASS   — every rule ran against something it applies to and stayed quiet.
//	REVIEW — the tree contains nothing the control's rules apply to, so
//	         the scan honestly cannot answer for it. A reviewed control is
//	         excluded from the score: a repo with no nginx in it is not
//	         rewarded for not having nginx.
package compliance

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/template"
	"gopkg.in/yaml.v3"
)

// Status is the three-valued outcome of one control.
type Status string

const (
	Pass   Status = "pass"
	Fail   Status = "fail"
	Review Status = "review"
)

// Framework is one mapping document.
type Framework struct {
	ID       string    `yaml:"framework" json:"id"`
	Title    string    `yaml:"title" json:"title"`
	Controls []Control `yaml:"controls" json:"controls"`
	Source   string    `yaml:"-" json:"-"`
}

// Control maps part of a framework onto qalqon rules.
type Control struct {
	ID    string   `yaml:"id" json:"id"`
	Title string   `yaml:"title" json:"title"`
	Rules []string `yaml:"rules" json:"rules"`
}

// Assessed is one control scored against one tree.
type Assessed struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Rules    []string         `json:"rules"`
	Status   Status           `json:"status"`
	Reason   string           `json:"reason,omitempty"` // why REVIEW, when it is one
	Findings []engine.Finding `json:"findings,omitempty"`
}

// Result is the assessment of one framework against one tree.
type Result struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Controls []Assessed `json:"controls"`
	Passed   int        `json:"passed"`
	Failed   int        `json:"failed"`
	Reviewed int        `json:"reviewed"`
	// Score is pass/(pass+fail) as an integer percent. Reviewed controls
	// are not counted: absence of evidence is not evidence of compliance.
	// -1 when no control was applicable.
	Score int `json:"score"`
}

// Load reads every framework document under root in fsys, validating the
// shape. A malformed document reports its own error and is skipped, so one
// broken file never blanks the whole library.
func Load(fsys fs.FS) ([]Framework, []error) {
	var (
		out  []Framework
		errs []error
	)
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && d.Name() != "." {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		f, readErr := fsys.Open(p)
		if readErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, readErr))
			return nil
		}
		defer f.Close()

		dec := yaml.NewDecoder(f)
		for index := 1; ; index++ {
			var fw Framework
			decErr := dec.Decode(&fw)
			if decErr != nil {
				if decErr.Error() != "EOF" {
					errs = append(errs, fmt.Errorf("%s (document %d): %w", p, index, decErr))
				}
				break
			}
			if fw.ID == "" && len(fw.Controls) == 0 {
				continue
			}
			fw.Source = p
			if vErr := validate(fw); vErr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p, vErr))
				continue
			}
			if dup := seen(out, fw.ID); dup != "" {
				errs = append(errs, fmt.Errorf("%s: duplicate framework id %q (already in %s)", p, fw.ID, dup))
				continue
			}
			out = append(out, fw)
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, errs
}

func seen(fw []Framework, id string) string {
	for _, f := range fw {
		if f.ID == id {
			return f.Source
		}
	}
	return ""
}

// validate checks the document is complete enough to be evaluated: every
// control needs an id, a title and at least one mapped rule.
func validate(fw Framework) error {
	if fw.ID == "" {
		return fmt.Errorf("missing framework id")
	}
	if fw.Title == "" {
		return fmt.Errorf("%s: missing title", fw.ID)
	}
	if len(fw.Controls) == 0 {
		return fmt.Errorf("%s: needs at least one control", fw.ID)
	}
	ids := map[string]bool{}
	for i, c := range fw.Controls {
		if c.ID == "" {
			return fmt.Errorf("%s: control %d has no id", fw.ID, i+1)
		}
		if ids[c.ID] {
			return fmt.Errorf("%s: duplicate control id %q", fw.ID, c.ID)
		}
		ids[c.ID] = true
		if c.Title == "" {
			return fmt.Errorf("%s: control %q has no title", fw.ID, c.ID)
		}
		if len(c.Rules) == 0 {
			return fmt.Errorf("%s: control %q maps to no qalqon rules", fw.ID, c.ID)
		}
	}
	return nil
}

// ValidateAgainst checks every mapped rule id exists in the template set.
// Called by the report command so a mapping that names a rule the library
// removed fails loudly rather than scoring an impossible control.
func ValidateAgainst(fw Framework, set *template.Set) error {
	known := map[string]bool{}
	for _, tpl := range set.Templates {
		known[tpl.ID] = true
	}
	var unknown []string
	for _, c := range fw.Controls {
		for _, r := range c.Rules {
			if !known[r] {
				unknown = append(unknown, r)
			}
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	return fmt.Errorf("%s maps rules that are not in the library: %s", fw.ID, strings.Join(unknown, ", "))
}

// Evaluate scores one framework against the findings a scan produced. Files
// is the path list WalkFiles returned — the set of paths the scan walked,
// used to tell an unused control from a satisfied one.
func Evaluate(fw Framework, set *template.Set, findings []engine.Finding, files []string) Result {
	byRule := map[string][]engine.Finding{}
	for _, f := range findings {
		byRule[f.TemplateID] = append(byRule[f.TemplateID], f)
	}

	// Group the walked paths per template once: a template's file globs
	// answer "would this rule have considered this tree at all?".
	coveredBy := make([][]string, len(fw.Controls))
	for i, c := range fw.Controls {
		for _, rule := range c.Rules {
			tpl := find(set, rule)
			if tpl == nil {
				continue
			}
			for _, p := range files {
				if tpl.AppliesTo(p, filepath.Base(p)) {
					coveredBy[i] = append(coveredBy[i], p)
					break
				}
			}
		}
	}

	res := Result{ID: fw.ID, Title: fw.Title}
	for i, c := range fw.Controls {
		a := Assessed{ID: c.ID, Title: c.Title, Rules: c.Rules}
		var failures []engine.Finding
		for _, rule := range c.Rules {
			failures = append(failures, byRule[rule]...)
		}
		a.Findings = failures

		switch covered := len(coveredBy[i]); {
		case len(failures) > 0:
			a.Status = Fail
			res.Failed++
		case covered == 0:
			a.Status = Review
			res.Reviewed++
			a.Reason = "no file in this tree matches the rules this control maps to"
		case covered < len(c.Rules):
			a.Status = Review
			res.Reviewed++
			a.Reason = "only " + itoa(covered) + " of " + itoa(len(c.Rules)) +
				" rules had an applicable file here; the remaining subjects are absent"
		default:
			a.Status = Pass
			res.Passed++
		}
		res.Controls = append(res.Controls, a)
	}

	if res.Passed+res.Failed > 0 {
		res.Score = 100 * res.Passed / (res.Passed + res.Failed)
	} else {
		res.Score = -1
	}
	return res
}

func find(set *template.Set, id string) *template.Template {
	for _, tpl := range set.Templates {
		if tpl.ID == id {
			return tpl
		}
	}
	return nil
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
