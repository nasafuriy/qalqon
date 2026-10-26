package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/host"
	"github.com/nasafuriy/qalqon/internal/template"
)

// Report is the shape of --json output.
type Report struct {
	Tool     string           `json:"tool"`
	Version  string           `json:"version"`
	Root     string           `json:"root"`
	Findings []engine.Finding `json:"findings"`
	Summary  Summary          `json:"summary"`
}

// Summary is the machine-readable tally.
type Summary struct {
	Total        int            `json:"total"`
	BySeverity   map[string]int `json:"by_severity"`
	FilesWalked  int64          `json:"files_walked"`
	FilesRead    int64          `json:"files_read"`
	BytesRead    int64          `json:"bytes_read"`
	TemplatesRun int            `json:"templates_run"`
	DurationMS   int64          `json:"duration_ms"`
}

// JSON writes one indented object describing the whole run.
func JSON(w io.Writer, findings []engine.Finding, stats engine.Stats, root, version string) error {
	bySeverity := map[string]int{}
	for s, n := range Counts(findings) {
		bySeverity[string(s)] = n
	}
	if findings == nil {
		findings = []engine.Finding{}
	}

	report := Report{
		Tool:     "qalqon",
		Version:  version,
		Root:     root,
		Findings: findings,
		Summary: Summary{
			Total:        len(findings),
			BySeverity:   bySeverity,
			FilesWalked:  stats.FilesWalked,
			FilesRead:    stats.FilesRead,
			BytesRead:    stats.BytesRead,
			TemplatesRun: stats.TemplatesRun,
			DurationMS:   stats.Duration.Milliseconds(),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// TargetReport is the shape of --json output for a target scan.
type TargetReport struct {
	Tool      string               `json:"tool"`
	Version   string               `json:"version"`
	Mode      string               `json:"mode"`
	Findings  []engine.Finding     `json:"findings"`
	Unreached []engine.TargetError `json:"unreachable,omitempty"`
	Summary   Summary              `json:"summary"`
}

// JSONTargets writes the machine-readable report for a target scan, keeping
// unreachable hosts separate from findings.
func JSONTargets(w io.Writer, findings []engine.Finding, failures []engine.TargetError, stats engine.Stats, version string) error {
	bySeverity := map[string]int{}
	for s, n := range Counts(findings) {
		bySeverity[string(s)] = n
	}
	if findings == nil {
		findings = []engine.Finding{}
	}

	report := TargetReport{
		Tool:      "qalqon",
		Version:   version,
		Mode:      "target",
		Findings:  findings,
		Unreached: failures,
		Summary: Summary{
			Total:        len(findings),
			BySeverity:   bySeverity,
			FilesWalked:  stats.FilesWalked,
			FilesRead:    stats.FilesRead,
			TemplatesRun: stats.TemplatesRun,
			DurationMS:   stats.Duration.Milliseconds(),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// JSONL writes one finding per line, for piping into other tools.
func JSONL(w io.Writer, findings []engine.Finding) error {
	enc := json.NewEncoder(w)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// HostReport is the shape of --json output for a host audit. It carries
// findings and the probes this machine could not answer; the raw facts are
// available through `qalqon host -facts`, which prints them unjudged.
type HostReport struct {
	Tool     string           `json:"tool"`
	Version  string           `json:"version"`
	Mode     string           `json:"mode"`
	Findings []engine.Finding `json:"findings"`
	Skipped  []string         `json:"skipped,omitempty"`
	Summary  Summary          `json:"summary"`
}

// JSONHosts writes the machine-readable report for a host audit, including
// the facts behind every finding.
func JSONHosts(w io.Writer, findings []engine.Finding, skipped []host.Skipped, stats engine.Stats, version string) error {
	bySeverity := map[string]int{}
	for s, n := range Counts(findings) {
		bySeverity[string(s)] = n
	}
	if findings == nil {
		findings = []engine.Finding{}
	}

	var skips []string
	seen := map[string]bool{}
	for _, s := range skipped {
		if s.Part == "" || seen[s.Part] {
			continue
		}
		seen[s.Part] = true
		skips = append(skips, s.Part)
	}

	report := HostReport{
		Tool:     "qalqon",
		Version:  version,
		Mode:     "host",
		Findings: findings,
		Skipped:  skips,
		Summary: Summary{
			Total:        len(findings),
			BySeverity:   bySeverity,
			FilesWalked:  stats.FilesWalked,
			TemplatesRun: stats.TemplatesRun,
			DurationMS:   stats.Duration.Milliseconds(),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

/* ------------------------------------------------------------------ SARIF */

// SARIF writes SARIF 2.1.0, which GitHub ingests to populate the Security tab
// and annotate pull requests inline.
func SARIF(w io.Writer, findings []engine.Finding, version string) error {
	rules := map[string]sarifRule{}
	var order []string

	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		if _, seen := rules[f.TemplateID]; !seen {
			order = append(order, f.TemplateID)
			help := f.Description
			if f.Remediation != "" {
				help = help + "\n\nRemediation: " + f.Remediation
			}
			for _, ref := range f.Reference {
				help += "\n" + ref
			}
			rules[f.TemplateID] = sarifRule{
				ID:               f.TemplateID,
				Name:             f.TemplateID,
				ShortDescription: sarifText{Text: f.Name},
				FullDescription:  sarifText{Text: firstNonEmpty(f.Description, f.Name)},
				Help:             sarifText{Text: firstNonEmpty(help, f.Name)},
				DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
				Properties: sarifRuleProps{
					Tags:             append([]string{"security", string(f.Severity)}, f.Tags...),
					SecuritySeverity: securityScore(f.Severity),
				},
			}
		}

		line := f.Line
		if line < 1 {
			line = 1
		}
		col := f.Column
		if col < 1 {
			col = 1
		}

		results = append(results, sarifResult{
			RuleID:  f.TemplateID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: messageFor(f)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Where()},
					Region:           sarifRegion{StartLine: line, StartColumn: col},
				},
			}},
		})
	}

	ruleList := make([]sarifRule, 0, len(order))
	for _, id := range order {
		ruleList = append(ruleList, rules[id])
	}

	doc := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Qalqon",
				InformationURI: "https://github.com/nasafuriy/qalqon",
				Version:        version,
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func messageFor(f engine.Finding) string {
	msg := f.Name
	if f.Description != "" {
		msg = fmt.Sprintf("%s — %s", f.Name, f.Description)
	}
	if f.Remediation != "" {
		msg += " Remediation: " + f.Remediation
	}
	return msg
}

// GitHub maps these levels onto its own alert severities.
func sarifLevel(s template.Severity) string {
	switch s {
	case template.SeverityCritical, template.SeverityHigh:
		return "error"
	case template.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// security-severity is a CVSS-like number GitHub reads to rank alerts.
func securityScore(s template.Severity) string {
	switch s {
	case template.SeverityCritical:
		return "9.5"
	case template.SeverityHigh:
		return "7.5"
	case template.SeverityMedium:
		return "5.0"
	case template.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Help             sarifText      `json:"help"`
	DefaultConfig    sarifConfig    `json:"defaultConfiguration"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}
