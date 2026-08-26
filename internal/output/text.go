// Package output renders scan results for humans, for machines, and for
// GitHub's code-scanning UI.
package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/template"
)

// ANSI colours, blanked out when the terminal will not render them.
type palette struct {
	dim, bold, reset          string
	critical, high, medium    string
	low, info, file, fix, hit string
}

func newPalette(enabled bool) palette {
	if !enabled {
		return palette{}
	}
	return palette{
		dim: "\x1b[2m", bold: "\x1b[1m", reset: "\x1b[0m",
		critical: "\x1b[1;35m", // magenta
		high:     "\x1b[1;31m", // red
		medium:   "\x1b[1;33m", // yellow
		low:      "\x1b[1;36m", // cyan
		info:     "\x1b[1;34m", // blue
		file:     "\x1b[1;97m",
		fix:      "\x1b[32m",
		hit:      "\x1b[2;37m",
	}
}

func (p palette) severity(s template.Severity) string {
	switch s {
	case template.SeverityCritical:
		return p.critical
	case template.SeverityHigh:
		return p.high
	case template.SeverityMedium:
		return p.medium
	case template.SeverityLow:
		return p.low
	default:
		return p.info
	}
}

// ColorEnabled decides whether to emit ANSI codes.
func ColorEnabled(force, disable bool) bool {
	if disable {
		return false
	}
	if force {
		return true
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

// TextOptions controls the human-readable report.
type TextOptions struct {
	Color   bool
	Quiet   bool // findings only, no header or summary
	Stats   bool
	Version string
	// Unit names what was examined, for the header line. Defaults to "files".
	Unit string
	// Rules names what did the examining. Defaults to "templates"; a
	// dependency scan checks versions against advisories instead.
	Rules string
}

// Text writes the report a person reads in a terminal or CI log.
func Text(w io.Writer, findings []engine.Finding, stats engine.Stats, opts TextOptions) error {
	p := newPalette(opts.Color)

	unit := opts.Unit
	if unit == "" {
		unit = "files"
	}
	if stats.FilesWalked == 1 {
		unit = strings.TrimSuffix(unit, "s")
	}

	rules := opts.Rules
	if rules == "" {
		rules = "templates"
	}

	if !opts.Quiet {
		fmt.Fprintf(w, "%sqalqon%s %s· %d %s · %s %s in %s%s\n\n",
			p.bold, p.reset, p.dim,
			stats.TemplatesRun, rules,
			thousands(stats.FilesWalked), unit, roundDuration(stats), p.reset)
	}

	if len(findings) == 0 {
		if !opts.Quiet {
			fmt.Fprintf(w, "%sNo findings.%s\n", p.fix, p.reset)
		}
		return nil
	}

	// Group by file: people fix one file at a time.
	byFile := map[string][]engine.Finding{}
	var files []string
	for _, f := range findings {
		where := f.Where()
		if _, ok := byFile[where]; !ok {
			files = append(files, where)
		}
		byFile[where] = append(byFile[where], f)
	}
	sort.Strings(files)

	width := 0
	for _, f := range findings {
		if len(f.TemplateID) > width {
			width = len(f.TemplateID)
		}
	}
	if width > 34 {
		width = 34
	}

	for _, file := range files {
		group := byFile[file]
		sort.Slice(group, func(i, j int) bool {
			if group[i].Line != group[j].Line {
				return group[i].Line < group[j].Line
			}
			return group[i].TemplateID < group[j].TemplateID
		})

		fmt.Fprintf(w, "%s%s%s\n", p.file, file, p.reset)

		for _, f := range group {
			// File findings point at a line; target findings name the part of
			// the response the rule looked at.
			where := "—"
			switch {
			case f.Commit != "":
				// A history finding is located by commit; the line number in
				// a diff is not a line number in any file that exists.
				where = f.Commit[:min(len(f.Commit), 8)]
			case f.Part != "":
				where = f.Part
			case f.Line > 0 && f.Column > 0:
				where = fmt.Sprintf("%d:%d", f.Line, f.Column)
			case f.Line > 0:
				// A dependency is pinned to a line, not to a column.
				where = strconv.Itoa(f.Line)
			}
			fmt.Fprintf(w, "  %s%-9s%s %s%-8s%s %s%-*s%s %s\n",
				p.dim, where, p.reset,
				p.severity(f.Severity), f.Severity, p.reset,
				p.dim, width, f.TemplateID, p.reset,
				f.Name)

			if f.Match != "" {
				fmt.Fprintf(w, "             %s%s%s\n", p.hit, f.Match, p.reset)
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "             %s→ %s%s\n", p.fix, f.Remediation, p.reset)
			}
		}
		fmt.Fprintln(w)
	}

	if opts.Quiet {
		return nil
	}

	counts := Counts(findings)
	var parts []string
	for _, s := range reverse(template.Severities()) {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s%d %s%s", p.severity(s), counts[s], s, p.reset))
		}
	}

	fmt.Fprintf(w, "%s%d finding%s%s   %s\n",
		p.bold, len(findings), plural(len(findings)), p.reset, strings.Join(parts, " · "))

	if opts.Stats {
		fmt.Fprintf(w, "%sread %s files (%s) · %s%s\n",
			p.dim, thousands(stats.FilesRead), humanBytes(stats.BytesRead), roundDuration(stats), p.reset)
	}
	return nil
}

// Counts tallies findings per severity.
func Counts(findings []engine.Finding) map[template.Severity]int {
	out := map[template.Severity]int{}
	for _, f := range findings {
		out[f.Severity]++
	}
	return out
}

// Highest returns the most severe level present, or "" when there are none.
func Highest(findings []engine.Finding) template.Severity {
	var top template.Severity
	for _, f := range findings {
		if top == "" || f.Severity.Rank() > top.Rank() {
			top = f.Severity
		}
	}
	return top
}

func reverse(in []template.Severity) []template.Severity {
	out := make([]template.Severity, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func thousands(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func roundDuration(stats engine.Stats) string {
	d := stats.Duration
	switch {
	case d < 1000:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d.Milliseconds() < 1000:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}
