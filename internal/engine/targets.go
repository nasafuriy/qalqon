package engine

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/nasafuriy/qalqon/internal/probe"
	"github.com/nasafuriy/qalqon/internal/service"
	"github.com/nasafuriy/qalqon/internal/template"
)

// TargetOptions configures a target scan.
//
// Concurrency is capped deliberately low. This mode exists to audit the
// handful of hosts you operate, not to sweep a range, and a modest ceiling
// keeps it that way while also being polite to the servers involved.
type TargetOptions struct {
	Concurrency int
	Timeout     time.Duration
	MaxBody     int64
	UserAgent   string
	// CheckTLSVersions asks each https host which protocol versions it
	// accepts, rather than only recording the one it negotiated.
	CheckTLSVersions bool
	// ServiceCVEs looks up the versions a host names in its own headers
	// against a curated advisory table. Off by default: a banner is a claim
	// rather than a measurement, and the default report is meant to be
	// trustworthy without a caveat attached to every line.
	ServiceCVEs bool
}

// MaxTargetConcurrency bounds parallel requests regardless of what is asked for.
const MaxTargetConcurrency = 10

// TargetError records a target that could not be probed at all.
type TargetError struct {
	Target string `json:"target"`
	Err    string `json:"error"`
}

// RunTargets probes each target once and runs the http templates over the
// response. Targets that fail outright are returned separately, because a DNS
// failure is not a finding — it is a problem with the input.
func RunTargets(ctx context.Context, set *template.Set, targets []string, opts TargetOptions) ([]Finding, []TargetError, Stats, error) {
	start := time.Now()

	http := set.OfKind(template.KindHTTP)
	stats := Stats{TemplatesRun: http.Len()}

	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Concurrency > MaxTargetConcurrency {
		opts.Concurrency = MaxTargetConcurrency
	}

	var (
		mu       sync.Mutex
		findings []Finding
		failures []TargetError
		wg       sync.WaitGroup
	)

	queue := make(chan string)

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range queue {
				result, err := probe.Fetch(ctx, target, probe.Options{
					Timeout:          opts.Timeout,
					MaxBody:          opts.MaxBody,
					UserAgent:        opts.UserAgent,
					CheckTLSVersions: opts.CheckTLSVersions,
				})
				if err != nil {
					mu.Lock()
					failures = append(failures, TargetError{Target: target, Err: err.Error()})
					mu.Unlock()
					continue
				}

				local := matchTarget(http, result)
				if opts.ServiceCVEs {
					local = append(local, serviceFindings(result)...)
				}
				mu.Lock()
				findings = append(findings, local...)
				mu.Unlock()
			}
		}()
	}

	for _, target := range targets {
		select {
		case queue <- target:
		case <-ctx.Done():
		}
	}
	close(queue)
	wg.Wait()

	stats.FilesWalked = int64(len(targets))
	stats.FilesRead = int64(len(targets) - len(failures))
	stats.Duration = time.Since(start)

	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.TemplateID < b.TemplateID
	})
	sort.Slice(failures, func(i, j int) bool { return failures[i].Target < failures[j].Target })

	return findings, failures, stats, ctx.Err()
}

func matchTarget(set *template.Set, result *probe.Result) []Finding {
	var out []Finding

	for _, t := range set.Templates {
		hits, ok := t.MatchParts(result.Parts)
		if !ok {
			continue
		}

		if len(hits) == 0 {
			// An "absent" rule has nothing to point at, so name the part it read.
			out = append(out, targetFinding(t, result, 0, primaryPart(t), ""))
			continue
		}

		seen := map[string]bool{}
		for _, h := range hits {
			line, _ := position(result.Parts[h.Part], h.Offset)
			key := h.Part + ":" + h.Text
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, targetFinding(t, result, line, h.Part, h.Text))
			if t.Once {
				break
			}
		}
	}
	return out
}

// primaryPart is the part the rule is really about: the first matcher that is
// not just establishing context.
func primaryPart(t *template.Template) string {
	for i := range t.Matchers {
		if !t.Matchers[i].Context {
			return t.Matchers[i].Part
		}
	}
	if len(t.Matchers) > 0 {
		return t.Matchers[0].Part
	}
	return ""
}

func targetFinding(t *template.Template, result *probe.Result, line int, part, match string) Finding {
	return Finding{
		TemplateID:  t.ID,
		Name:        t.Info.Name,
		Severity:    t.Info.Severity,
		Description: t.Info.Description,
		Remediation: t.Info.Remediation,
		Reference:   t.Info.Reference,
		Tags:        t.Info.Tags,
		Target:      result.FinalURL,
		Part:        part,
		Line:        line,
		Match:       truncate(match, 160),
	}
}

// serviceFindings reports what is publicly known about the versions a host
// disclosed in its own headers.
//
// This does not go through the template engine. A template matches text, and
// the question here is arithmetic — is 1.10.3 below 1.20.1 — which a regex
// cannot answer without a rule per version, and would answer wrongly the
// moment a version reached double digits.
func serviceFindings(result *probe.Result) []Finding {
	var out []Finding
	for _, f := range service.Findings(result.Parts[template.PartHeader]) {
		severity, err := template.ParseSeverity(f.Severity)
		if err != nil {
			severity = template.SeverityInfo
		}
		out = append(out, Finding{
			TemplateID:  f.ID,
			Name:        f.Name,
			Severity:    severity,
			Description: f.Description,
			Remediation: f.Remediation,
			Reference:   f.Refs,
			Tags:        f.Tags,
			Target:      result.FinalURL,
			Part:        template.PartHeader,
			Match:       truncate(f.Match, 160),
		})
	}
	return out
}
