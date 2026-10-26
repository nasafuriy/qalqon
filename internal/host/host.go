// Package host audits the machine the binary is running on.
//
// Every probe is strictly read-only: it reads the registry, /proc, or the
// output of a built-in status command, and changes nothing. A probe renders
// its facts as "key: value" lines — exactly the way the HTTP probe renders
// TLS state — so the matcher engine evaluates host rules without knowing
// them apart from file and HTTP ones.
//
// Facts that need administrator rights arrive only when there is an
// administrator, and probes that could not run are simply absent: a rule
// that names a part the machine could not answer is skipped quietly, not
// turned into a false positive about an empty string.
package host

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/template"
	"gopkg.in/yaml.v3"
)

// Facts are the answers one prober found, one entry per fact. Values are
// rendered verbatim into the part's text.
type Facts map[string]string

// Prober reads one facet of the machine. Name is both the probe's identity
// and the part name templates address it by.
type Prober interface {
	Name() string
	Probe(ctx context.Context) (Facts, error)
}

// ProberFunc adapts a function into a Prober.
type ProberFunc struct {
	ProbeName string
	Fn        func(ctx context.Context) (Facts, error)
}

func (p ProberFunc) Name() string { return p.ProbeName }
func (p ProberFunc) Probe(ctx context.Context) (Facts, error) {
	return p.Fn(ctx)
}

// Options controls a host audit.
type Options struct {
	// Probes restricts the run to these probers; empty means all of them.
	Probes []string
	// Probers replaces the platform probe set entirely. Tests use it to run
	// against fixture answers without touching a real operating system.
	Probers []Prober
	// Concurrency caps how many probes run at once. Probes are local and
	// cheap, so the default is plenty.
	Concurrency int
}

// Stats describes the run, shaped like the engine's so the shared output
// code needs no special case.
type Stats struct {
	TemplatesRun int
	PartsProbed  int
	Duration     time.Duration
	FactsTotal   int
}

// Skipped is a probeset a rule needed but this machine could not answer,
// with the reason it was skipped.
type Skipped struct {
	Part   string
	Reason string
}

// Run probes the machine and evaluates every host template against the
// resulting parts. Secrets in PowerShell history, if it exists, are found by
// running the secret-tagged file rules over that part separately.
//
// A template whose parts cannot all be answered by this machine is skipped
// rather than run: an "absent" matcher against a part that simply did not
// load would report on the user's own machine a misconfiguration that may
// not exist, and false positives on a local audit cost more trust than they
// are ever worth recovering.
func Run(ctx context.Context, set, secretSet *template.Set, opts Options) ([]engine.Finding, Stats, []Skipped, error) {
	started := time.Now()
	var stats Stats

	var probes []Prober
	if len(opts.Probers) > 0 {
		probes = opts.Probers
	} else {
		probes = selectProbes(opts.Probes)
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}

	parts := map[string][]byte{}
	var skipped []Skipped

	type result struct {
		name  string
		text  []byte
		facts int
	}
	factsToPart := func(name string, facts Facts) ([]byte, int) {
		// A single "content" fact is raw text (PowerShell history), not a
		// key/value list: the part carries the text itself so the secret
		// rules see what a scan would have.
		if len(facts) == 1 {
			if raw, ok := facts["content"]; ok {
				return []byte(raw), 1
			}
		}
		return render(facts), len(facts)
	}

	results := make(chan result, len(probes))
	errs := make(chan Skipped, len(probes))
	sem := make(chan struct{}, opts.Concurrency)

	var wg sync.WaitGroup
	for _, p := range probes {
		wg.Add(1)
		go func(p Prober) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			facts, err := p.Probe(ctx)
			if err != nil {
				errs <- Skipped{Part: p.Name(), Reason: err.Error()}
				return
			}
			text, n := factsToPart(p.Name(), facts)
			results <- result{name: p.Name(), text: text, facts: n}
		}(p)
	}
	wg.Wait()
	close(results)
	close(errs)

	// The system part is always present, even when nothing else runs.
	if facts, err := systemProber().Probe(ctx); err == nil {
		parts["system"] = render(facts)
	}

	for r := range results {
		parts[r.name] = r.text
		stats.PartsProbed++
		stats.FactsTotal += r.facts
	}
	for s := range errs {
		skipped = append(skipped, s)
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Part < skipped[j].Part })

	stats.TemplatesRun = set.Len()
	findings := matchHost(set, parts, &skipped)

	// PowerShell history is ordinary text, not a list of facts, so the
	// secret rules from the file library run over it directly.
	if hist, ok := parts["history"]; ok && len(hist) > 0 && secretSet.Len() > 0 {
		findings = append(findings, matchSecretHistory(secretSet, hist)...)
	}

	stats.Duration = time.Since(started)
	return findings, stats, skipped, nil
}

// render turns facts into the text a matcher sees: one "key: value" line per
// fact, sorted, so rules are written against a stable order.
func render(facts Facts) []byte {
	if len(facts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(facts))
	for k := range facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, facts[k])
	}
	return b.Bytes()
}

// matchHost evaluates host templates, skipping any rule that names a part
// this machine did not answer.
func matchHost(set *template.Set, parts map[string][]byte, skipped *[]Skipped) []engine.Finding {
	var out []engine.Finding

	for _, t := range set.Templates {
		ready, missing := readyParts(t, parts)
		if !ready {
			*skipped = append(*skipped, Skipped{Part: missing, Reason: "probe ran on this platform or was not asked to"})
			continue
		}

		hits, ok := t.MatchParts(parts)
		if !ok {
			continue
		}
		part := primaryPart(t)
		if len(hits) == 0 {
			out = append(out, hostFinding(t, part, 0, ""))
			continue
		}
		seen := map[string]bool{}
		for _, h := range hits {
			if seen[h.Text] {
				continue
			}
			seen[h.Text] = true
			line, _ := lineOf(parts[part], h.Offset)
			out = append(out, hostFinding(t, part, line, h.Text))
			if t.Once {
				break
			}
		}
	}
	return out
}

// readyParts reports whether every part the template reads exists, and which
// one is missing when it does not.
func readyParts(t *template.Template, parts map[string][]byte) (bool, string) {
	for i := range t.Matchers {
		if _, ok := parts[t.Matchers[i].Part]; !ok {
			return false, t.Matchers[i].Part
		}
	}
	return true, ""
}

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

func hostFinding(t *template.Template, part string, line int, match string) engine.Finding {
	return engine.Finding{
		TemplateID:  t.ID,
		Name:        t.Info.Name,
		Severity:    t.Info.Severity,
		Description: t.Info.Description,
		Remediation: t.Info.Remediation,
		Reference:   t.Info.Reference,
		Tags:        t.Info.Tags,
		Part:        part,
		Line:        line,
		Match:       truncate(match, 160),
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// matchSecretHistory runs the secret rules over PowerShell history. History
// is not configuration and the file it was typed into may exist or not, so
// the finding names the history itself.
func matchSecretHistory(set *template.Set, history []byte) []engine.Finding {
	var out []engine.Finding
	for _, t := range set.Templates {
		if !t.MayMatch(history) {
			continue
		}
		hits, ok := t.Match(history)
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, h := range hits {
			if seen[h.Text] {
				continue
			}
			seen[h.Text] = true
			line, _ := lineOf(history, h.Offset)
			f := hostFinding(t, "history", line, h.Text)
			f.File = "PowerShell history"
			f.Tags = append(f.Tags, "history")
			out = append(out, f)
		}
	}
	return out
}

// lineOf converts a byte offset inside a part into a 1-based line number.
func lineOf(content []byte, offset int) (int, int) {
	if offset > len(content) {
		offset = len(content)
	}
	line := 1 + bytes.Count(content[:offset], []byte{'\n'})
	col := offset + 1
	if i := bytes.LastIndexByte(content[:offset], '\n'); i >= 0 {
		col = offset - i
	}
	return line, col
}

// execCommand runs a built-in status command and returns its stdout.
//
// Only status commands are ever passed here, and each call has two reasons
// to be safe: the program name is a build-time constant, and every argument
// is a literal in the probe that builds the call. Nothing from the scanned
// system or the user ever reaches it as a program name.
func execCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func selectProbes(only []string) []Prober {
	want := map[string]bool{}
	for _, name := range only {
		want[strings.ToLower(strings.TrimSpace(name))] = true
	}

	all := append([]Prober{systemProber()}, platformProbes()...)
	if len(want) == 0 {
		return all
	}
	var out []Prober
	for _, p := range all {
		if want[strings.ToLower(p.Name())] {
			out = append(out, p)
		}
	}
	return out
}

// SelectProbes names the probe set a run (or a fact dump) will use, applying
// an optional restriction. The system prober is part of every set.
func SelectProbes(only []string) []Prober { return selectProbes(only) }

// NamedFacts pairs a probe name with what it found, for fact dumps and the
// JSON report.
type NamedFacts struct {
	Name  string `json:"probe"`
	Facts Facts  `json:"facts"`
}

// SortedFacts renders facts as stable "key: value" lines.
func SortedFacts(facts Facts) []string {
	text := render(facts)
	if len(text) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(text), "\n"), "\n")
}

func systemProber() Prober {
	return ProberFunc{
		ProbeName: "system",
		Fn: func(ctx context.Context) (Facts, error) {
			platform, admin := runtime.GOOS+":"+runtime.GOARCH, osAdminState()
			return Facts{
				"platform":       platform,
				"admin":          fmt.Sprintf("%v", admin),
				"go_version":     strings.ReplaceAll(runtime.Version(), " ", "_"),
				"probe_time_utc": time.Now().UTC().Format(time.RFC3339),
			}, nil
		},
	}
}

// LoadFixture reads a host-facts fixture: a YAML document mapping each
// probe name to its facts, so the audit can be tested against a
// deliberately insecure machine without needing a real one. A value may be
// a mapping of keys or a plain string carrying raw part text (history).
func LoadFixture(path string) (map[string]Facts, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var outer map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &outer); err != nil {
		return nil, err
	}
	out := make(map[string]Facts, len(outer))
	for part, node := range outer {
		var asMap map[string]string
		if err := node.Decode(&asMap); err == nil {
			out[part] = Facts(asMap)
			continue
		}
		var asText string
		if err := node.Decode(&asText); err != nil {
			return nil, fmt.Errorf("%s: part %q is neither facts nor text", path, part)
		}
		out[part] = Facts{"content": asText}
	}
	return out, nil
}

// Info returns every probe this binary could run on this platform, used by
// the host command to explain its reach.
func Info() []string {
	var out []string
	all := append([]Prober{systemProber()}, platformProbes()...)
	for _, p := range all {
		out = append(out, p.Name())
	}
	return out
}
