// Package template defines the rule format Qalqon scans with, and loads
// rule files from disk or from the embedded library.
//
// A template is deliberately small enough to write in a couple of minutes:
// which files it applies to, and what has to be true (or absent) inside them.
package template

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity orders findings and drives the --fail-on threshold.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Rank returns the ordering position; unknown severities sort lowest.
func (s Severity) Rank() int { return severityRank[s] }

// Valid reports whether s is one of the five known levels.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// ParseSeverity accepts any capitalisation and rejects anything unknown.
func ParseSeverity(v string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(v)))
	if !s.Valid() {
		return "", fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", v)
	}
	return s, nil
}

// Severities lists every level from lowest to highest.
func Severities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

// Info carries everything a human needs once a template fires.
type Info struct {
	Name        string   `yaml:"name"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	Remediation string   `yaml:"remediation"`
	Reference   []string `yaml:"reference"`
	Tags        []string `yaml:"tags"`
}

// Matcher types.
const (
	// MatchRegex fires when the pattern is found.
	MatchRegex = "regex"
	// MatchWord is MatchRegex with the pattern treated literally.
	MatchWord = "word"
	// MatchAbsent fires when the pattern is *not* found anywhere in the file,
	// which is how "this directive is missing" rules are written.
	MatchAbsent = "absent"
)

// Matcher is one condition inside a template.
type Matcher struct {
	Type            string   `yaml:"type"`
	Patterns        []string `yaml:"patterns"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	// Condition combines this matcher's own patterns: "any" (default) or "all".
	Condition string `yaml:"condition"`
	Comment   string `yaml:"comment"`

	// Context marks a matcher that establishes what kind of file this is
	// (say, "kind: Deployment") rather than being the problem itself. It must
	// still match, but it never becomes the reported location.
	Context bool `yaml:"context"`

	// Part selects which piece of an HTTP response to match against. Ignored
	// by file templates; defaults to "header" for HTTP ones.
	Part string `yaml:"part"`

	compiled []*regexp.Regexp
}

// Template kinds.
const (
	// KindFile matches against the contents of files on disk.
	KindFile = "file"
	// KindHTTP matches against one response fetched from a target you control.
	KindHTTP = "http"
)

// Parts of an HTTP response a matcher can be pointed at.
const (
	PartHeader = "header"
	PartBody   = "body"
	PartStatus = "status"
	PartTLS    = "tls"
	PartURL    = "url"
)

// ValidParts lists the addressable parts of a probed response.
var ValidParts = []string{PartHeader, PartBody, PartStatus, PartTLS, PartURL}

// Template is a single rule.
type Template struct {
	ID   string `yaml:"id"`
	Info Info   `yaml:"info"`

	// Type selects what the rule runs against: "file" (default) or "http".
	Type string `yaml:"type"`

	// Files are globs the template applies to. A pattern containing "/" is
	// matched against the path relative to the scan root; otherwise it is
	// matched against the file name alone.
	Files   []string `yaml:"files"`
	Exclude []string `yaml:"exclude"`

	// MaxSize skips files larger than this many bytes (default 2 MiB).
	MaxSize int64 `yaml:"max-size"`

	// Condition combines the matchers: "and" (default) or "or".
	Condition string    `yaml:"condition"`
	Matchers  []Matcher `yaml:"matchers"`

	// Once reports a single finding per file, for rules about the file as a
	// whole rather than about particular lines.
	Once bool `yaml:"once"`

	// Prefilter lists literal strings, any one of which must appear in the
	// file before the regexes are run at all. A plain substring search is far
	// cheaper than a regex sweep, so this is what keeps broad rules like the
	// credential scanners fast over a whole repository.
	//
	// Every literal must be implied by something the template positively
	// requires. Do not derive one from an "absent" matcher, because that
	// inverts the logic and the rule will stop firing.
	Prefilter []string `yaml:"prefilter"`

	prefilter [][]byte

	// Source records where the template came from, for error messages.
	Source string `yaml:"-"`
}

// DefaultMaxSize is the per-file cap when a template does not set one.
const DefaultMaxSize = 2 << 20

// Hit is one place inside a file, or inside one part of an HTTP response,
// where a matcher fired.
type Hit struct {
	Offset int
	Text   string
	Part   string
}

var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Validate checks the template is well formed and compiles its patterns.
// It must be called before Match.
func (t *Template) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("missing id")
	}
	if !idPattern.MatchString(t.ID) {
		return fmt.Errorf("id %q must be lowercase words joined by hyphens", t.ID)
	}
	if t.Info.Name == "" {
		return fmt.Errorf("%s: info.name is required", t.ID)
	}
	if !t.Info.Severity.Valid() {
		return fmt.Errorf("%s: severity %q is not one of info, low, medium, high, critical", t.ID, t.Info.Severity)
	}
	if t.Type == "" {
		t.Type = KindFile
	}
	switch t.Type {
	case KindFile:
		if len(t.Files) == 0 {
			return fmt.Errorf("%s: a file template needs at least one entry under files", t.ID)
		}
	case KindHTTP:
		if len(t.Files) > 0 {
			return fmt.Errorf("%s: an http template must not set files", t.ID)
		}
	default:
		return fmt.Errorf("%s: type must be %q or %q, got %q", t.ID, KindFile, KindHTTP, t.Type)
	}

	if len(t.Matchers) == 0 {
		return fmt.Errorf("%s: needs at least one matcher", t.ID)
	}

	for i := range t.Matchers {
		m := &t.Matchers[i]
		if t.Type == KindFile {
			if m.Part != "" {
				return fmt.Errorf("%s: matcher %d sets part, which only applies to http templates", t.ID, i+1)
			}
			continue
		}
		if m.Part == "" {
			m.Part = PartHeader
		}
		valid := false
		for _, p := range ValidParts {
			if m.Part == p {
				valid = true
			}
		}
		if !valid {
			return fmt.Errorf("%s: matcher %d has part %q (want one of %s)", t.ID, i+1, m.Part, strings.Join(ValidParts, ", "))
		}
	}

	switch strings.ToLower(t.Condition) {
	case "", "and", "or":
	default:
		return fmt.Errorf("%s: condition must be \"and\" or \"or\", got %q", t.ID, t.Condition)
	}

	if t.MaxSize <= 0 {
		t.MaxSize = DefaultMaxSize
	}

	t.prefilter = t.prefilter[:0]
	for _, lit := range t.Prefilter {
		if lit == "" {
			return fmt.Errorf("%s: prefilter entries cannot be empty", t.ID)
		}
		t.prefilter = append(t.prefilter, []byte(lit))
	}

	for i := range t.Matchers {
		if err := t.Matchers[i].compile(); err != nil {
			return fmt.Errorf("%s: matcher %d: %w", t.ID, i+1, err)
		}
	}
	return nil
}

func (m *Matcher) compile() error {
	if m.Type == "" {
		m.Type = MatchRegex
	}
	switch m.Type {
	case MatchRegex, MatchWord, MatchAbsent:
	default:
		return fmt.Errorf("unknown type %q (want regex, word or absent)", m.Type)
	}
	switch strings.ToLower(m.Condition) {
	case "", "any", "or", "all", "and":
	default:
		return fmt.Errorf("condition must be \"any\" or \"all\", got %q", m.Condition)
	}
	if len(m.Patterns) == 0 {
		return fmt.Errorf("needs at least one pattern")
	}

	m.compiled = make([]*regexp.Regexp, 0, len(m.Patterns))
	for _, p := range m.Patterns {
		expr := p
		if m.Type == MatchWord {
			expr = regexp.QuoteMeta(p)
		}
		if m.CaseInsensitive {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return fmt.Errorf("pattern %q: %w", p, err)
		}
		m.compiled = append(m.compiled, re)
	}
	return nil
}

func (m *Matcher) requiresAll() bool {
	c := strings.ToLower(m.Condition)
	return c == "all" || c == "and"
}

// eval runs one matcher over the file content.
func (m *Matcher) eval(content []byte) (hits []Hit, ok bool) {
	if m.Type == MatchAbsent {
		// "all" means every pattern must be absent; "any" means at least one is.
		absentCount := 0
		for _, re := range m.compiled {
			if !re.Match(content) {
				absentCount++
			}
		}
		if m.requiresAll() {
			return nil, absentCount == len(m.compiled)
		}
		return nil, absentCount > 0
	}

	matchedPatterns := 0
	for _, re := range m.compiled {
		locs := re.FindAllIndex(content, 64)
		if len(locs) == 0 {
			continue
		}
		matchedPatterns++
		for _, loc := range locs {
			hits = append(hits, Hit{
				Offset: loc[0],
				Text:   strings.TrimSpace(string(content[loc[0]:loc[1]])),
			})
		}
	}

	if m.requiresAll() {
		ok = matchedPatterns == len(m.compiled)
	} else {
		ok = matchedPatterns > 0
	}
	if !ok {
		return nil, false
	}
	return hits, true
}

// MayMatch is the cheap gate: a plain substring scan that rules the template
// out before any regex runs. Templates without a prefilter always pass.
func (t *Template) MayMatch(content []byte) bool {
	if len(t.prefilter) == 0 {
		return true
	}
	for _, lit := range t.prefilter {
		if bytes.Contains(content, lit) {
			return true
		}
	}
	return false
}

// Match runs every matcher and reports whether the template fires, along with
// the positions worth showing the user.
func (t *Template) Match(content []byte) ([]Hit, bool) {
	requireAll := !strings.EqualFold(t.Condition, "or")

	var hits []Hit
	matched := 0

	for i := range t.Matchers {
		h, ok := t.Matchers[i].eval(content)
		if ok {
			matched++
			// Context matchers gate the rule but never point at the problem.
			if !t.Matchers[i].Context {
				hits = append(hits, h...)
			}
		} else if requireAll {
			return nil, false
		}
	}

	if requireAll {
		return hits, matched == len(t.Matchers)
	}
	if matched == 0 {
		return nil, false
	}
	return hits, true
}

// MatchParts runs an HTTP template against the parts of one probed response.
// Each matcher reads only the part it names, so a header rule never trips over
// text in the body.
func (t *Template) MatchParts(parts map[string][]byte) ([]Hit, bool) {
	requireAll := !strings.EqualFold(t.Condition, "or")

	var hits []Hit
	matched := 0

	for i := range t.Matchers {
		m := &t.Matchers[i]
		h, ok := m.eval(parts[m.Part])
		if ok {
			matched++
			if !m.Context {
				for j := range h {
					h[j].Part = m.Part
				}
				hits = append(hits, h...)
			}
		} else if requireAll {
			return nil, false
		}
	}

	if requireAll {
		return hits, matched == len(t.Matchers)
	}
	if matched == 0 {
		return nil, false
	}
	return hits, true
}

// OfKind narrows the set to file or http templates.
func (s *Set) OfKind(kind string) *Set {
	var out []*Template
	for _, t := range s.Templates {
		if t.Type == kind {
			out = append(out, t)
		}
	}
	return &Set{Templates: out}
}

// AppliesTo reports whether the template should be run against this path.
// rel uses forward slashes and is relative to the scan root.
func (t *Template) AppliesTo(rel, base string) bool {
	for _, pattern := range t.Exclude {
		if matchGlob(pattern, rel, base) {
			return false
		}
	}
	for _, pattern := range t.Files {
		if matchGlob(pattern, rel, base) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, rel, base string) bool {
	p := strings.TrimPrefix(pattern, "./")
	p = strings.TrimPrefix(p, "**/")

	if caseInsensitive {
		// Windows filesystems are case-insensitive; Dockerfile and dockerfile
		// are the same file, so a pattern that only matches one of them is a
		// rule that silently never fires for half the team.
		p, rel, base = strings.ToLower(p), strings.ToLower(rel), strings.ToLower(base)
	}

	if !strings.Contains(p, "/") {
		ok, _ := path.Match(p, base)
		return ok
	}

	if ok, _ := path.Match(p, rel); ok {
		return true
	}
	// Also allow the pattern to match any trailing part of the path, so
	// "nginx/*.conf" finds "deploy/nginx/site.conf".
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		if ok, _ := path.Match(p, strings.Join(parts[i:], "/")); ok {
			return true
		}
	}
	return false
}

// caseInsensitive records that the local filesystem treats names as
// case-insensitive, as Windows does. Glob matching follows the filesystem's
// rule rather than the rule of whoever committed the pattern.
var caseInsensitive = runtime.GOOS == "windows"

// SetCaseInsensitive overrides the platform default. Tests use it to exercise
// both behaviours on every operating system.
func SetCaseInsensitive(v bool) { caseInsensitive = v }

func caseMatch(a, b string) bool {
	if caseInsensitive {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	return a == b
}

// Set is a validated, ordered collection of templates.
type Set struct {
	Templates []*Template
}

// Load reads every .yaml and .yml file under root in fsys, validating as it
// goes. Every template is checked, so one bad file reports its own error
// rather than aborting the whole load.
func Load(fsys fs.FS, root string) (*Set, []error) {
	var (
		out  []*Template
		errs []error
		seen = map[string]string{}
	)

	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
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

		// A file may hold several templates separated by "---", which keeps
		// related rules together without one file per rule.
		dec := yaml.NewDecoder(f)
		for index := 1; ; index++ {
			var tpl Template
			decErr := dec.Decode(&tpl)
			if decErr == io.EOF {
				break
			}
			if decErr != nil {
				errs = append(errs, fmt.Errorf("%s (document %d): %w", p, index, decErr))
				break
			}
			// Skip empty documents, which trailing "---" separators produce.
			if tpl.ID == "" && tpl.Info.Name == "" && len(tpl.Matchers) == 0 {
				continue
			}
			tpl.Source = p

			if err := tpl.Validate(); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p, err))
				continue
			}
			if prev, dup := seen[tpl.ID]; dup {
				errs = append(errs, fmt.Errorf("%s: duplicate id %q (already defined in %s)", p, tpl.ID, prev))
				continue
			}
			seen[tpl.ID] = p

			copied := tpl
			out = append(out, &copied)
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return &Set{Templates: out}, errs
}

// Filter returns the templates that survive the given selection. Empty
// selections mean "keep everything".
func (s *Set) Filter(minSeverity Severity, severities, tags, ids []string) *Set {
	lower := func(v []string) map[string]bool {
		m := make(map[string]bool, len(v))
		for _, x := range v {
			for _, part := range strings.Split(x, ",") {
				if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
					m[part] = true
				}
			}
		}
		return m
	}

	wantSeverity := lower(severities)
	wantTags := lower(tags)
	wantIDs := lower(ids)

	var out []*Template
	for _, t := range s.Templates {
		if minSeverity != "" && t.Info.Severity.Rank() < minSeverity.Rank() {
			continue
		}
		if len(wantSeverity) > 0 && !wantSeverity[string(t.Info.Severity)] {
			continue
		}
		if len(wantIDs) > 0 && !wantIDs[strings.ToLower(t.ID)] {
			continue
		}
		if len(wantTags) > 0 {
			hit := false
			for _, tag := range t.Info.Tags {
				if wantTags[strings.ToLower(tag)] {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		out = append(out, t)
	}
	return &Set{Templates: out}
}

// Len reports how many templates are in the set.
func (s *Set) Len() int { return len(s.Templates) }
