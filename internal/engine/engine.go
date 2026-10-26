// Package engine walks a tree and runs templates against the files that
// matter, using every core available.
//
// The hot path is deliberately narrow: a file is only read from disk if at
// least one template's file globs already matched its name. On a large
// repository that skips almost everything before touching the disk.
package engine

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nasafuriy/qalqon/internal/template"
)

// Finding is one template firing on one file.
type Finding struct {
	TemplateID  string            `json:"template_id"`
	Name        string            `json:"name"`
	Severity    template.Severity `json:"severity"`
	Description string            `json:"description,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Reference   []string          `json:"reference,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	// File is set by a filesystem scan; Target and Part by a target scan.
	File   string `json:"file,omitempty"`
	Target string `json:"target,omitempty"`
	Part   string `json:"part,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
	Match  string `json:"match,omitempty"`
	// Commit is set by a history scan, and names where the content was
	// introduced. The file it names may no longer exist.
	Commit string `json:"commit,omitempty"`
	Author string `json:"author,omitempty"`
	Date   string `json:"date,omitempty"`
}

// Where names the thing a finding is about, whichever mode produced it.
func (f Finding) Where() string {
	if f.Target != "" {
		return f.Target
	}
	return f.File
}

// Options configures a scan.
type Options struct {
	Root        string
	Concurrency int
	Exclude     []string
	Hidden      bool
	MaxFileSize int64
}

// Stats describes the work done, for --stats.
type Stats struct {
	FilesWalked  int64
	FilesRead    int64
	BytesRead    int64
	TemplatesRun int
	Duration     time.Duration
}

// Directories that are never worth scanning and are expensive to walk.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true, "bower_components": true,
	".terraform": true, ".venv": true, "venv": true, "__pycache__": true,
	"dist": true, "build": true, "target": true, "out": true,
	".next": true, ".nuxt": true, ".cache": true, ".gradle": true,
	".idea": true, ".vscode": true, ".pytest_cache": true, ".mypy_cache": true,
}

// Dot-directories that hold exactly the kind of configuration this tool
// exists to check, so they are scanned even though hidden paths are skipped.
var alwaysScanDotDirs = map[string]bool{
	".github": true, ".gitlab": true, ".circleci": true,
	".azure": true, ".azuredevops": true, ".devcontainer": true,
	".config": true, ".chart": true,
}

const defaultMaxFileSize = 4 << 20

// Run scans opts.Root with every template in set.
func Run(ctx context.Context, set *template.Set, opts Options) ([]Finding, Stats, error) {
	start := time.Now()

	if opts.Concurrency <= 0 {
		opts.Concurrency = runtime.NumCPU()
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = defaultMaxFileSize
	}

	root := opts.Root
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, Stats{}, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, Stats{}, err
	}

	stats := Stats{TemplatesRun: set.Len()}

	// A single file target still goes through the same pipeline.
	walkRoot := absRoot
	if !info.IsDir() {
		walkRoot = filepath.Dir(absRoot)
	}

	var (
		walked   atomic.Int64
		read     atomic.Int64
		bytesIn  atomic.Int64
		mu       sync.Mutex
		findings []Finding
	)

	paths := make(chan string, opts.Concurrency*64)

	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				local := scanFile(set, walkRoot, p, opts, &read, &bytesIn)
				if len(local) > 0 {
					mu.Lock()
					findings = append(findings, local...)
					mu.Unlock()
				}
			}
		}()
	}

	walkErr := filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory should not abort the whole scan.
			return nil //nolint:nilerr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if d.IsDir() {
			name := d.Name()
			if p == absRoot {
				return nil
			}
			if skipDirs[name] {
				return filepath.SkipDir
			}
			if !opts.Hidden && strings.HasPrefix(name, ".") && !alwaysScanDotDirs[name] {
				return filepath.SkipDir
			}
			if excluded(opts.Exclude, relSlash(walkRoot, p), name) {
				return filepath.SkipDir
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}
		walked.Add(1)

		if excluded(opts.Exclude, relSlash(walkRoot, p), d.Name()) {
			return nil
		}

		select {
		case paths <- p:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})

	close(paths)
	wg.Wait()

	stats.FilesWalked = walked.Load()
	stats.FilesRead = read.Load()
	stats.BytesRead = bytesIn.Load()
	stats.Duration = time.Since(start)

	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.TemplateID < b.TemplateID
	})

	if walkErr != nil && ctx.Err() != nil {
		return findings, stats, ctx.Err()
	}
	return findings, stats, nil
}

func scanFile(set *template.Set, root, path string, opts Options, read, bytesIn *atomic.Int64) []Finding {
	rel := relSlash(root, path)
	base := filepath.Base(path)

	// Cheap gate: decide from the name alone whether any template cares.
	applicable := make([]*template.Template, 0, 4)
	for _, t := range set.Templates {
		if t.AppliesTo(rel, base) {
			applicable = append(applicable, t)
		}
	}
	if len(applicable) == 0 {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil || info.Size() > opts.MaxFileSize {
		return nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	read.Add(1)
	bytesIn.Add(int64(len(content)))

	if isBinary(content) {
		return nil
	}

	content = normalizeEndings(content)

	// A rule library sitting in the repository would otherwise be scanned as
	// though it were configuration: templates/compose.yaml matches the glob
	// for a real compose file, and its example patterns then look like real
	// findings. Skip anything that is itself a Qalqon template.
	if isQalqonTemplate(content) {
		return nil
	}

	var out []Finding
	for _, t := range applicable {
		if int64(len(content)) > t.MaxSize {
			continue
		}
		// Substring gate first: far cheaper than sweeping the regexes.
		if !t.MayMatch(content) {
			continue
		}
		hits, ok := t.Match(content)
		if !ok {
			continue
		}

		if len(hits) == 0 {
			// An "absent" rule has no position to point at; report the file.
			out = append(out, newFinding(t, rel, 0, 0, ""))
			continue
		}

		// One finding per line keeps the report readable when a pattern
		// matches many times in the same file.
		sort.Slice(hits, func(i, j int) bool { return hits[i].Offset < hits[j].Offset })

		seenLines := make(map[int]bool, len(hits))
		for _, h := range hits {
			line, col := position(content, h.Offset)
			if seenLines[line] {
				continue
			}
			seenLines[line] = true
			out = append(out, newFinding(t, rel, line, col, h.Text))

			// Rules about the file as a whole report their first hit only.
			if t.Once {
				break
			}
		}
	}
	return out
}

func newFinding(t *template.Template, file string, line, col int, match string) Finding {
	return Finding{
		TemplateID:  t.ID,
		Name:        t.Info.Name,
		Severity:    t.Info.Severity,
		Description: t.Info.Description,
		Remediation: t.Info.Remediation,
		Reference:   t.Info.Reference,
		Tags:        t.Info.Tags,
		File:        file,
		Line:        line,
		Column:      col,
		Match:       truncate(match, 160),
	}
}

// position converts a byte offset into a 1-based line and column.
func position(content []byte, offset int) (line, col int) {
	if offset > len(content) {
		offset = len(content)
	}
	line = 1 + bytes.Count(content[:offset], []byte{'\n'})
	lineStart := bytes.LastIndexByte(content[:offset], '\n') + 1
	col = offset - lineStart + 1
	return line, col
}

// Top-level id/files/matchers keys together are a strong signature for a
// Qalqon template and vanishingly unlikely in real configuration.
var (
	tplID       = regexp.MustCompile(`(?m)^id:\s*[a-z0-9][a-z0-9-]*\s*$`)
	tplFiles    = regexp.MustCompile(`(?m)^files:\s*$`)
	tplMatchers = regexp.MustCompile(`(?m)^matchers:\s*$`)
)

// IsQalqonTemplate reports whether this content is itself a rule definition.
//
// Exported because history has to make the same decision. A rule that says
// what an AWS key looks like contains something shaped exactly like an AWS
// key, and a scanner that reports its own template library is unusable. The
// two commands agreeing matters: when scan stays quiet about a file and
// history does not, the only way to reconcile them is -exclude, and that is
// a blunt instrument to reach for over a disagreement between two parts of
// the same tool.
func IsQalqonTemplate(content []byte) bool {
	return isQalqonTemplate(content)
}

func isQalqonTemplate(content []byte) bool {
	return tplID.Match(content) && tplFiles.Match(content) && tplMatchers.Match(content)
}

// normalizeEndings folds CRLF and bare CR line endings to LF, once, before
// any pattern runs. On Windows almost every text file ends in CRLF; without
// this, end-of-line anchors ($, (?m)^) and one-line captures behave
// differently from the same file committed with LF, which is how a Windows
// checkout quietly turns a rule off. Doing it here means templates are
// written against LF everywhere and a fixture proves it stays that way.
func normalizeEndings(content []byte) []byte {
	if bytes.IndexByte(content, '\r') < 0 {
		return content
	}
	content = bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(content, []byte("\r"), []byte("\n"))
}

// isBinary uses the same heuristic as git: a NUL byte near the start.
func isBinary(content []byte) bool {
	limit := len(content)
	if limit > 8000 {
		limit = 8000
	}
	return bytes.IndexByte(content[:limit], 0) >= 0
}

func relSlash(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		rel = p
	}
	return filepath.ToSlash(rel)
}

// caseInsensitive follows the filesystem's rule: on Windows, FILE.TXT and
// file.txt are one file, so exclude globs match either spelling.
var caseInsensitive = runtime.GOOS == "windows"

func excluded(patterns []string, rel, base string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if caseInsensitive {
			// Same rule as template matching: on Windows a file named
			// README.md and readme.md are one file.
			pattern, rel, base = strings.ToLower(pattern), strings.ToLower(rel), strings.ToLower(base)
		}
		if ok, _ := filepath.Match(pattern, base); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, rel); ok {
			return true
		}
		if strings.Contains(rel, strings.Trim(pattern, "*/")) && strings.Contains(pattern, "/") {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
