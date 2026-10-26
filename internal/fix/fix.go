// Package fix applies the deterministic changes templates declare in their
// fix block, or — the default — shows them without touching anything.
//
// The contract is narrow on purpose. A diff is what a reviewer reads, so
// every run produces one. An apply backs the file up first, writes the
// change, then re-runs the rule that found the problem on the new content;
// only if the rule goes quiet does the change stay. A fix that did not end
// its finding is rolled back from the backup immediately, so the tree never
// rests in a half-applied state.
package fix

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nasafuriy/qalqon/internal/template"
)

// Status of one fix.
type Status string

const (
	// DryRun states nothing was written; Diff holds what would be.
	StatusDryRun Status = "dry_run"
	// Applied states the change was written and verified by re-scan.
	StatusApplied Status = "applied"
	// RolledBack states the change was written, did not verify, and the
	// backup was restored.
	StatusRolledBack Status = "rolled_back"
	// Skipped states the file was off-limits; Reason says why.
	StatusSkipped Status = "skipped"
)

// Target is one fixable finding, resolved to what the engine needs: the
// file it belongs to (slash-separated, relative to the scan root) and the
// rule that found it.
type Target struct {
	File       string
	TemplateID string
}

// Result records what happened to one fixable finding.
type Result struct {
	File   string
	Status Status
	Diff   string
	Backup string
	Reason string
}

// Options configure a fix run.
type Options struct {
	// Apply changes files. The zero value is a dry run: diffs are rendered
	// and nothing is written. Writes are opt-in, never the default.
	Apply bool
	// Root is the tree the scan ran against; target paths are relative to it.
	Root string
	// BackupDir overrides the backup directory (default ".qalqon-backups").
	BackupDir string
	// MaxFileSize refuses to read or write files above this size, matching
	// what the scan examined.
	MaxFileSize int64
}

// Engine applies the fixes a template set declares. One instance timestamps
// its backup directory once, so a run leaves one backup entry, not one per
// file.
type Engine struct {
	opts Options
	when string
}

// New constructs an engine over one run.
func New(opts Options) *Engine {
	opts.Root = filepath.Clean(opts.Root)
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 4 << 20 // the engine's default per-file cap
	}
	return &Engine{opts: opts, when: time.Now().UTC().Format("20060102T150405")}
}

// Run walks targets, resolves each to its template, and applies or renders
// the fixes for those that declare one.
//
// Targets for the same rule on the same file collapse into one fix: the
// patch rewrites every instance of the pattern, so the second finding would
// already be fixed by the first.
func (e *Engine) Run(set *template.Set, targets []Target) <-chan Result {
	out := make(chan Result, len(targets))
	go func() {
		defer close(out)

		byID := map[string]*template.Template{}
		for _, tpl := range set.Templates {
			byID[tpl.ID] = tpl
		}

		uniq := dedupe(targets)
		sort.Slice(uniq, func(i, j int) bool {
			if uniq[i].File != uniq[j].File {
				return uniq[i].File < uniq[j].File
			}
			return uniq[i].TemplateID < uniq[j].TemplateID
		})

		for _, t := range uniq {
			tpl, ok := byID[t.TemplateID]
			if !ok || !tpl.Fixable() {
				continue
			}
			res, err := e.fix(tpl, t.File)
			if err != nil {
				res = Result{File: t.File, Status: StatusSkipped, Reason: err.Error()}
			}
			out <- res
		}
	}()
	return out
}

// Collect drains the result stream in order.
func Collect(results <-chan Result) []Result {
	var out []Result
	for r := range results {
		out = append(out, r)
	}
	return out
}

func dedupe(targets []Target) []Target {
	seen := map[Target]bool{}
	out := make([]Target, 0, len(targets))
	for _, t := range targets {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// fix runs one fix against one file: refuse, diff, optionally write, verify.
func (e *Engine) fix(tpl *template.Template, file string) (Result, error) {
	res := Result{File: file}

	f := tpl.Fix

	absRoot, absFile, rel, err := e.resolve(file)
	if err != nil {
		res.Status = StatusSkipped
		res.Reason = err.Error()
		return res, nil
	}
	res.File = rel
	base := e.opts.BackupDir
	if base == "" {
		base = ".qalqon-backups"
	}
	res.Backup = filepath.Join(base, e.when, filepath.ToSlash(rel))

	info, err := os.Stat(absFile)
	if err != nil {
		res.Status = StatusSkipped
		res.Reason = "not readable (stat failed)"
		return res, nil
	}
	if info.Size() > e.opts.MaxFileSize {
		res.Status = StatusSkipped
		res.Reason = fmt.Sprintf("larger than the fix size cap (%d bytes)", e.opts.MaxFileSize)
		return res, nil
	}

	raw, err := os.ReadFile(absFile)
	if err != nil {
		res.Status = StatusSkipped
		res.Reason = "unreadable"
		return res, nil
	}
	if isBinary(raw) {
		res.Status = StatusSkipped
		res.Reason = "binary file"
		return res, nil
	}

	// The scan normalises CRLF before matching; the patch does the same and
	// re-encodes afterwards, so a Windows file keeps its endings.
	crlf := bytes.Contains(raw[:min(len(raw), 8000)], []byte("\r\n"))
	content := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))

	patched, err := patch(f, content)
	if err != nil {
		res.Status = StatusSkipped
		res.Reason = err.Error()
		return res, nil
	}
	dff := Diff(content, patched)
	if dff == "" {
		res.Status = StatusSkipped
		res.Reason = "the fix pattern no longer matches this content"
		return res, nil
	}

	// Dry run: the diff is the deliverable.
	if !e.opts.Apply {
		res.Status = StatusDryRun
		res.Diff = dff
		return res, nil
	}

	if err := e.backup(absRoot, rel, raw); err != nil {
		res.Status = StatusSkipped
		res.Reason = "backup failed: " + err.Error()
		return res, nil
	}

	// A read-only file fails here and reports itself, which is the cheaper
	// and more truthful variant of a check that could also go wrong.
	out := patched
	if crlf {
		out = bytes.ReplaceAll(patched, []byte("\n"), []byte("\r\n"))
	}
	if err := os.WriteFile(absFile, out, info.Mode().Perm()); err != nil {
		res.Status = StatusSkipped
		res.Reason = "write refused: " + err.Error()
		return res, nil
	}
	res.Diff = dff

	// Verify by re-scan: the rule that found the problem must go quiet on
	// the patched content. If it does not, restore the backup.
	if tpl.MayMatch(patched) {
		if _, ok := tpl.Match(patched); ok {
			_ = os.WriteFile(absFile, raw, info.Mode().Perm())
			res.Status = StatusRolledBack
			res.Reason = "the rule still matches after the fix; original restored"
			return res, nil
		}
	}
	res.Status = StatusApplied
	return res, nil
}

// Patch applies one fix op to LF-normalised content. It is the package's
// single patch primitive: the engine uses it on file bytes, and tests use it
// to prove a declared fix actually silences its rule.
func Patch(f *template.Fix, content []byte) ([]byte, error) {
	return patch(f, content)
}

// patch applies one file fix op to LF-normalised content.
func patch(f *template.Fix, content []byte) ([]byte, error) {
	re, err := regexp.Compile(f.Find)
	if err != nil {
		return nil, fmt.Errorf("find pattern: %w", err)
	}

	switch f.Op {
	case template.FixReplace:
		return re.ReplaceAll(content, []byte(f.Replace)), nil

	case template.FixInsertAfter, template.FixInsertBefore:
		lines := strings.Split(string(content), "\n")
		out := make([]string, 0, len(lines)+8)
		for _, line := range lines {
			if re.MatchString(line) {
				// The inserted line joins the matched line's indentation.
				// Every format that gets an insert fix is whitespace-
				// insensitive, so this is cosmetic — but a diff that looks
				// hand-written is a diff a reviewer accepts.
				insert := indentOf(line) + strings.TrimLeft(f.Replace, " \t")
				if f.Op == template.FixInsertBefore {
					out = append(out, insert, line)
				} else {
					out = append(out, line, insert)
				}
				continue
			}
			out = append(out, line)
		}
		return []byte(strings.Join(out, "\n")), nil

	case template.FixDeleteLine:
		lines := strings.Split(string(content), "\n")
		out := make([]string, 0, len(lines))
		for _, line := range lines {
			if re.MatchString(line) {
				continue
			}
			out = append(out, line)
		}
		return []byte(strings.Join(out, "\n")), nil

	default:
		return nil, fmt.Errorf("unsupported file fix op %q", f.Op)
	}
}

// indentOf reports the leading whitespace of one line.
func indentOf(line string) string {
	for i, r := range line {
		if r != ' ' && r != '\t' {
			return line[:i]
		}
	}
	return ""
}

func isBinary(raw []byte) bool {
	limit := len(raw)
	if limit > 8000 {
		limit = 8000
	}
	return bytes.IndexByte(raw[:limit], 0) >= 0
}

// resolve maps a slash path from the findings onto the scan root and refuses
// anything that is not a plain file below it. Fix paths come from the scan,
// so an escape here would mean a bug — refusing keeps it that way.
func (e *Engine) resolve(file string) (absRoot, absFile, rel string, err error) {
	rel = filepath.Clean(filepath.FromSlash(file))
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
		return "", "", "", fmt.Errorf("refusing to write outside the scan root: %s", file)
	}
	absRoot, err = filepath.Abs(e.opts.Root)
	if err != nil {
		return "", "", "", err
	}
	absFile = filepath.Join(absRoot, rel)
	if !strings.HasPrefix(absFile, absRoot+string(filepath.Separator)) {
		return "", "", "", fmt.Errorf("refusing to write outside the scan root: %s", file)
	}
	return absRoot, absFile, rel, nil
}

// backup copies the file's current bytes under the run's backup directory.
func (e *Engine) backup(absRoot, rel string, raw []byte) error {
	base := e.opts.BackupDir
	if base == "" {
		base = ".qalqon-backups"
	}
	dir := filepath.Join(absRoot, base, e.when, filepath.Dir(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dest := filepath.Join(dir, filepath.Base(rel))
	return os.WriteFile(dest, raw, 0o644)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
