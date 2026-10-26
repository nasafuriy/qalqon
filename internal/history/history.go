// Package history looks for secrets in commits, not only in the files that
// are there now.
//
// Deleting a credential in a later commit does not remove it: it is still in
// the history, still in every clone, and still readable from the GitHub API.
// A scan of the working tree reports nothing, which is exactly the wrong
// answer to give someone who thinks they cleaned it up.
package history

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/template"
)

// Options controls how far back to look.
type Options struct {
	Root       string
	MaxCommits int    // 0 means every commit
	Since      string // anything git --since accepts, e.g. "6 months ago"
	// Exclude skips paths. A repository that keeps deliberately insecure
	// fixtures needs this: those credentials are in the history on purpose,
	// and reporting them buries a real one.
	Exclude []string
	// MaxBlob caps how much added content is buffered per file per commit.
	MaxBlob int
}

// Stats describes what the walk covered.
type Stats struct {
	Commits  int
	Files    int
	Bytes    int64
	Duration time.Duration
}

const (
	// Field separators inside the --format string: ASCII record and unit
	// separators. Neither occurs in a commit header, and a diff body line
	// always begins with '+', '-' or a space, so a line starting with one of
	// these can only be ours.
	//
	// Not NUL: Windows passes arguments as null-terminated strings, so a NUL
	// inside one makes the exec fail outright.
	recordSep = "\x1e"
	fieldSep  = "\x1f"

	defaultMaxBlob = 1 << 20
)

// Available reports whether this looks like a git repository we can read.
func Available(root string) error {
	cmd := exec.Command("git", "-C", root, "rev-parse", "--git-dir")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s is not a git repository (%s)",
			root, strings.TrimSpace(string(out)))
	}
	return nil
}

// Scan walks the history and runs the given templates over the content each
// commit *added*. Only additions are examined: a line that was only ever
// deleted was introduced by some earlier commit, and that commit is where it
// gets reported.
func Scan(ctx context.Context, set *template.Set, opts Options) ([]engine.Finding, Stats, error) {
	started := time.Now()
	var stats Stats

	if err := Available(opts.Root); err != nil {
		return nil, stats, err
	}
	if opts.MaxBlob <= 0 {
		opts.MaxBlob = defaultMaxBlob
	}

	args := []string{
		"-C", opts.Root,
		"log", "--all", "-p",
		"--no-color", "--no-textconv", "--no-renames",
		"--diff-filter=AM", // added or modified; deletions add nothing
		"-U0",              // only the changed lines, no context
		"--format=" + recordSep + "%H" + fieldSep + "%an" + fieldSep + "%aI",
	}
	if opts.MaxCommits > 0 {
		args = append(args, fmt.Sprintf("-n%d", opts.MaxCommits))
	}
	if opts.Since != "" {
		args = append(args, "--since="+opts.Since)
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, stats, err
	}
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, stats, err
	}
	defer func() {
		_ = cmd.Wait()
	}()

	w := &walker{set: set, opts: opts, stats: &stats}

	sc := bufio.NewScanner(stdout)
	// Commits can carry very long lines; a minified bundle is one line.
	sc.Buffer(make([]byte, 64*1024), 8<<20)

	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return w.findings, stats, err
		}
		w.line(sc.Text())
	}
	w.flush()

	if err := sc.Err(); err != nil {
		return w.findings, stats, err
	}

	stats.Duration = time.Since(started)
	return w.findings, stats, nil
}

// walker holds the state of the stream: which commit and which file the
// added lines currently belong to.
type walker struct {
	set   *template.Set
	opts  Options
	stats *Stats

	commit, author, date string
	path                 string
	buf                  strings.Builder
	truncated            bool

	findings []engine.Finding
	seen     map[string]bool
}

func (w *walker) line(line string) {
	switch {
	case strings.HasPrefix(line, recordSep):
		w.flush()
		parts := strings.Split(strings.TrimPrefix(line, recordSep), fieldSep)
		if len(parts) == 3 {
			w.commit, w.author, w.date = parts[0], parts[1], parts[2]
			w.stats.Commits++
		}

	case strings.HasPrefix(line, "+++ "):
		w.flush()
		path := strings.TrimPrefix(line, "+++ ")
		if path == "/dev/null" {
			w.path = ""
			return
		}
		path = strings.TrimPrefix(path, "b/")
		if excluded(w.opts.Exclude, path) {
			w.path = ""
			return
		}
		w.path = path
		w.stats.Files++

	case strings.HasPrefix(line, "+"):
		if w.path == "" {
			return
		}
		if w.buf.Len() >= w.opts.MaxBlob {
			w.truncated = true
			return
		}
		body := line[1:]
		w.buf.WriteString(body)
		w.buf.WriteByte('\n')
		w.stats.Bytes += int64(len(body)) + 1
	}
}

// flush runs the templates over whatever the current file accumulated.
func (w *walker) flush() {
	defer func() {
		w.buf.Reset()
		w.truncated = false
	}()

	if w.path == "" || w.buf.Len() == 0 || w.commit == "" {
		return
	}

	content := []byte(w.buf.String())
	// A CRLF file appears in a diff as a CR at the end of each added line;
	// patterns are written against LF, so fold it here like scan does.
	content = bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))

	// The same self-exclusion scan makes. A commit that adds a rule adds
	// something shaped exactly like the credential the rule describes, and
	// reporting that is how a scanner ends up switched off. Only whole rules
	// are recognised — id, files and matchers together — so a one-line edit to
	// a template is still read normally.
	if engine.IsQalqonTemplate(content) {
		return
	}

	base := w.path
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}

	if w.seen == nil {
		w.seen = map[string]bool{}
	}

	for _, t := range w.set.Templates {
		if !t.AppliesTo(w.path, base) {
			continue
		}
		if !t.MayMatch(content) {
			continue
		}
		hits, ok := t.Match(content)
		if !ok {
			continue
		}
		for _, hit := range hits {
			// The same credential usually appears in many commits: once when
			// added, again in every rebase and merge that carried it. Report
			// the first commit that introduced it and stop.
			key := t.ID + "\x00" + w.path + "\x00" + hit.Text
			if w.seen[key] {
				continue
			}
			w.seen[key] = true

			w.findings = append(w.findings, engine.Finding{
				TemplateID:  t.ID,
				Name:        t.Info.Name,
				Severity:    t.Info.Severity,
				Description: t.Info.Description,
				Remediation: historyRemediation(t.Info.Remediation),
				Reference:   t.Info.Reference,
				Tags:        append(append([]string{}, t.Info.Tags...), "history"),
				File:        w.path,
				Match:       truncate(hit.Text, 160),
				Commit:      short(w.commit),
				Author:      w.author,
				Date:        w.date,
				Fixable:     t.Fixable(),
			})
		}
	}
}

// historyRemediation adds the part that only applies to history: rotating is
// not optional, because the value cannot be taken back out of every clone.
func historyRemediation(base string) string {
	const extra = "The value is in the history and in every clone, so rewriting the " +
		"commit does not undo the exposure: rotate it first."
	if base == "" {
		return extra
	}
	return strings.TrimRight(base, " ") + " " + extra
}

// excluded decides whether a path from the diff should be skipped.
//
// The walk sees whole paths rather than directory entries, so "testdata" has
// to match a segment of the path, not only a directory being descended into.
func excluded(patterns []string, path string) bool {
	if len(patterns) == 0 {
		return false
	}
	base := path
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	segments := strings.Split(path, "/")

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(strings.Trim(pattern, "/"))
		if pattern == "" {
			continue
		}
		if ok, _ := filepath.Match(pattern, base); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, path); ok {
			return true
		}
		if strings.HasPrefix(path, pattern+"/") {
			return true
		}
		for _, segment := range segments {
			if ok, _ := filepath.Match(pattern, segment); ok {
				return true
			}
		}
	}
	return false
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
