package history

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nasafuriy/qalqon/internal/template"
)

// A rule that finds the fixture credential, kept local so these tests do not
// depend on the shape of the shipped library.
const secretRule = `
id: test-aws-key
type: file
info:
  name: AWS access key id in source
  severity: critical
  remediation: Disable the key in IAM.
  tags: [secret]
files:
  - "*.env"
  - "*.txt"
matchers:
  - patterns:
      - 'AKIA[0-9A-Z]{16}'
`

func ruleSet(t *testing.T) *template.Set {
	t.Helper()
	fsys := fstest.MapFS{
		"rules/secret.yaml": &fstest.MapFile{Data: []byte(secretRule)},
	}
	set, errs := template.Load(fsys, "rules")
	if len(errs) > 0 {
		t.Fatal(errs[0])
	}
	if set.Len() != 1 {
		t.Fatalf("loaded %d templates, want 1", set.Len())
	}
	return set
}

type repo struct {
	t   *testing.T
	dir string
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	r := &repo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.git("config", "user.name", "Test")
	r.git("config", "user.email", "test@example.com")
	return r
}

func (r *repo) git(args ...string) {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func (r *repo) commit(name, body, message string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, name), []byte(body), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.git("add", "-A")
	r.git("commit", "-q", "-m", message)
}

func scan(t *testing.T, dir string, opts Options) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts.Root = dir
	findings, _, err := Scan(ctx, ruleSet(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.TemplateID)
	}
	return ids
}

// The point of the whole command: a credential removed in a later commit is
// still in the history, and a working-tree scan cannot see it.
func TestFindsASecretThatWasLaterRemoved(t *testing.T) {
	r := newRepo(t)
	r.commit("config.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", "add config")
	r.commit("config.env", "AWS_ACCESS_KEY_ID=${FROM_ENV}\n", "move it out")

	// The file as it stands carries nothing.
	body, err := os.ReadFile(filepath.Join(r.dir, "config.env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "AKIA") {
		t.Fatal("the fixture did not actually remove the secret")
	}

	if got := scan(t, r.dir, Options{}); len(got) != 1 || got[0] != "test-aws-key" {
		t.Fatalf("got %v, want one test-aws-key finding", got)
	}
}

func TestReportsTheCommitThatIntroducedIt(t *testing.T) {
	r := newRepo(t)
	r.commit("a.txt", "nothing here\n", "first")
	r.commit("config.env", "key=AKIAIOSFODNN7EXAMPLE\n", "add the key")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	findings, stats, err := Scan(ctx, ruleSet(t), Options{Root: r.dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Commit == "" {
		t.Error("no commit recorded")
	}
	if f.Author != "Test" {
		t.Errorf("author %q", f.Author)
	}
	if f.File != "config.env" {
		t.Errorf("file %q", f.File)
	}
	if !strings.Contains(f.Remediation, "rotate") {
		t.Errorf("remediation should say to rotate: %q", f.Remediation)
	}
	if stats.Commits != 2 {
		t.Errorf("walked %d commits, want 2", stats.Commits)
	}
}

// A credential that survives many commits should be reported once, not once
// per commit that carried it forward.
func TestReportsEachSecretOnce(t *testing.T) {
	r := newRepo(t)
	r.commit("config.env", "key=AKIAIOSFODNN7EXAMPLE\n", "add")
	for i := 0; i < 3; i++ {
		r.commit("config.env", "key=AKIAIOSFODNN7EXAMPLE\nn="+strings.Repeat("x", i+1)+"\n", "touch")
	}

	if got := scan(t, r.dir, Options{}); len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(got), got)
	}
}

func TestCleanHistoryReportsNothing(t *testing.T) {
	r := newRepo(t)
	r.commit("config.env", "AWS_ACCESS_KEY_ID=${FROM_ENV}\n", "config")
	r.commit("readme.txt", "no credentials here\n", "docs")

	if got := scan(t, r.dir, Options{}); len(got) != 0 {
		t.Fatalf("got %v, want nothing", got)
	}
}

func TestMaxCommitsLimitsTheWalk(t *testing.T) {
	r := newRepo(t)
	r.commit("config.env", "key=AKIAIOSFODNN7EXAMPLE\n", "the secret")
	r.commit("readme.txt", "later\n", "second")
	r.commit("other.txt", "later still\n", "third")

	// Only the most recent commit, which added nothing interesting.
	if got := scan(t, r.dir, Options{MaxCommits: 1}); len(got) != 0 {
		t.Fatalf("got %v, want nothing within one commit", got)
	}
	// The whole history still finds it.
	if got := scan(t, r.dir, Options{}); len(got) != 1 {
		t.Fatalf("got %v, want the secret", got)
	}
}

func TestAvailableRejectsSomethingThatIsNotARepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	if err := Available(t.TempDir()); err == nil {
		t.Error("a plain directory was accepted as a repository")
	}
}

func TestScanReportsANonRepositoryClearly(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, err := Scan(ctx, ruleSet(t), Options{Root: t.TempDir()})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestExcludeSkipsPaths(t *testing.T) {
	r := newRepo(t)
	if err := os.MkdirAll(filepath.Join(r.dir, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.commit("testdata/fixture.env", "key=AKIAIOSFODNN7EXAMPLE\n", "add a fixture")
	r.commit("real.env", "key=AKIAIOSFODNN7EXAMPLE\n", "add the real one")

	// Both are found when nothing is excluded.
	if got := scan(t, r.dir, Options{}); len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %v", len(got), got)
	}

	// A repository that keeps deliberately insecure fixtures needs to be able
	// to say so, or the real finding is buried.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	findings, _, err := Scan(ctx, ruleSet(t), Options{
		Root:    r.dir,
		Exclude: []string{"testdata"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].File != "real.env" {
		t.Errorf("kept the wrong one: %s", findings[0].File)
	}
}

func TestExcludeMatchesSeveralShapes(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"testdata", "testdata/vulnerable/.env", true}, // a leading segment
		{"testdata", "a/testdata/b.env", true},         // a segment anywhere
		{"*.env", "config/app.env", true},              // the base name
		{"testdata/*", "testdata/a.env", true},         // an explicit glob
		{"testdata", "testdata.env", false},            // not a prefix match
		{"vendor", "src/main.go", false},
	}
	for _, c := range cases {
		if got := excluded([]string{c.pattern}, c.path); got != c.want {
			t.Errorf("excluded(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}
