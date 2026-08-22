package deps

import (
	"os"
	"path/filepath"
	"testing"
)

// The published CVSS v3.1 examples. Getting these right is what lets one
// severity scale hold across ecosystems that label things differently.
func TestCVSSBaseScoreMatchesThePublishedExamples(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
	}
	for _, c := range cases {
		if got := cvssBaseScore(c.vector); got != c.want {
			t.Errorf("%s\n  got  %.1f\n  want %.1f", c.vector, got, c.want)
		}
	}
}

func TestCVSSIgnoresVectorsItCannotScore(t *testing.T) {
	// A v2 vector, a v4 vector and a truncated one all have to return zero
	// rather than a wrong number, so the caller falls back to the label.
	for _, v := range []string{
		"AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
		"CVSS:3.1/AV:N/AC:L",
		"",
	} {
		if got := cvssBaseScore(v); got != 0 {
			t.Errorf("%q: got %.1f, want 0", v, got)
		}
	}
}

func TestSeverityBands(t *testing.T) {
	cases := map[string]string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "critical", // 9.8
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": "high",     // 7.8
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": "medium",   // 5.9
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L": "low",      // 3.9
	}
	for vector, want := range cases {
		if got := severityFromCVSS(vector); got != want {
			t.Errorf("%s: got %s, want %s", vector, got, want)
		}
	}
}

/* --------------------------------------------------------------- parsers */

func TestParseGoMod(t *testing.T) {
	src := `module example.com/app

go 1.22

require (
	github.com/gin-gonic/gin v1.6.0
	golang.org/x/text v0.3.0 // indirect
)

require gopkg.in/yaml.v3 v3.0.0

replace example.com/old => ./local
`
	got, err := parseGoMod("go.mod", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d dependencies, want 3: %+v", len(got), got)
	}

	byName := map[string]Dependency{}
	for _, d := range got {
		byName[d.Name] = d
	}

	gin := byName["github.com/gin-gonic/gin"]
	if gin.Version != "1.6.0" {
		t.Errorf("the leading v should be stripped for OSV, got %q", gin.Version)
	}
	if !gin.Direct {
		t.Error("gin is a direct requirement")
	}
	if byName["golang.org/x/text"].Direct {
		t.Error("an // indirect requirement is not direct")
	}
	if _, ok := byName["example.com/old"]; ok {
		t.Error("a replace directive is not a requirement")
	}
	if gin.Ecosystem != "Go" {
		t.Errorf("ecosystem %q", gin.Ecosystem)
	}
}

func TestParseRequirementsOnlyTakesPinnedVersions(t *testing.T) {
	src := `# comment
django==4.2.1
requests==2.28.0  # trailing comment
flask>=2.0
urllib3
celery[redis]==5.2.7 ; python_version >= "3.8"
-r other.txt
`
	got, err := parseRequirements("requirements.txt", []byte(src))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"django":   "4.2.1",
		"requests": "2.28.0",
		"celery":   "5.2.7",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d, want %d: %+v", len(got), len(want), got)
	}
	for _, d := range got {
		if want[d.Name] != d.Version {
			t.Errorf("%s: got %q, want %q", d.Name, d.Version, want[d.Name])
		}
		if d.Ecosystem != "PyPI" {
			t.Errorf("ecosystem %q", d.Ecosystem)
		}
	}
}

func TestParseNPMLockBothFormats(t *testing.T) {
	v3 := `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.15"},
	    "node_modules/a/node_modules/minimist": {"version": "0.0.8"}
	  }
	}`
	got, err := parseNPMLock("package-lock.json", []byte(v3))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("v3: got %d, want 2: %+v", len(got), got)
	}
	for _, d := range got {
		switch d.Name {
		case "lodash":
			if !d.Direct || d.Version != "4.17.15" {
				t.Errorf("lodash: %+v", d)
			}
		case "minimist":
			if d.Direct {
				t.Error("a nested copy is not a direct dependency")
			}
		default:
			t.Errorf("unexpected package %q", d.Name)
		}
	}

	v1 := `{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "lodash": {"version": "4.17.15",
	      "dependencies": {"minimist": {"version": "0.0.8"}}}
	  }
	}`
	got, err = parseNPMLock("package-lock.json", []byte(v1))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("v1: got %d, want 2: %+v", len(got), got)
	}
}

func TestParseCargoLock(t *testing.T) {
	src := `version = 3

[[package]]
name = "time"
version = "0.1.44"

[[package]]
name = "libc"
version = "0.2.139"
dependencies = ["other"]

[metadata]
key = "value"
`
	got, err := parseCargoLock("Cargo.lock", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(got), got)
	}
	if got[0].Name != "time" || got[0].Version != "0.1.44" {
		t.Errorf("first package: %+v", got[0])
	}
	if got[0].Ecosystem != "crates.io" {
		t.Errorf("ecosystem %q", got[0].Ecosystem)
	}
}

func TestParseComposerLock(t *testing.T) {
	src := `{
	  "packages": [{"name": "monolog/monolog", "version": "v1.0.0"}],
	  "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]
	}`
	got, err := parseComposerLock("composer.lock", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].Version != "1.0.0" {
		t.Errorf("the v prefix should be stripped, got %q", got[0].Version)
	}
}

/* ----------------------------------------------------------------- walk */

func TestCollectFindsManifestsAndSkipsInstalledCopies(t *testing.T) {
	root := t.TempDir()

	write := func(rel, body string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("go.mod", "module x\n\nrequire github.com/a/b v1.0.0\n")
	write("web/requirements.txt", "django==4.2.1\n")
	// A vendored copy must not be read again: it describes the same tree.
	write("node_modules/pkg/package-lock.json",
		`{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0"}}}`)
	write(".git/requirements.txt", "should-not-appear==1.0.0\n")

	got, errs := Collect(root)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(got) != 2 {
		t.Fatalf("got %d dependencies, want 2: %+v", len(got), got)
	}
	for _, d := range got {
		if d.Name == "x" || d.Name == "should-not-appear" {
			t.Errorf("%s should have been skipped", d.Name)
		}
		if filepath.IsAbs(d.File) {
			t.Errorf("file should be relative to the root, got %q", d.File)
		}
	}
}

func TestCollectDeduplicates(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"a", "b"} {
		full := filepath.Join(root, dir)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, "requirements.txt"),
			[]byte("django==4.2.1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := Collect(root)
	if len(got) != 1 {
		t.Fatalf("the same package in two manifests should be reported once, got %+v", got)
	}
}

func TestCVEPrefersTheCVEAlias(t *testing.T) {
	v := Vulnerability{ID: "GHSA-xxxx", Aliases: []string{"GO-2021-0001", "CVE-2021-1234"}}
	if got := v.CVE(); got != "CVE-2021-1234" {
		t.Errorf("got %q", got)
	}
	bare := Vulnerability{ID: "GHSA-yyyy"}
	if got := bare.CVE(); got != "GHSA-yyyy" {
		t.Errorf("with no CVE alias the OSV id is the identifier, got %q", got)
	}
}
