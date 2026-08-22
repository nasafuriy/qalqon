// Package deps reads dependency manifests and asks a vulnerability database
// what is known about the versions it finds.
//
// This is the one part of qalqon that needs the network. Configuration
// scanning stays entirely offline; a dependency check cannot, because the
// answer changes every day and no useful copy of it fits in a binary.
package deps

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Dependency is one package at one version, and where it was declared.
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	File      string `json:"file"`
	Line      int    `json:"line,omitempty"`
	// Direct is false for a transitive dependency. Both are reported, since
	// a vulnerability reached through a chain is still reachable, but the
	// distinction changes who has to fix it.
	Direct bool `json:"direct"`
}

func (d Dependency) String() string { return d.Name + "@" + d.Version }

// manifest names we know how to read, mapped to the parser that reads them.
var parsers = map[string]func(path string, data []byte) ([]Dependency, error){
	"go.mod":            parseGoMod,
	"package-lock.json": parseNPMLock,
	"requirements.txt":  parseRequirements,
	"Cargo.lock":        parseCargoLock,
	"composer.lock":     parseComposerLock,
}

// skipDirs are never worth walking: they hold installed copies of the very
// packages the manifests already name.
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "target": true,
	".git": true, "dist": true, "build": true, "__pycache__": true,
	".venv": true, "venv": true, "site-packages": true,
}

// Collect walks root and returns every dependency declared by a manifest it
// recognises. Unreadable or malformed manifests are reported as errors but do
// not stop the walk: one bad file should not hide the rest of a repository.
func Collect(root string) ([]Dependency, []error) {
	var out []Dependency
	var errs []error

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (skipDirs[name] || strings.HasPrefix(name, ".") && name != ".") {
				return filepath.SkipDir
			}
			return nil
		}

		parse, ok := parsers[d.Name()]
		if !ok {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		found, err := parse(rel, data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", rel, err))
			return nil
		}
		out = append(out, found...)
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}
	return dedupe(out), errs
}

// dedupe keeps one entry per package/version/ecosystem. A monorepo commonly
// declares the same library in several manifests, and reporting the same
// advisory five times helps nobody.
func dedupe(in []Dependency) []Dependency {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, d := range in {
		key := d.Ecosystem + "\x00" + d.Name + "\x00" + d.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
}

/* ------------------------------------------------------------------ Go */

// parseGoMod reads require directives, in both the block and single-line
// forms. Indirect requirements are included: they are compiled into the
// binary just the same.
func parseGoMod(path string, data []byte) ([]Dependency, error) {
	var out []Dependency
	inBlock := false

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(stripComment(sc.Text()))
		if text == "" {
			continue
		}

		switch {
		case text == "require (":
			inBlock = true
			continue
		case inBlock && text == ")":
			inBlock = false
			continue
		case strings.HasPrefix(text, "require "):
			text = strings.TrimPrefix(text, "require ")
		case !inBlock:
			continue
		}

		fields := strings.Fields(text)
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "v") {
			continue
		}
		out = append(out, Dependency{
			Name: fields[0],
			// OSV records Go versions without the leading v.
			Version:   strings.TrimPrefix(fields[1], "v"),
			Ecosystem: "Go",
			File:      path,
			Line:      line,
			Direct:    !strings.Contains(sc.Text(), "// indirect"),
		})
	}
	return out, sc.Err()
}

func stripComment(s string) string {
	if i := strings.Index(s, "//"); i >= 0 {
		return s[:i]
	}
	return s
}

/* ---------------------------------------------------------------- npm */

type npmLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	// v2 and v3
	Packages map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"packages"`
	// v1
	Dependencies map[string]npmV1Entry `json:"dependencies"`
}

type npmV1Entry struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Dependencies map[string]npmV1Entry `json:"dependencies"`
}

func parseNPMLock(path string, data []byte) ([]Dependency, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var out []Dependency
	add := func(name, version string, direct bool) {
		if name == "" || version == "" {
			return
		}
		out = append(out, Dependency{
			Name: name, Version: version, Ecosystem: "npm",
			File: path, Direct: direct,
		})
	}

	// v2/v3: keys look like "node_modules/left-pad" or
	// "node_modules/a/node_modules/b" for a nested copy. The root entry has
	// an empty key and describes the project itself, so it is skipped.
	for key, p := range lock.Packages {
		if key == "" {
			continue
		}
		idx := strings.LastIndex(key, "node_modules/")
		if idx < 0 {
			continue
		}
		name := key[idx+len("node_modules/"):]
		// A top-level entry is a direct dependency; a nested one is not.
		add(name, p.Version, !strings.Contains(key[len("node_modules/"):], "node_modules/"))
	}

	// v1 nests the whole tree under "dependencies".
	var walk func(m map[string]npmV1Entry, direct bool)
	walk = func(m map[string]npmV1Entry, direct bool) {
		for name, e := range m {
			add(name, e.Version, direct)
			if len(e.Dependencies) > 0 {
				walk(e.Dependencies, false)
			}
		}
	}
	walk(lock.Dependencies, true)

	return out, nil
}

/* --------------------------------------------------------------- PyPI */

// parseRequirements only takes lines pinned with ==. A range such as
// "django>=4" does not name a version to look up, and guessing which one is
// installed would produce advisories for something nobody is running.
func parseRequirements(path string, data []byte) ([]Dependency, error) {
	var out []Dependency

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if i := strings.Index(text, "#"); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		if text == "" || strings.HasPrefix(text, "-") {
			continue // -r includes, -e editable installs, pip flags
		}
		// Drop environment markers and extras: "pkg[extra]==1.0 ; python>=3"
		if i := strings.Index(text, ";"); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		name, version, ok := strings.Cut(text, "==")
		if !ok {
			continue
		}
		if i := strings.Index(name, "["); i >= 0 {
			name = name[:i]
		}
		version = strings.TrimSpace(strings.Trim(version, "="))
		name = strings.TrimSpace(name)
		if name == "" || version == "" || strings.ContainsAny(version, "*<>! ") {
			continue
		}
		out = append(out, Dependency{
			Name: name, Version: version, Ecosystem: "PyPI",
			File: path, Line: line, Direct: true,
		})
	}
	return out, sc.Err()
}

/* --------------------------------------------------------------- Rust */

// parseCargoLock reads the [[package]] tables. The file is TOML, but the
// shape here is simple enough that a line reader is clearer than pulling in
// a parser for it.
func parseCargoLock(path string, data []byte) ([]Dependency, error) {
	var out []Dependency
	var name, version string
	var startLine int

	flush := func() {
		if name != "" && version != "" {
			out = append(out, Dependency{
				Name: name, Version: version, Ecosystem: "crates.io",
				File: path, Line: startLine, Direct: false,
			})
		}
		name, version = "", ""
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		switch {
		case text == "[[package]]":
			flush()
			startLine = line
		case strings.HasPrefix(text, "name = "):
			name = strings.Trim(strings.TrimPrefix(text, "name = "), `"`)
		case strings.HasPrefix(text, "version = "):
			version = strings.Trim(strings.TrimPrefix(text, "version = "), `"`)
		case strings.HasPrefix(text, "["):
			flush() // any other table ends the current package
		}
	}
	flush()
	return out, sc.Err()
}

/* ----------------------------------------------------------------- PHP */

type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseComposerLock(path string, data []byte) ([]Dependency, error) {
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Dependency
	for _, group := range [][]composerPkg{lock.Packages, lock.PackagesDev} {
		for _, p := range group {
			if p.Name == "" || p.Version == "" {
				continue
			}
			out = append(out, Dependency{
				Name: p.Name,
				// Composer writes tags as v1.2.3; OSV records 1.2.3.
				Version:   strings.TrimPrefix(p.Version, "v"),
				Ecosystem: "Packagist",
				File:      path, Direct: true,
			})
		}
	}
	return out, nil
}
