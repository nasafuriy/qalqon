// Command qalqon scans a working tree for configuration mistakes using a
// library of small YAML templates.
//
//	qalqon .                     scan the current directory
//	qalqon scan ./infra -sarif   emit SARIF for GitHub code scanning
//	qalqon templates             list what will be run
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/nasafuriy/qalqon"
	"github.com/nasafuriy/qalqon/internal/deps"
	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/history"
	"github.com/nasafuriy/qalqon/internal/output"
	"github.com/nasafuriy/qalqon/internal/probe"
	"github.com/nasafuriy/qalqon/internal/template"
)

// version is stamped at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}

	command := args[0]
	rest := args[1:]

	switch command {
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "qalqon %s\n", version)
		return exitOK
	case "templates":
		return listTemplates(rest, stdout, stderr)
	case "validate":
		return validate(rest, stdout, stderr)
	case "scan":
		return scan(rest, stdout, stderr)
	case "target":
		return scanTargets(rest, stdout, stderr)
	case "deps":
		return scanDeps(rest, stdout, stderr)
	case "history":
		return scanHistory(rest, stdout, stderr)
	default:
		// Allow "qalqon ." as shorthand for "qalqon scan .".
		if strings.HasPrefix(command, "-") || fileish(command) {
			return scan(args, stdout, stderr)
		}
		fmt.Fprintf(stderr, "qalqon: unknown command %q\n\n", command)
		usage(stderr)
		return exitError
	}
}

func fileish(s string) bool {
	if s == "." || s == ".." {
		return true
	}
	_, err := os.Stat(s)
	return err == nil
}

/* ------------------------------------------------------------------ scan */

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func scan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dirs       stringList
		severities stringList
		tags       stringList
		ids        stringList
		exclude    stringList
	)
	fs.Var(&dirs, "t", "extra template directory (repeatable)")
	fs.Var(&severities, "severity", "only run templates with these severities")
	fs.Var(&tags, "tags", "only run templates carrying these tags")
	fs.Var(&ids, "id", "only run these template ids")
	fs.Var(&exclude, "exclude", "skip paths matching these globs")

	minSeverity := fs.String("min-severity", "", "skip templates below this severity")
	failOn := fs.String("fail-on", "low", "exit 1 when a finding at this severity or above is reported (none disables)")
	concurrency := fs.Int("c", 0, "worker count (default: one per CPU)")
	maxSize := fs.Int64("max-size", 0, "skip files larger than this many bytes")
	noBuiltin := fs.Bool("no-builtin", false, "ignore the embedded template library")
	hidden := fs.Bool("hidden", false, "also scan dot-directories")

	asJSON := fs.Bool("json", false, "write a JSON report")
	asJSONL := fs.Bool("jsonl", false, "write one JSON finding per line")
	asSARIF := fs.Bool("sarif", false, "write SARIF 2.1.0 for GitHub code scanning")
	outPath := fs.String("o", "", "write output to a file instead of stdout")

	quiet := fs.Bool("quiet", false, "findings only, no header or summary")
	stats := fs.Bool("stats", false, "print scan throughput")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	forceColor := fs.Bool("color", false, "force ANSI colour even when piped")

	fs.Usage = func() { usage(stderr) }
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return exitError
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	if _, err := os.Stat(root); err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}

	set, code := loadTemplates(dirs, *noBuiltin, stderr)
	if code != exitOK {
		return code
	}

	var min template.Severity
	if *minSeverity != "" {
		parsed, err := template.ParseSeverity(*minSeverity)
		if err != nil {
			fmt.Fprintf(stderr, "qalqon: %v\n", err)
			return exitError
		}
		min = parsed
	}

	set = set.Filter(min, severities, tags, ids).OfKind(template.KindFile)
	if set.Len() == 0 {
		fmt.Fprintln(stderr, "qalqon: no file templates match those filters")
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	findings, runStats, err := engine.Run(ctx, set, engine.Options{
		Root:        root,
		Concurrency: *concurrency,
		Exclude:     exclude,
		Hidden:      *hidden,
		MaxFileSize: *maxSize,
	})
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}

	sink := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(stderr, "qalqon: %v\n", err)
			return exitError
		}
		defer f.Close()
		sink = f
	}

	switch {
	case *asSARIF:
		err = output.SARIF(sink, findings, version)
	case *asJSONL:
		err = output.JSONL(sink, findings)
	case *asJSON:
		err = output.JSON(sink, findings, runStats, root, version)
	default:
		err = output.Text(sink, findings, runStats, output.TextOptions{
			Color:   *outPath == "" && output.ColorEnabled(*forceColor, *noColor),
			Quiet:   *quiet,
			Stats:   *stats,
			Version: version,
		})
	}
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}

	if strings.EqualFold(*failOn, "none") || len(findings) == 0 {
		return exitOK
	}
	threshold, err := template.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}
	if output.Highest(findings).Rank() >= threshold.Rank() {
		return exitFindings
	}
	return exitOK
}

// discoverTargets turns a list of hosts into a list of URLs to probe, by
// finding which ports are actually listening.
//
// It runs before the templates do, and prints what it found, because the
// answer is worth seeing on its own: a port nobody remembered leaving open
// is a finding even when the service on it turns out to be fine.
func discoverTargets(hosts []string, spec string, timeout time.Duration,
	stdout, stderr io.Writer, quiet bool) ([]string, error) {

	ports, err := probe.ParsePorts(spec)
	if err != nil {
		return nil, err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var out []string
	for _, host := range hosts {
		open, err := probe.Discover(ctx, host, probe.DiscoverOptions{
			Ports:   ports,
			Timeout: timeout,
		})
		if err != nil && len(open) == 0 {
			return nil, err
		}

		if !quiet {
			label := host
			if len(ports) > 0 {
				label = fmt.Sprintf("%s (%d ports)", host, len(ports))
			} else {
				label = fmt.Sprintf("%s (%d common ports)", host, len(probe.DefaultPorts))
			}
			fmt.Fprintf(stdout, "%s → %d listening\n", label, len(open))
			for _, p := range open {
				scheme := "http"
				if p.TLS {
					scheme = "https"
				}
				fmt.Fprintf(stdout, "  %-6d %s\n", p.Port, scheme)
			}
			fmt.Fprintln(stdout)
		}

		for _, p := range open {
			out = append(out, p.URL(host))
		}
	}
	return out, nil
}

/* ---------------------------------------------------------------- history */

// scanHistory runs the secret rules over what each commit added, rather than
// over the files that happen to be checked out.
//
// Deleting a credential in a later commit does not remove it. It stays in
// the history, in every clone, and in the forge's API, so a working-tree
// scan gives exactly the wrong answer to someone who thinks they cleaned it
// up. Rotating is the only fix, which is why the remediation says so.
func scanHistory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dirs       stringList
		severities stringList
		tags       stringList
		ids        stringList
		exclude    stringList
	)
	fs.Var(&dirs, "t", "extra template directory (repeatable)")
	fs.Var(&severities, "severity", "only run templates with these severities")
	fs.Var(&tags, "tags", "only run templates carrying these tags")
	fs.Var(&ids, "id", "only run these template ids")
	fs.Var(&exclude, "exclude", "skip paths matching these globs")

	maxCommits := fs.Int("n", 0, "stop after this many commits (0 scans all)")
	since := fs.String("since", "", `only commits after this, e.g. "6 months ago"`)
	minSeverity := fs.String("min-severity", "", "skip templates below this severity")
	failOn := fs.String("fail-on", "low", "exit 1 at this severity or above (none disables)")
	noBuiltin := fs.Bool("no-builtin", false, "ignore the embedded template library")
	allRules := fs.Bool("all-rules", false, "run every file rule, not only the secret ones")

	asJSON := fs.Bool("json", false, "write a JSON report")
	asJSONL := fs.Bool("jsonl", false, "write one JSON finding per line")
	asSARIF := fs.Bool("sarif", false, "write SARIF 2.1.0")
	outPath := fs.String("o", "", "write to this file instead of stdout")
	quiet := fs.Bool("quiet", false, "findings only")
	stats := fs.Bool("stats", false, "print throughput")
	forceColor := fs.Bool("color", false, "force ANSI colour")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")

	fs.Usage = func() { usage(stderr) }
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return exitError
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}

	set, code := loadTemplates(dirs, *noBuiltin, stderr)
	if code != exitOK {
		return code
	}

	var min template.Severity
	if *minSeverity != "" {
		parsed, err := template.ParseSeverity(*minSeverity)
		if err != nil {
			fmt.Fprintf(stderr, "qalqon: %v\n", err)
			return exitError
		}
		min = parsed
	}

	set = set.Filter(min, severities, tags, ids).OfKind(template.KindFile)
	// Configuration rules judge a file as it stands; a diff hunk is not that
	// file, so running them over history mostly produces noise. Secrets are
	// the exception: a credential is a credential wherever it appears.
	if !*allRules && len(tags) == 0 && len(ids) == 0 {
		set = set.Filter(min, nil, stringList{"secret"}, nil)
	}
	if set.Len() == 0 {
		fmt.Fprintln(stderr, "qalqon: no file templates match those filters")
		return exitError
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	findings, hstats, err := history.Scan(ctx, set, history.Options{
		Root:       root,
		MaxCommits: *maxCommits,
		Since:      *since,
		Exclude:    exclude,
	})
	if err != nil && len(findings) == 0 {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}

	runStats := engine.Stats{
		FilesWalked:  int64(hstats.Commits),
		FilesRead:    int64(hstats.Files),
		BytesRead:    hstats.Bytes,
		TemplatesRun: set.Len(),
		Duration:     hstats.Duration,
	}

	sink := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(stderr, "qalqon: %v\n", err)
			return exitError
		}
		defer f.Close()
		sink = f
	}

	switch {
	case *asSARIF:
		err = output.SARIF(sink, findings, version)
	case *asJSONL:
		err = output.JSONL(sink, findings)
	case *asJSON:
		err = output.JSON(sink, findings, runStats, root, version)
	default:
		err = output.Text(sink, findings, runStats, output.TextOptions{
			Color:   *outPath == "" && output.ColorEnabled(*forceColor, *noColor),
			Quiet:   *quiet,
			Stats:   *stats,
			Version: version,
			Unit:    "commits",
		})
	}
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}

	if strings.EqualFold(*failOn, "none") || len(findings) == 0 {
		return exitOK
	}
	threshold, err := template.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}
	if output.Highest(findings).Rank() >= threshold.Rank() {
		return exitFindings
	}
	return exitOK
}

/* ------------------------------------------------------------ dependencies */

// scanDeps reads the dependency manifests under a path and asks OSV what is
// known about the versions it finds.
//
// This is the only command that needs the network. Configuration scanning
// stays offline on purpose; a vulnerability database cannot, because the
// answer changes daily and no useful copy of it fits in a binary. That is
// why it is a separate command rather than part of scan: nothing you run
// today should suddenly start making requests.
func scanDeps(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("deps", flag.ContinueOnError)
	fs.SetOutput(stderr)

	timeout := fs.Duration("timeout", 60*time.Second, "give up on the database after this long")
	listOnly := fs.Bool("list", false, "list the dependencies found and stop, without querying")
	failOn := fs.String("fail-on", "low", "exit 1 when a finding at this severity or above is reported (none disables)")
	directOnly := fs.Bool("direct", false, "only report on dependencies this project declares itself")

	asJSON := fs.Bool("json", false, "write a JSON report")
	asJSONL := fs.Bool("jsonl", false, "write one JSON finding per line")
	asSARIF := fs.Bool("sarif", false, "write SARIF 2.1.0")
	outPath := fs.String("o", "", "write to this file instead of stdout")
	quiet := fs.Bool("quiet", false, "findings only")
	stats := fs.Bool("stats", false, "print throughput")
	forceColor := fs.Bool("color", false, "force ANSI colour")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")

	if err := fs.Parse(reorder(fs, args)); err != nil {
		return exitError
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	if _, err := os.Stat(root); err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}

	started := time.Now()
	found, errs := deps.Collect(root)
	for _, err := range errs {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
	}

	if len(found) == 0 {
		if !*quiet {
			fmt.Fprintf(stdout, "qalqon · no dependency manifests found under %s\n", root)
			fmt.Fprintf(stdout, "  looked for: go.mod, package-lock.json, requirements.txt, Cargo.lock, composer.lock\n")
		}
		return exitOK
	}

	if *directOnly {
		kept := found[:0]
		for _, d := range found {
			if d.Direct {
				kept = append(kept, d)
			}
		}
		found = kept
	}

	if *listOnly {
		for _, d := range found {
			kind := "indirect"
			if d.Direct {
				kind = "direct"
			}
			fmt.Fprintf(stdout, "%-12s %-10s %s\n", d.Ecosystem, kind, d)
		}
		fmt.Fprintf(stdout, "\n%d dependencies\n", len(found))
		return exitOK
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	vulns, err := deps.NewClient(*timeout).Query(ctx, found)
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: querying osv.dev: %v\n", err)
		fmt.Fprintf(stderr, "  this command needs network access; use -list to see the dependencies offline\n")
		return exitError
	}

	findings := dependencyFindings(vulns)

	manifests := map[string]bool{}
	for _, d := range found {
		manifests[d.File] = true
	}
	runStats := engine.Stats{
		FilesWalked:  int64(len(manifests)),
		FilesRead:    int64(len(manifests)),
		TemplatesRun: len(found),
		Duration:     time.Since(started),
	}

	sink := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(stderr, "qalqon: %v\n", err)
			return exitError
		}
		defer f.Close()
		sink = f
	}

	switch {
	case *asSARIF:
		err = output.SARIF(sink, findings, version)
	case *asJSONL:
		err = output.JSONL(sink, findings)
	case *asJSON:
		err = output.JSON(sink, findings, runStats, root, version)
	default:
		err = output.Text(sink, findings, runStats, output.TextOptions{
			Color:   *outPath == "" && output.ColorEnabled(*forceColor, *noColor),
			Quiet:   *quiet,
			Stats:   *stats,
			Version: version,
			Unit:    "manifests",
			Rules:   "dependencies",
		})
	}
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}

	if strings.EqualFold(*failOn, "none") || len(findings) == 0 {
		return exitOK
	}
	threshold, err := template.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}
	if output.Highest(findings).Rank() >= threshold.Rank() {
		return exitFindings
	}
	return exitOK
}

// dependencyFindings turns advisories into the same Finding the rest of the
// tool reports, so every output format keeps working unchanged.
func dependencyFindings(vulns []deps.Vulnerability) []engine.Finding {
	out := make([]engine.Finding, 0, len(vulns))
	for _, v := range vulns {
		severity, err := template.ParseSeverity(v.Severity)
		if err != nil {
			// An advisory with no score still deserves to be seen.
			severity = template.SeverityInfo
		}

		name := v.Summary
		if name == "" {
			name = "Known vulnerability in " + v.Dep.Name
		}

		remediation := "No fixed version is published yet. Check whether the advisory lists a workaround, or whether the package is still needed."
		if len(v.FixedIn) > 0 {
			remediation = fmt.Sprintf("Upgrade %s to %s or later.",
				v.Dep.Name, v.FixedIn[0])
		}

		tags := []string{"dependency", "cve", strings.ToLower(v.Dep.Ecosystem)}
		if !v.Dep.Direct {
			tags = append(tags, "transitive")
		}

		out = append(out, engine.Finding{
			TemplateID:  v.CVE(),
			Name:        name,
			Severity:    severity,
			Description: strings.TrimSpace(firstParagraph(v.Details)),
			Remediation: remediation,
			Reference:   []string{"https://osv.dev/vulnerability/" + v.ID},
			Tags:        tags,
			File:        v.Dep.File,
			Line:        v.Dep.Line,
			Match:       v.Dep.String(),
		})
	}
	return out
}

// firstParagraph keeps a report readable. OSV details run to several
// paragraphs of markdown; the opening one carries the point.
func firstParagraph(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n\n"); i > 0 {
		s = s[:i]
	}
	if len(s) > 400 {
		s = strings.TrimSpace(s[:400]) + "…"
	}
	return strings.ReplaceAll(s, "\n", " ")
}

/* ---------------------------------------------------------------- targets */

func scanTargets(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("target", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dirs       stringList
		severities stringList
		tags       stringList
		ids        stringList
	)
	fs.Var(&dirs, "t", "extra template directory (repeatable)")
	fs.Var(&severities, "severity", "only run templates with these severities")
	fs.Var(&tags, "tags", "only run templates carrying these tags")
	fs.Var(&ids, "id", "only run these template ids")

	listFile := fs.String("l", "", "read targets from a file, one per line")
	discover := fs.Bool("discover", false, "find the listening ports on each host first")
	portSpec := fs.String("ports", "", "ports to try with -discover, e.g. 80,443,8000-8100")
	tlsVersions := fs.Bool("tls-versions", false, "ask which TLS versions each host accepts (one extra handshake per version)")
	timeout := fs.Duration("timeout", probe.DefaultTimeout, "per-target timeout")
	concurrency := fs.Int("c", 4, "targets probed in parallel (capped at 10)")
	userAgent := fs.String("ua", "", "override the User-Agent header")
	maxBody := fs.Int64("max-body", probe.DefaultMaxBody, "bytes of response body to read")
	minSeverity := fs.String("min-severity", "", "skip templates below this severity")
	failOn := fs.String("fail-on", "low", "exit 1 at this severity or above (none disables)")
	noBuiltin := fs.Bool("no-builtin", false, "ignore the embedded template library")

	asJSON := fs.Bool("json", false, "write a JSON report")
	asJSONL := fs.Bool("jsonl", false, "write one JSON finding per line")
	asSARIF := fs.Bool("sarif", false, "write SARIF 2.1.0")
	outPath := fs.String("o", "", "write output to a file instead of stdout")
	quiet := fs.Bool("quiet", false, "findings only")
	stats := fs.Bool("stats", false, "print timing")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	forceColor := fs.Bool("color", false, "force ANSI colour even when piped")

	fs.Usage = func() { usage(stderr) }
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return exitError
	}

	targets := append([]string{}, fs.Args()...)
	if *listFile != "" {
		lines, err := readLines(*listFile)
		if err != nil {
			fmt.Fprintf(stderr, "qalqon: %v\n", err)
			return exitError
		}
		targets = append(targets, lines...)
	}
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "usage: qalqon target <url>... [-l targets.txt]")
		fmt.Fprintln(stderr, "\nProbe only hosts you run or are authorised to test.")
		return exitError
	}

	if *discover {
		found, err := discoverTargets(targets, *portSpec, *timeout, stdout, stderr, *quiet)
		if err != nil {
			fmt.Fprintf(stderr, "qalqon: %v\n", err)
			return exitError
		}
		if len(found) == 0 {
			if !*quiet {
				fmt.Fprintln(stdout, "No listening ports found.")
			}
			return exitOK
		}
		targets = found
	}

	set, code := loadTemplates(dirs, *noBuiltin, stderr)
	if code != exitOK {
		return code
	}

	var min template.Severity
	if *minSeverity != "" {
		parsed, err := template.ParseSeverity(*minSeverity)
		if err != nil {
			fmt.Fprintf(stderr, "qalqon: %v\n", err)
			return exitError
		}
		min = parsed
	}

	set = set.Filter(min, severities, tags, ids).OfKind(template.KindHTTP)
	if set.Len() == 0 {
		fmt.Fprintln(stderr, "qalqon: no http templates match those filters")
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	findings, failures, runStats, err := engine.RunTargets(ctx, set, targets, engine.TargetOptions{
		Concurrency:      *concurrency,
		Timeout:          *timeout,
		MaxBody:          *maxBody,
		UserAgent:        *userAgent,
		CheckTLSVersions: *tlsVersions,
	})
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}

	sink := stdout
	if *outPath != "" {
		f, createErr := os.Create(*outPath)
		if createErr != nil {
			fmt.Fprintf(stderr, "qalqon: %v\n", createErr)
			return exitError
		}
		defer f.Close()
		sink = f
	}

	switch {
	case *asSARIF:
		err = output.SARIF(sink, findings, version)
	case *asJSONL:
		err = output.JSONL(sink, findings)
	case *asJSON:
		err = output.JSONTargets(sink, findings, failures, runStats, version)
	default:
		err = output.Text(sink, findings, runStats, output.TextOptions{
			Color:   *outPath == "" && output.ColorEnabled(*forceColor, *noColor),
			Quiet:   *quiet,
			Stats:   *stats,
			Version: version,
			Unit:    "targets",
		})
	}
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}

	// A target that could not be reached is an input problem, not a finding,
	// so it goes to stderr and does not affect the findings exit code.
	for _, f := range failures {
		fmt.Fprintf(stderr, "qalqon: %s: %s\n", f.Target, f.Err)
	}

	if strings.EqualFold(*failOn, "none") || len(findings) == 0 {
		if len(failures) > 0 && len(targets) == len(failures) {
			return exitError
		}
		return exitOK
	}
	threshold, err := template.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}
	if output.Highest(findings).Rank() >= threshold.Rank() {
		return exitFindings
	}
	return exitOK
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

/* -------------------------------------------------------------- templates */

func listTemplates(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("templates", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var dirs stringList
	fs.Var(&dirs, "t", "extra template directory (repeatable)")
	noBuiltin := fs.Bool("no-builtin", false, "ignore the embedded template library")
	asJSON := fs.Bool("json", false, "write the list as JSON")
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return exitError
	}

	set, code := loadTemplates(dirs, *noBuiltin, stderr)
	if code != exitOK {
		return code
	}

	if *asJSON {
		type row struct {
			ID       string   `json:"id"`
			Name     string   `json:"name"`
			Severity string   `json:"severity"`
			Tags     []string `json:"tags"`
			Files    []string `json:"files"`
		}
		rows := make([]row, 0, set.Len())
		for _, t := range set.Templates {
			rows = append(rows, row{t.ID, t.Info.Name, string(t.Info.Severity), t.Info.Tags, t.Files})
		}
		return writeJSON(stdout, stderr, rows)
	}

	width := 0
	for _, t := range set.Templates {
		if len(t.ID) > width {
			width = len(t.ID)
		}
	}
	for _, t := range set.Templates {
		fmt.Fprintf(stdout, "%-*s  %-5s  %-8s  %s\n", width, t.ID, t.Type, t.Info.Severity, t.Info.Name)
	}
	fmt.Fprintf(stdout, "\n%d templates (%d file, %d http)\n",
		set.Len(), set.OfKind(template.KindFile).Len(), set.OfKind(template.KindHTTP).Len())
	return exitOK
}

func validate(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: qalqon validate <directory>")
		return exitError
	}

	total, bad := 0, 0
	for _, dir := range args {
		set, errs := template.Load(os.DirFS(dir), ".")
		total += set.Len()
		for _, err := range errs {
			bad++
			fmt.Fprintf(stderr, "%s: %v\n", dir, err)
		}
	}

	if bad > 0 {
		fmt.Fprintf(stderr, "\n%d template(s) rejected\n", bad)
		return exitError
	}
	fmt.Fprintf(stdout, "%d template(s) valid\n", total)
	return exitOK
}

/* ------------------------------------------------------------------ util */

func loadTemplates(dirs []string, noBuiltin bool, stderr io.Writer) (*template.Set, int) {
	merged := map[string]*template.Template{}
	var order []string

	add := func(set *template.Set) {
		for _, t := range set.Templates {
			if _, seen := merged[t.ID]; !seen {
				order = append(order, t.ID)
			}
			merged[t.ID] = t // later sources win, so a custom copy can override
		}
	}

	if !noBuiltin {
		set, errs := template.Load(qalqon.Templates, "templates")
		for _, err := range errs {
			fmt.Fprintf(stderr, "qalqon: built-in template: %v\n", err)
		}
		if len(errs) > 0 {
			return nil, exitError
		}
		add(set)
	}

	for _, dir := range dirs {
		set, errs := template.Load(os.DirFS(dir), ".")
		for _, err := range errs {
			fmt.Fprintf(stderr, "qalqon: %s: %v\n", dir, err)
		}
		if len(errs) > 0 {
			return nil, exitError
		}
		add(set)
	}

	sort.Strings(order)
	out := &template.Set{}
	for _, id := range order {
		out.Templates = append(out.Templates, merged[id])
	}

	if out.Len() == 0 {
		fmt.Fprintln(stderr, "qalqon: no templates loaded")
		return nil, exitError
	}
	return out, exitOK
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(stderr, "qalqon: %v\n", err)
		return exitError
	}
	return exitOK
}

// reorder moves positional arguments after the flags, so both
// "qalqon scan -json ." and "qalqon scan . -json" work.
func reorder(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") {
				name := strings.TrimLeft(a, "-")
				if f := fs.Lookup(name); f != nil && !isBoolFlag(f) && i+1 < len(args) {
					i++
					flags = append(flags, args[i])
				}
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

func isBoolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `qalqon %s — find configuration mistakes before they ship

USAGE
  qalqon <path>                    scan a directory or file
  qalqon scan <path> [flags]
  qalqon target <url>... [flags]   check hosts you run: headers, cookies, TLS
  qalqon deps <path> [flags]       check dependency versions against osv.dev
  qalqon history <path> [flags]    look for secrets in commits, not just files
  qalqon templates [flags]         list the templates that would run
  qalqon validate <dir>            check your own templates parse
  qalqon version

DEPS FLAGS
  -list             list what was found and stop, without querying
  -direct           only what this project declares itself, not the whole tree
  -timeout D        give up on the database after this long (default 60s)

  Reads go.mod, package-lock.json, requirements.txt, Cargo.lock and
  composer.lock. This is the only command that uses the network: scanning
  configuration stays offline, because a vulnerability database cannot.

HISTORY FLAGS
  -n N              stop after this many commits
  -since WHEN       only commits after this, e.g. -since "6 months ago"
  -all-rules        run every file rule, not only the secret ones
  -exclude GLOB     skip matching paths (repeatable)

  Runs the secret rules over what each commit added. A credential deleted in
  a later commit is still in the history and in every clone, so a scan of
  the working tree reports nothing while the value is still exposed. That is
  also why the remediation says to rotate rather than to rewrite.

TARGET FLAGS
  -l FILE           read targets from a file, one per line
  -discover         find the listening ports on each host first
  -ports SPEC       ports to try with -discover, e.g. 80,443,8000-8100
  -tls-versions     ask which TLS versions each host accepts
  -timeout D        per-target timeout (default 10s)
  -c N              targets in parallel, capped at 10
  -ua STRING        override the User-Agent
  -max-body N       bytes of response body to read

  Each target gets one ordinary GET — no path guessing, no payloads, no
  authentication attempts. -discover opens a TCP connection per port and
  nothing more, and defaults to a short list of ports where web services
  actually live. Probe only hosts you operate or are authorised to test.

SCAN FLAGS
  -t DIR            extra template directory (repeatable)
  -no-builtin       ignore the embedded library
  -severity LIST    only these severities, e.g. -severity high,critical
  -min-severity S   skip everything below S
  -tags LIST        only templates with these tags, e.g. -tags docker
  -id LIST          only these template ids
  -exclude GLOB     skip matching paths (repeatable)
  -hidden           also scan dot-directories
  -c N              workers (default: one per CPU)
  -max-size N       skip files larger than N bytes

OUTPUT
  -json             a JSON report
  -jsonl            one JSON finding per line
  -sarif            SARIF 2.1.0 for GitHub code scanning
  -o FILE           write to FILE instead of stdout
  -quiet            findings only
  -stats            print throughput
  -color/-no-color  force or disable ANSI colour

EXIT CODES
  0  clean, or every finding below -fail-on
  1  at least one finding at or above -fail-on (default low)
  2  usage or runtime error

EXAMPLES
  qalqon .
  qalqon deps .
  qalqon history .
  qalqon deps . -direct -fail-on high
  qalqon scan . -severity high,critical
  qalqon scan . -tags docker -stats
  qalqon scan . -sarif -o results.sarif
  qalqon scan . -t ./my-templates -fail-on high
`, version)
}
