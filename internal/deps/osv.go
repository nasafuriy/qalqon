package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// OSV is the open vulnerability database at osv.dev. It aggregates the
// per-ecosystem advisory feeds (GitHub, RustSec, PyPA and the rest) behind
// one query, which is why it is worth a network call.
const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvVulnURL  = "https://api.osv.dev/v1/vulns/"

	// The API accepts up to 1000 queries per batch. Staying well under keeps
	// the request small enough to retry cheaply on a flaky connection.
	batchSize = 250
)

// Vulnerability is one advisory affecting one dependency.
type Vulnerability struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases,omitempty"` // usually the CVE
	Summary   string     `json:"summary,omitempty"`
	Details   string     `json:"details,omitempty"`
	Severity  string     `json:"severity"` // critical|high|medium|low|unknown
	CVSS      string     `json:"cvss,omitempty"`
	FixedIn   []string   `json:"fixed_in,omitempty"`
	Withdrawn bool       `json:"withdrawn,omitempty"`
	Dep       Dependency `json:"dependency"`
}

// CVE returns the CVE id when the advisory has one, otherwise the OSV id.
func (v Vulnerability) CVE() string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// Client queries OSV. The zero value is not usable; use NewClient.
type Client struct {
	HTTP    *http.Client
	Workers int
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: timeout},
		Workers: 8,
	}
}

/* ------------------------------------------------------------ the query */

type batchQuery struct {
	Queries []queryItem `json:"queries"`
}

type queryItem struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type batchResult struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// Query asks OSV about every dependency and returns the advisories that
// apply. Dependencies with no known problem produce nothing.
//
// The call is made in two stages because that is how the API is shaped:
// a batch call says *which* advisories apply, and a per-advisory call
// carries the detail worth printing.
func (c *Client) Query(ctx context.Context, deps []Dependency) ([]Vulnerability, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	// id -> the dependencies it affects. One advisory often covers several.
	hits := make(map[string][]Dependency)

	for start := 0; start < len(deps); start += batchSize {
		end := min(start+batchSize, len(deps))
		chunk := deps[start:end]

		var body batchQuery
		for _, d := range chunk {
			var q queryItem
			q.Package.Name = d.Name
			q.Package.Ecosystem = d.Ecosystem
			q.Version = d.Version
			body.Queries = append(body.Queries, q)
		}

		var res batchResult
		if err := c.post(ctx, osvBatchURL, body, &res); err != nil {
			return nil, err
		}
		// Results come back positionally, one per query.
		for i, r := range res.Results {
			if i >= len(chunk) {
				break
			}
			for _, v := range r.Vulns {
				hits[v.ID] = append(hits[v.ID], chunk[i])
			}
		}
	}

	if len(hits) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(hits))
	for id := range hits {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	details, err := c.fetchDetails(ctx, ids)
	if err != nil {
		return nil, err
	}

	var out []Vulnerability
	for _, id := range ids {
		record, ok := details[id]
		if !ok || record.Withdrawn != "" {
			continue // withdrawn advisories are noise
		}
		for _, d := range hits[id] {
			v := record.toVulnerability(d)
			out = append(out, v)
		}
	}

	out = mergeAliases(out)

	sort.Slice(out, func(i, j int) bool {
		if ri, rj := rank(out[i].Severity), rank(out[j].Severity); ri != rj {
			return ri > rj
		}
		if out[i].Dep.Name != out[j].Dep.Name {
			return out[i].Dep.Name < out[j].Dep.Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// mergeAliases collapses records that describe the same flaw.
//
// One issue commonly has two OSV entries: the ecosystem advisory (GHSA-…,
// RUSTSEC-…) and the language's own database (GO-…, PYSEC-…). Both alias to
// the same CVE, and reporting both means every Go vulnerability is listed
// twice. They also carry different metadata: GHSA records usually have a
// CVSS vector while the Go database does not, so the merged record keeps
// whichever half is more informative.
func mergeAliases(in []Vulnerability) []Vulnerability {
	// key: the dependency plus the shared identifier
	best := make(map[string]int, len(in))
	var out []Vulnerability

	for _, v := range in {
		key := v.Dep.Ecosystem + "\x00" + v.Dep.Name + "\x00" +
			v.Dep.Version + "\x00" + v.CVE()

		idx, seen := best[key]
		if !seen {
			best[key] = len(out)
			out = append(out, v)
			continue
		}

		kept := &out[idx]
		// A scored record wins over an unscored one; between two scored
		// records the more severe reading is the safer one to report.
		if rank(v.Severity) > rank(kept.Severity) {
			v.FixedIn = unionSorted(kept.FixedIn, v.FixedIn)
			v.Aliases = unionSorted(kept.Aliases, v.Aliases)
			if v.Summary == "" {
				v.Summary = kept.Summary
			}
			if v.Details == "" {
				v.Details = kept.Details
			}
			*kept = v
			continue
		}
		kept.FixedIn = unionSorted(kept.FixedIn, v.FixedIn)
		kept.Aliases = unionSorted(kept.Aliases, v.Aliases)
		if kept.Summary == "" {
			kept.Summary = v.Summary
		}
		if kept.Details == "" {
			kept.Details = v.Details
		}
	}
	return out
}

func unionSorted(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var out []string
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

/* ---------------------------------------------------------- the details */

type osvRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func (c *Client) fetchDetails(ctx context.Context, ids []string) (map[string]osvRecord, error) {
	var (
		mu   sync.Mutex
		out  = make(map[string]osvRecord, len(ids))
		errs []error
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, c.Workers)

	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var rec osvRecord
			if err := c.get(ctx, osvVulnURL+id, &rec); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", id, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			out[id] = rec
			mu.Unlock()
		}(id)
	}
	wg.Wait()

	// A few failed lookups should not discard the advisories that did load.
	if len(out) == 0 && len(errs) > 0 {
		return nil, errs[0]
	}
	return out, nil
}

func (r osvRecord) toVulnerability(d Dependency) Vulnerability {
	v := Vulnerability{
		ID:      r.ID,
		Aliases: r.Aliases,
		Summary: r.Summary,
		Details: r.Details,
		Dep:     d,
	}

	// Prefer a CVSS vector, which is comparable across sources. Fall back to
	// the database's own wording when there is no score.
	for _, s := range r.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V") && s.Score != "" {
			v.CVSS = s.Score
			v.Severity = severityFromCVSS(s.Score)
			break
		}
	}
	if v.Severity == "" {
		label := r.DatabaseSpecific.Severity
		for _, a := range r.Affected {
			if label == "" {
				label = a.DatabaseSpecific.Severity
			}
		}
		v.Severity = normaliseLabel(label)
	}

	// The fixed version, for the package we actually asked about.
	seen := map[string]bool{}
	for _, a := range r.Affected {
		if !strings.EqualFold(a.Package.Name, d.Name) {
			continue
		}
		for _, rg := range a.Ranges {
			for _, e := range rg.Events {
				if e.Fixed != "" && !seen[e.Fixed] {
					seen[e.Fixed] = true
					v.FixedIn = append(v.FixedIn, e.Fixed)
				}
			}
		}
	}
	sort.Strings(v.FixedIn)
	return v
}

/* -------------------------------------------------------------- scoring */

// severityFromCVSS reads the base score out of a CVSS vector and maps it to
// the bands qalqon already uses elsewhere. Parsing the vector rather than
// trusting a label keeps one scale across every ecosystem.
func severityFromCVSS(vector string) string {
	score := cvssBaseScore(vector)
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return "unknown"
}

func normaliseLabel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	}
	return "unknown"
}

func rank(sev string) int {
	switch sev {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

/* --------------------------------------------------------------- HTTP */

func (c *Client) post(ctx context.Context, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) get(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	req.Header.Set("User-Agent", "qalqon")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("osv.dev returned %s: %s",
			resp.Status, strings.TrimSpace(string(snippet)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}
