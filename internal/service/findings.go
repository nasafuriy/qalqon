package service

import (
	"fmt"
	"sort"
	"strings"
)

// Finding is one thing known about a version a host disclosed. It is
// deliberately not engine.Finding: this package answers "what is published
// about this version", and the caller decides how to present it.
type Finding struct {
	ID          string
	Name        string
	Severity    string
	Description string
	Remediation string
	Refs        []string
	Tags        []string
	// Match is the header text the conclusion was drawn from, so the report
	// can show its own evidence.
	Match string
}

// Findings turns a rendered header part into what is known about the versions
// it disclosed.
func Findings(headerPart []byte) []Finding {
	var out []Finding

	for _, s := range Detect(headerPart) {
		a := Assess(s)
		evidence := s.Header + ": " + s.Raw

		if a.EndOfLife {
			out = append(out, Finding{
				ID:       "service-end-of-life",
				Name:     fmt.Sprintf("%s %s is past upstream support", Title(s.Product), s.Version),
				Severity: "medium",
				Description: fmt.Sprintf(
					"The %s header names %s %s. %s Nothing found after that release is fixed here, "+
						"so the count of unpatched issues only grows.",
					s.Header, Title(s.Product), s.Version, a.Support.Note),
				Remediation: fmt.Sprintf(
					"Move to %s %s or later. %s",
					Title(s.Product), a.Support.Oldest, Caveat),
				Tags:  []string{"service", "version", "eol", s.Product},
				Match: evidence,
			})
		}

		for _, adv := range a.Advisories {
			out = append(out, Finding{
				ID:       "service-known-vulnerability",
				Name:     fmt.Sprintf("%s: %s %s is in the affected range", adv.ID, Title(s.Product), s.Version),
				Severity: adv.Severity,
				Description: fmt.Sprintf("%s. Upstream lists this as affecting %s %s.",
					strings.TrimRight(adv.Summary, "."), Title(s.Product), s.Version),
				Remediation: a.Upgrade(adv) + " " + Caveat,
				Refs:        adv.Refs,
				Tags:        []string{"service", "version", "cve", s.Product},
				Match:       evidence,
			})
		}
	}

	// Worst first, then by identifier, so two runs against the same host print
	// the same report.
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := rank(out[i].Severity), rank(out[j].Severity); ri != rj {
			return ri > rj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func rank(severity string) int {
	switch severity {
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

// Title capitalises a product name for prose. The table keys are lowercase
// because header values are matched case-insensitively; the report is read by
// a person.
func Title(product string) string {
	switch product {
	case "nginx":
		return "nginx" // lowercase is the project's own spelling
	case "php":
		return "PHP"
	case "iis":
		return "IIS"
	case "apache":
		return "Apache httpd"
	}
	if product == "" {
		return product
	}
	return strings.ToUpper(product[:1]) + product[1:]
}
