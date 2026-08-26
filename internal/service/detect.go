// Package service reads the software a host names in its own headers and says
// what is publicly known about that version.
//
// A word about what this can and cannot prove. The Server header is a claim,
// not a measurement: it can be edited, proxied away, or set to something
// deliberately misleading. Worse for a scanner, distributions backport
// security fixes without changing the version string, so a Debian nginx
// reporting 1.10.3 may carry every patch that upstream shipped in 1.10.3 plus
// three years of fixes on top.
//
// So nothing here says "you are vulnerable". It says which advisories name
// this version upstream, and every finding carries the caveat. That is still
// worth reporting — an attacker reads the same banner and makes the same
// inference — but the difference matters, and pretending otherwise would put
// noise in a report the user is meant to trust.
package service

import (
	"regexp"
	"strings"
)

// Service is one piece of software a response named.
type Service struct {
	// Product is normalised: "nginx", "apache", "php", "express".
	Product string
	Version string
	// Header is where the claim came from, so a report can quote it.
	Header string
	// Raw is the full header value as sent.
	Raw string
}

// banner matches "name/1.2.3" anywhere in a header value, which is how
// essentially every server writes it. Trailing platform notes — the "(Ubuntu)"
// in "Apache/2.2.14 (Ubuntu)" — fall outside the match and are ignored.
var banner = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_+.\-]*)/([0-9]+(?:\.[0-9]+)*)`)

// aliases maps what servers call themselves to the name the advisory table
// uses. openresty is nginx with Lua compiled in, and its version number is
// nginx's with a build suffix, so its core advisories are nginx's.
var aliases = map[string]string{
	"apache":        "apache",
	"apache-coyote": "tomcat",
	"httpd":         "apache",
	"nginx":         "nginx",
	"openresty":     "nginx",
	"php":           "php",
	"php-fpm":       "php",
	"express":       "express",
	"gunicorn":      "gunicorn",
	"werkzeug":      "werkzeug",
	"microsoft-iis": "iis",
	"iis":           "iis",
	"lighttpd":      "lighttpd",
	"apache-tomcat": "tomcat",
	"tomcat":        "tomcat",
	"coyote":        "tomcat",
}

// Jetty is deliberately absent. It writes its banner as "Jetty(9.4.z-SNAPSHOT)"
// — no slash, and often a placeholder instead of a patch level — so there is
// nothing here that a version comparison can be trusted with.

// headers worth reading. Others exist — X-AspNet-Version, X-Generator — but
// these three carry a version often enough to be worth the parsing.
var headers = []string{"server", "x-powered-by", "x-aspnet-version"}

// Detect reads the rendered header part and returns everything it recognised.
//
// The input is the same text the templates match against: one "Name: value"
// line per header.
func Detect(headerPart []byte) []Service {
	var out []Service
	seen := map[string]bool{}

	for _, line := range strings.Split(string(headerPart), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)

		if !wanted(name) {
			continue
		}

		for _, m := range banner.FindAllStringSubmatch(value, -1) {
			product, ok := aliases[strings.ToLower(m[1])]
			if !ok {
				continue
			}
			version := normaliseVersion(product, m[2])
			key := product + "@" + version
			if seen[key] {
				continue
			}
			seen[key] = true

			out = append(out, Service{
				Product: product,
				Version: version,
				Header:  canonicalHeader(name),
				Raw:     value,
			})
		}
	}
	return out
}

func wanted(name string) bool {
	for _, h := range headers {
		if name == h {
			return true
		}
	}
	return false
}

// normaliseVersion turns a product's own numbering into the one the advisory
// table is written in.
func normaliseVersion(product, version string) string {
	// openresty appends its own build number to nginx's version:
	// 1.13.6.1 is nginx 1.13.6, build 1. Four segments, and the advisories
	// are all written against three.
	if product == "nginx" && strings.Count(version, ".") == 3 {
		if i := strings.LastIndex(version, "."); i > 0 {
			return version[:i]
		}
	}
	return version
}

func canonicalHeader(lower string) string {
	switch lower {
	case "server":
		return "Server"
	case "x-powered-by":
		return "X-Powered-By"
	case "x-aspnet-version":
		return "X-AspNet-Version"
	}
	return lower
}
