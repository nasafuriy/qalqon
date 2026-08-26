package service

import "fmt"

// CuratedAsOf is when the tables below were last reviewed. A version table
// goes stale silently, which is the worst way for a security tool to be
// wrong, so the date is printed with the findings rather than hidden here.
const CuratedAsOf = "2026-08"

// Advisory is one published vulnerability, written against upstream release
// numbers.
type Advisory struct {
	ID       string
	Summary  string
	Severity string
	Ranges   []Range
	Refs     []string
}

// Affects reports whether this version falls in any affected range.
func (a Advisory) Affects(version string) bool {
	for _, r := range a.Ranges {
		if r.contains(version) {
			return true
		}
	}
	return false
}

// Support records the oldest release still receiving security fixes upstream.
//
// The floors are deliberately conservative — set at a boundary that is clearly
// past, not at the newest release. The claim being made is "upstream has
// stopped fixing this entirely", which is defensible from a version string;
// "you are missing last month's patch" is not, because a distribution may
// have shipped it without touching the banner.
type Support struct {
	// Oldest is the lowest version still supported upstream.
	Oldest string
	// Note explains the boundary in the operator's terms.
	Note string
}

var supported = map[string]Support{
	"nginx": {
		Oldest: "1.24.0",
		Note:   "nginx maintains only the current stable and mainline branches; older ones get no fixes at all.",
	},
	"apache": {
		Oldest: "2.4.0",
		Note:   "Only the 2.4 branch is maintained. 2.2 reached end of life in July 2017, and 2.0 and 1.3 long before that.",
	},
	"php": {
		Oldest: "8.2.0",
		Note:   "PHP supports each branch for two years plus one year of security fixes. 8.1 left security support at the end of 2025.",
	},
	"express": {
		Oldest: "4.20.0",
		Note:   "Express 4 below 4.20 is missing published fixes, and 4.16 predates several of them.",
	},
	"gunicorn": {
		Oldest: "22.0.0",
		Note:   "Gunicorn below 22.0 carries the request-smuggling flaw fixed in that release.",
	},
	"werkzeug": {
		Oldest: "3.0.3",
		Note:   "Werkzeug below 3.0.3 is missing the debugger and multipart fixes.",
	},
	"iis": {
		Oldest: "10.0",
		Note:   "IIS versions track the Windows Server release. 8.5 means Server 2012 R2, which left extended support in October 2023.",
	},
	"tomcat": {
		Oldest: "9.0.0",
		Note:   "Tomcat 8.5 reached end of life in March 2024; 7.0 and earlier long before.",
	},
	"lighttpd": {
		Oldest: "1.4.60",
		Note:   "lighttpd fixes land only on the current 1.4 line.",
	},
}

// advisories are landmark, widely exploited issues with unambiguous fixed
// versions. This is not a mirror of the CVE database and is not trying to be:
// a banner cannot support that weight. It is the short list an attacker
// checks first on seeing the version.
var advisories = map[string][]Advisory{
	"nginx": {
		{
			ID:       "CVE-2021-23017",
			Summary:  "Off-by-one in the resolver allows remote code execution when nginx is configured with a resolver directive",
			Severity: "critical",
			Ranges:   []Range{{Introduced: "0.6.18", Fixed: "1.20.1"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
		},
		{
			ID:       "CVE-2019-9511",
			Summary:  "HTTP/2 flow-control abuse exhausts CPU and memory (one of the \"HTTP/2 DoS\" family)",
			Severity: "high",
			Ranges:   []Range{{Introduced: "1.9.5", Fixed: "1.16.1"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-9511"},
		},
		{
			ID:       "CVE-2017-7529",
			Summary:  "Integer overflow in the range filter leaks memory contents through a crafted Range header",
			Severity: "high",
			Ranges:   []Range{{Introduced: "0.5.6", Fixed: "1.13.3"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-7529"},
		},
		{
			ID:       "CVE-2016-4450",
			Summary:  "NULL pointer dereference writing a client request body crashes the worker",
			Severity: "high",
			Ranges:   []Range{{Introduced: "1.3.9", Fixed: "1.11.1"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-4450"},
		},
		{
			ID:       "CVE-2022-41742",
			Summary:  "Memory disclosure and worker crash in the mp4 module",
			Severity: "medium",
			Ranges:   []Range{{Introduced: "1.1.3", Fixed: "1.23.2"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-41742"},
		},
	},
	"apache": {
		{
			ID:       "CVE-2021-42013",
			Summary:  "Path traversal and remote code execution; the incomplete fix for CVE-2021-41773",
			Severity: "critical",
			Ranges:   []Range{{Introduced: "2.4.49", Fixed: "2.4.51"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
		},
		{
			ID:       "CVE-2021-40438",
			Summary:  "Server-side request forgery through mod_proxy: a crafted request makes the server fetch a URL of the attacker's choosing",
			Severity: "critical",
			Ranges:   []Range{{Fixed: "2.4.49"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-40438"},
		},
		{
			ID:       "CVE-2023-25690",
			Summary:  "HTTP request smuggling through mod_proxy when RewriteRule or ProxyPassMatch uses a substitution",
			Severity: "critical",
			Ranges:   []Range{{Introduced: "2.4.0", Fixed: "2.4.56"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-25690"},
		},
		{
			ID:       "CVE-2017-7679",
			Summary:  "mod_mime reads past the end of a buffer and can return memory contents",
			Severity: "high",
			Ranges: []Range{
				{Introduced: "2.4.0", Fixed: "2.4.26"},
				{Fixed: "2.2.33"},
			},
			Refs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-7679"},
		},
		{
			ID:       "CVE-2011-3192",
			Summary:  "A crafted Range header exhausts memory and CPU — the \"Apache Killer\" denial of service",
			Severity: "high",
			Ranges:   []Range{{Fixed: "2.2.20"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2011-3192"},
		},
	},
	"php": {
		{
			ID:       "CVE-2024-4577",
			Summary:  "Argument injection in PHP-CGI on Windows gives remote code execution; exploited in the wild within days of disclosure",
			Severity: "critical",
			Ranges: []Range{
				{Fixed: "8.1.29"},
				{Introduced: "8.2.0", Fixed: "8.2.20"},
				{Introduced: "8.3.0", Fixed: "8.3.8"},
			},
			Refs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-4577"},
		},
		{
			ID:       "CVE-2019-11043",
			Summary:  "Underflow in PHP-FPM gives remote code execution on the common nginx fastcgi_split_path_info configuration",
			Severity: "critical",
			Ranges: []Range{
				{Introduced: "7.1.0", Fixed: "7.1.33"},
				{Introduced: "7.2.0", Fixed: "7.2.24"},
				{Introduced: "7.3.0", Fixed: "7.3.11"},
			},
			Refs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-11043"},
		},
	},
	"express": {
		{
			ID:       "CVE-2024-43796",
			Summary:  "Cross-site scripting through an unsanitised argument to res.redirect",
			Severity: "medium",
			Ranges:   []Range{{Fixed: "4.20.0"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-43796"},
		},
		{
			ID:       "CVE-2024-29041",
			Summary:  "Open redirect: res.location accepts a URL that browsers resolve to another origin",
			Severity: "medium",
			Ranges:   []Range{{Fixed: "4.19.2"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-29041"},
		},
	},
	"gunicorn": {
		{
			ID:       "CVE-2024-1135",
			Summary:  "Transfer-Encoding headers are validated inconsistently, allowing request smuggling past a front-end proxy",
			Severity: "high",
			Ranges:   []Range{{Fixed: "22.0.0"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-1135"},
		},
	},
	"werkzeug": {
		{
			ID:       "CVE-2024-34069",
			Summary:  "The debugger's PIN protection can be bypassed, giving code execution when the debugger is reachable",
			Severity: "high",
			Ranges:   []Range{{Fixed: "3.0.3"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-34069"},
		},
		{
			ID:       "CVE-2023-25577",
			Summary:  "Multipart parsing allocates without bound, so a small request can exhaust memory",
			Severity: "high",
			Ranges:   []Range{{Fixed: "2.2.3"}},
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-25577"},
		},
	},
}

// Assessment is what is known about one detected service.
type Assessment struct {
	Service Service
	// EndOfLife is set when upstream has stopped fixing this release entirely.
	EndOfLife bool
	// Support carries the boundary and why, when EndOfLife is true.
	Support Support
	// Advisories are the published issues naming this version upstream.
	Advisories []Advisory
}

// Assess looks up everything known about one detected service.
func Assess(s Service) Assessment {
	out := Assessment{Service: s}

	if sup, ok := supported[s.Product]; ok && compareVersions(s.Version, sup.Oldest) < 0 {
		out.EndOfLife = true
		out.Support = sup
	}
	for _, a := range advisories[s.Product] {
		if a.Affects(s.Version) {
			out.Advisories = append(out.Advisories, a)
		}
	}
	return out
}

// Upgrade names the version to move to.
//
// Normally that is the release which closed this advisory on the branch the
// service is on. When the branch itself is dead, it is not: telling someone
// running Apache 2.2.14 to move to 2.2.20 fixes the one CVE named here and
// leaves them on a branch that stopped receiving fixes in 2017. The advice has
// to point somewhere still maintained, or following every line of the report
// leaves the host no safer.
func (a Assessment) Upgrade(adv Advisory) string {
	fixed := fixedFor(adv.Ranges, a.Service.Version)

	if a.EndOfLife {
		floor := a.Support.Oldest
		if fixed != "" && compareVersions(fixed, floor) > 0 {
			floor = fixed
		}
		return fmt.Sprintf(
			"Upgrade %s to %s or later — the %s branch is no longer maintained, so upgrading within it would leave the rest unfixed.",
			Title(a.Service.Product), floor, branch(a.Service.Version))
	}

	if fixed == "" {
		return fmt.Sprintf("No fixed release is listed for %s.", adv.ID)
	}
	return fmt.Sprintf("Upgrade %s to %s or later.", Title(a.Service.Product), fixed)
}

// branch is the version with its patch level dropped: the line a release
// belongs to, which is the unit upstream declares end of life.
func branch(version string) string {
	parts := 0
	for i, r := range version {
		if r == '.' {
			parts++
			if parts == 2 {
				return version[:i]
			}
		}
	}
	return version
}

// Caveat is appended to every finding this package produces. It is not
// boilerplate: without it the finding overstates what a banner can show, and
// an operator who checks one and finds it already patched stops reading the
// rest.
const Caveat = "A banner is a claim, not a measurement. Distributions backport " +
	"security fixes without changing the version string, so confirm against your " +
	"package's changelog before treating this as exploitable — and consider removing " +
	"the version from the header either way."

// Products lists what the tables cover, for the help text.
func Products() []string {
	seen := map[string]bool{}
	var out []string
	for p := range supported {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for p := range advisories {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
