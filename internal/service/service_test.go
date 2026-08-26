package service

import (
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.10.3", "1.9.5", 1},   // the case string comparison gets backwards
		{"1.9.5", "1.10.3", -1},  //
		{"2.4.49", "2.4.51", -1}, //
		{"1.10", "1.10.0", 0},    // missing segments are zero
		{"1.10", "1.10.1", -1},   //
		{"8.2.0", "8.2.0", 0},
		{"22.0.0", "9.9.9", 1}, // two digits against one
		{"10.0", "8.5", 1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestRangeContains(t *testing.T) {
	cases := []struct {
		name    string
		r       Range
		version string
		want    bool
	}{
		{"inside", Range{"1.3.9", "1.11.1"}, "1.10.3", true},
		{"at introduced", Range{"1.3.9", "1.11.1"}, "1.3.9", true},
		{"at fixed is not affected", Range{"1.3.9", "1.11.1"}, "1.11.1", false},
		{"past fixed", Range{"1.3.9", "1.11.1"}, "1.20.0", false},
		{"before introduced", Range{"1.3.9", "1.11.1"}, "1.2.0", false},
		{"open start", Range{Fixed: "2.4.49"}, "2.2.14", true},
		{"open end", Range{Introduced: "1.0.0"}, "99.0.0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.contains(tc.version); got != tc.want {
				t.Errorf("contains(%q) = %t, want %t", tc.version, got, tc.want)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name    string
		headers string
		want    []Service
	}{
		{
			name:    "apache with a platform note",
			headers: "Server: Apache/2.2.14 (Ubuntu)\n",
			want:    []Service{{Product: "apache", Version: "2.2.14"}},
		},
		{
			name:    "nginx",
			headers: "Server: nginx/1.10.3\n",
			want:    []Service{{Product: "nginx", Version: "1.10.3"}},
		},
		{
			name:    "php through x-powered-by",
			headers: "X-Powered-By: PHP/5.4.16\n",
			want:    []Service{{Product: "php", Version: "5.4.16"}},
		},
		{
			// openresty's fourth segment is its own build number, not nginx's.
			name:    "openresty maps to nginx and drops the build number",
			headers: "Server: openresty/1.13.6.1\n",
			want:    []Service{{Product: "nginx", Version: "1.13.6"}},
		},
		{
			name:    "two products in one response",
			headers: "Server: nginx/1.10.3\nX-Powered-By: PHP/7.2.1\n",
			want: []Service{
				{Product: "nginx", Version: "1.10.3"},
				{Product: "php", Version: "7.2.1"},
			},
		},
		{
			// Everything the module list names is a separate claim; only the
			// products in the table are picked up.
			name:    "module list alongside the server",
			headers: "Server: Apache/2.2.14 (Unix) mod_ssl/2.2.14 OpenSSL/0.9.8k\n",
			want:    []Service{{Product: "apache", Version: "2.2.14"}},
		},
		{
			name:    "a version with no product we know",
			headers: "Server: SomethingCustom/4.2\n",
			want:    nil,
		},
		{
			name:    "no version at all",
			headers: "Server: cloudflare\n",
			want:    nil,
		},
		{
			// Only the headers that carry a software claim are read; a date or
			// an etag must not be mined for version numbers.
			name:    "other headers are ignored",
			headers: "Date: Mon, 02 Jun 2025 10:00:00 GMT\nETag: nginx/1.0.0\n",
			want:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect([]byte(tc.headers))
			if len(got) != len(tc.want) {
				t.Fatalf("got %d services, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range tc.want {
				if got[i].Product != tc.want[i].Product || got[i].Version != tc.want[i].Version {
					t.Errorf("service %d = %s/%s, want %s/%s", i,
						got[i].Product, got[i].Version,
						tc.want[i].Product, tc.want[i].Version)
				}
			}
		})
	}
}

func TestAssessEndOfLife(t *testing.T) {
	old := Assess(Service{Product: "apache", Version: "2.2.14"})
	if !old.EndOfLife {
		t.Error("Apache 2.2 should be past upstream support")
	}

	current := Assess(Service{Product: "apache", Version: "2.4.62"})
	if current.EndOfLife {
		t.Error("a maintained 2.4 release must not be called end of life")
	}
}

// The advisory table has to be right about which versions it names, or the
// findings are worse than nothing.
func TestAssessAdvisoryRanges(t *testing.T) {
	cases := []struct {
		product, version, cve string
		want                  bool
	}{
		{"nginx", "1.10.3", "CVE-2021-23017", true},   // in the long affected range
		{"nginx", "1.20.1", "CVE-2021-23017", false},  // the release that fixed it
		{"nginx", "1.27.0", "CVE-2021-23017", false},  // well past it
		{"nginx", "1.2.0", "CVE-2016-4450", false},    // predates the flaw
		{"nginx", "1.4.0", "CVE-2016-4450", true},     // 1.3.9 introduced it
		{"apache", "2.4.49", "CVE-2021-42013", true},  //
		{"apache", "2.4.51", "CVE-2021-42013", false}, //
		{"apache", "2.4.62", "CVE-2023-25690", false}, //
		{"php", "8.2.19", "CVE-2024-4577", true},      // branch-specific range
		{"php", "8.2.20", "CVE-2024-4577", false},     //
		{"php", "8.3.7", "CVE-2024-4577", true},       // a different branch
		{"php", "8.3.8", "CVE-2024-4577", false},      //
		{"php", "7.2.24", "CVE-2019-11043", false},    //
		{"php", "7.2.23", "CVE-2019-11043", true},     //
	}

	for _, tc := range cases {
		a := Assess(Service{Product: tc.product, Version: tc.version})
		found := false
		for _, adv := range a.Advisories {
			if adv.ID == tc.cve {
				found = true
			}
		}
		if found != tc.want {
			t.Errorf("%s %s: %s reported = %t, want %t",
				tc.product, tc.version, tc.cve, found, tc.want)
		}
	}
}

// The equivalent of testdata/clean. A current server must produce nothing at
// all, or the flag gets turned off and then it protects nothing.
func TestCurrentVersionsReportNothing(t *testing.T) {
	clean := []string{
		"Server: nginx/1.28.0\n",
		"Server: Apache/2.4.65 (Debian)\n",
		"X-Powered-By: PHP/8.4.2\n",
		"Server: gunicorn/23.0.0\n",
		"Server: Werkzeug/3.1.3\n",
		"X-Powered-By: Express/4.21.2\n",
		"Server: Microsoft-IIS/10.0\n",
		"Server: cloudflare\n",
		"Server: nginx\n",
	}
	for _, headers := range clean {
		t.Run(strings.TrimSpace(headers), func(t *testing.T) {
			if got := Findings([]byte(headers)); len(got) != 0 {
				for _, f := range got {
					t.Errorf("false positive: %s — %s", f.ID, f.Name)
				}
			}
		})
	}
}

func TestFindingsOnAnOldServer(t *testing.T) {
	got := Findings([]byte("Server: Apache/2.2.14 (Unix)\nX-Powered-By: PHP/5.4.16\n"))
	if len(got) == 0 {
		t.Fatal("an Apache 2.2 host with PHP 5.4 produced no findings")
	}

	var eol, cve int
	for _, f := range got {
		switch f.ID {
		case "service-end-of-life":
			eol++
		case "service-known-vulnerability":
			cve++
		}
		if !strings.Contains(f.Remediation, "backport") {
			t.Errorf("%s does not carry the backport caveat", f.Name)
		}
		if f.Match == "" {
			t.Errorf("%s shows no evidence for its claim", f.Name)
		}
	}
	if eol != 2 {
		t.Errorf("got %d end-of-life findings, want one each for Apache and PHP", eol)
	}
	if cve == 0 {
		t.Error("no advisories reported for two long-unmaintained versions")
	}

	// Worst first.
	if got[0].Severity != "critical" {
		t.Errorf("first finding is %s, want the critical one first", got[0].Severity)
	}
}

// Telling someone on Apache 2.2.14 to upgrade to 2.2.20 fixes the one CVE
// named and leaves them on a branch that died in 2017.
func TestRemediationDoesNotPointAtADeadBranch(t *testing.T) {
	got := Findings([]byte("Server: Apache/2.2.14\n"))
	for _, f := range got {
		if f.ID != "service-known-vulnerability" {
			continue
		}
		if strings.Contains(f.Remediation, "to 2.2.") {
			t.Errorf("%s sends the operator to a dead branch: %s", f.Name, f.Remediation)
		}
		if !strings.Contains(f.Remediation, "no longer maintained") {
			t.Errorf("%s does not say the branch is dead: %s", f.Name, f.Remediation)
		}
	}
}

// Every advisory range must name a fixed version above its introduced
// version, or the table has a typo that silently reports nothing.
func TestAdvisoryTableIsWellFormed(t *testing.T) {
	for product, list := range advisories {
		for _, adv := range list {
			if adv.ID == "" || adv.Summary == "" || adv.Severity == "" {
				t.Errorf("%s: advisory %q is missing a field", product, adv.ID)
			}
			if rank(adv.Severity) == 0 {
				t.Errorf("%s %s: severity %q is not a known level", product, adv.ID, adv.Severity)
			}
			if len(adv.Ranges) == 0 {
				t.Errorf("%s %s: no affected range, so it can never fire", product, adv.ID)
			}
			for _, r := range adv.Ranges {
				if r.Introduced != "" && r.Fixed != "" &&
					compareVersions(r.Introduced, r.Fixed) >= 0 {
					t.Errorf("%s %s: range %s–%s is empty", product, adv.ID, r.Introduced, r.Fixed)
				}
			}
			if len(adv.Refs) == 0 {
				t.Errorf("%s %s: no reference for the operator to read", product, adv.ID)
			}
		}
	}
}

// Every product the detector recognises should be in at least one table, or
// it is parsed and then thrown away.
func TestEveryAliasIsCovered(t *testing.T) {
	for _, product := range aliases {
		_, hasSupport := supported[product]
		_, hasAdvisories := advisories[product]
		if !hasSupport && !hasAdvisories {
			t.Errorf("alias maps to %q, which no table covers", product)
		}
	}
}

func TestSupportTableIsWellFormed(t *testing.T) {
	for product, s := range supported {
		if s.Oldest == "" {
			t.Errorf("%s: no support floor", product)
		}
		if !strings.HasSuffix(strings.TrimSpace(s.Note), ".") {
			t.Errorf("%s: note should read as a sentence: %q", product, s.Note)
		}
	}
}

func TestBranch(t *testing.T) {
	cases := map[string]string{
		"2.2.14":   "2.2",
		"8.1.29":   "8.1",
		"1.10.3":   "1.10",
		"10.0":     "10.0",
		"22":       "22",
		"1.13.6.1": "1.13",
	}
	for in, want := range cases {
		if got := branch(in); got != want {
			t.Errorf("branch(%q) = %q, want %q", in, got, want)
		}
	}
}
