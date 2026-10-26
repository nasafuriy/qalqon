package template

import (
	"runtime"
	"testing"
)

func TestGlobCaseSensitivityFollowsTheFilesystem(t *testing.T) {
	t.Cleanup(func() { SetCaseInsensitive(runtime.GOOS == "windows") })

	tpl := &Template{
		ID:       "case-test",
		Info:     Info{Name: "case test", Severity: SeverityMedium, Remediation: "fix it"},
		Files:    []string{"nginx.conf", "conf.d/*.conf"},
		Matchers: []Matcher{{Patterns: []string{"x"}}},
	}
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		insensitive  bool
		rel, base    string
		want, reason string
	}{
		// On a case-insensitive filesystem both spellings are one file.
		{true, "", "NGINX.CONF", "nginx.conf", "uppercase basename"},
		{true, "conf.d/Nginx.CONF", "other.conf", "conf.d/*.conf", "uppercase path"},
		{false, "", "NGINX.CONF", "", "nobody matches when the FS is case-sensitive"},
		{false, "", "nginx.conf", "nginx.conf", "exact match still works"},
	} {
		SetCaseInsensitive(tc.insensitive)
		got := ""
		for _, pattern := range tpl.Files {
			if matchGlob(pattern, tc.rel, tc.base) {
				got = pattern
				break
			}
		}
		if got != tc.want {
			t.Errorf("insensitive=%v rel=%q base=%q: want %q, got %q",
				tc.insensitive, tc.rel, tc.base, tc.want, got)
		}
	}
}

func TestValidateRejectsUnknownCondition(t *testing.T) {
	tpl := &Template{
		ID:        "bad-condition",
		Info:      Info{Name: "x", Severity: "medium", Remediation: "fix it"},
		Files:     []string{"a.txt"},
		Condition: "xor",
		Matchers:  []Matcher{{Patterns: []string{"a"}}},
	}
	if err := tpl.Validate(); err == nil {
		t.Fatal("expected a != xor condition to be rejected")
	}
}
