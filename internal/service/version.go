package service

import (
	"strconv"
	"strings"
)

// compareVersions orders two dotted numeric versions, returning -1, 0 or 1.
//
// Missing segments count as zero, so 1.10 and 1.10.0 are equal, and 1.10 is
// below 1.10.1. Segments are compared as numbers rather than text, which is
// the whole reason this exists: "1.10.3" sorts below "1.9.5" as a string, and
// getting that backwards would report every patched server and miss every
// unpatched one.
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")

	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}

	for i := 0; i < n; i++ {
		x := segment(as, i)
		y := segment(bs, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func segment(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	// Detection has already stripped anything non-numeric, but a hand-written
	// table entry with a typo should not be read as a huge version number.
	n, err := strconv.Atoi(parts[i])
	if err != nil {
		return 0
	}
	return n
}

// Range is a half-open interval of affected versions: Introduced is included,
// Fixed is not. An empty Introduced means "every version up to Fixed", and an
// empty Fixed means the advisory has no published fix.
type Range struct {
	Introduced string
	Fixed      string
}

func (r Range) contains(version string) bool {
	if r.Introduced != "" && compareVersions(version, r.Introduced) < 0 {
		return false
	}
	if r.Fixed != "" && compareVersions(version, r.Fixed) >= 0 {
		return false
	}
	return true
}

// fixedFor returns the version that closes the advisory for the branch this
// version is on, so the advice names the upgrade the operator would actually
// make rather than the newest release overall.
func fixedFor(ranges []Range, version string) string {
	for _, r := range ranges {
		if r.contains(version) {
			return r.Fixed
		}
	}
	return ""
}
