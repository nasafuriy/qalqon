package deps

import (
	"math"
	"strings"
)

// cvssBaseScore computes the CVSS v3 base score from a vector string.
//
// The score is calculated rather than read from a label because the labels
// differ between advisory databases: what GitHub calls "moderate" and what
// RustSec calls "medium" should not sort differently in one report. The
// formula is the published v3.1 one, which v3.0 vectors also satisfy closely
// enough for banding.
//
// A vector that is not v3 returns 0, and the caller falls back to the
// database's own wording.
func cvssBaseScore(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0
	}

	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			m[k] = v
		}
	}

	scopeChanged := m["S"] == "C"

	av := pick(m["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac := pick(m["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	ui := pick(m["UI"], map[string]float64{"N": 0.85, "R": 0.62})

	// Privileges Required is worth more to an attacker when a successful
	// attack can escape its original scope.
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	}
	pr := pick(m["PR"], prTable)

	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c := pick(m["C"], cia)
	i := pick(m["I"], cia)
	a := pick(m["A"], cia)

	if av == 0 || ac == 0 || pr == 0 || ui == 0 {
		return 0 // an incomplete vector is not worth guessing at
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui

	score := impact + exploitability
	if scopeChanged {
		score = 1.08 * score
	}
	return roundUp(math.Min(score, 10))
}

func pick(key string, table map[string]float64) float64 {
	if v, ok := table[key]; ok {
		return v
	}
	return 0
}

// roundUp is CVSS's own rounding: up to one decimal place, so 4.02 is 4.1.
// Working in integer tenths avoids the floating point edge cases the spec
// calls out.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
