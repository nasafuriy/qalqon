package fix

import (
	"fmt"
	"strings"
)

// patchContext is how many unchanged lines a hunk shows around a change.
const patchContext = 3

// Diff renders the change between two LF-normalised versions as a unified
// diff with a hunk per changed region. Ambiguity between a single edit and a
// rewrite does not exist for the fixes this package applies — one patch op
// touches a handful of lines — so a prefix/common-suffix scan is the honest
// middle ground: it never mislabels an unchanged line as changed.
func Diff(before, after []byte) string {
	if string(before) == string(after) {
		return ""
	}
	oldLines := splitLines(before)
	newLines := splitLines(after)

	// Common prefix and suffix, in lines.
	prefix := 0
	for prefix < len(oldLines) && prefix < len(newLines) && oldLines[prefix] == newLines[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(oldLines)-prefix && suffix < len(newLines)-prefix &&
		oldLines[len(oldLines)-1-suffix] == newLines[len(newLines)-1-suffix] {
		suffix++
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- a\n+++ b\n")

	// The unchanged head and tail appear as context; the middle is the
	// change.
	head := oldLines[max(0, prefix-patchContext):prefix]
	tailStartOld := len(oldLines) - suffix
	tailStartNew := len(newLines) - suffix

	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n",
		max(1, prefix-patchContext+1), len(head)+len(oldLines[prefix:tailStartOld]),
		max(1, prefix-patchContext+1), len(head)+len(newLines[prefix:tailStartNew]))

	for _, l := range head {
		fmt.Fprintf(&b, " %s\n", l)
	}
	for _, l := range oldLines[prefix:tailStartOld] {
		fmt.Fprintf(&b, "-%s\n", l)
	}
	for _, l := range newLines[prefix:tailStartNew] {
		fmt.Fprintf(&b, "+%s\n", l)
	}
	for _, l := range oldLines[tailStartOld:min(tailStartOld+patchContext, len(oldLines))] {
		fmt.Fprintf(&b, " %s\n", l)
	}
	return b.String()
}

func splitLines(content []byte) []string {
	text := strings.TrimSuffix(string(content), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
