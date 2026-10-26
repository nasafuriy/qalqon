// Package qalqon carries the built-in template library inside the binary, so
// a fresh install scans correctly with no extra files and no network access.
package qalqon

import "embed"

// Templates holds the shipped rule library, rooted at "templates".
//
//go:embed all:templates
var Templates embed.FS

// Compliance holds the shipped framework mappings, rooted at "compliance".
// Each document maps published control topics onto rule ids, so a plain
// scan can be scored as a checklist by `qalqon report`.
//
//go:embed all:compliance
var Compliance embed.FS
