// Package qalqon carries the built-in template library inside the binary, so
// a fresh install scans correctly with no extra files and no network access.
package qalqon

import "embed"

// Templates holds the shipped rule library, rooted at "templates".
//
//go:embed all:templates
var Templates embed.FS
