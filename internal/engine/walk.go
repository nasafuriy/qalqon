package engine

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// WalkFiles returns the slash paths the scan pipeline would consider for
// opts.Root — the same walk Run performs, without reading or matching any
// file. The compliance report uses it to distinguish a control that passed
// from a control whose subject never appeared in the tree at all, which is
// the difference between PASS and REVIEW.
func WalkFiles(ctx context.Context, opts Options) ([]string, error) {
	root := opts.Root
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, err
	}
	walkRoot := absRoot
	if !info.IsDir() {
		walkRoot = filepath.Dir(absRoot)
	}

	var out []string
	err = filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory should not abort the walk.
			return nil //nolint:nilerr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			name := d.Name()
			if p == absRoot {
				return nil
			}
			if skipDirs[name] {
				return fs.SkipDir
			}
			if !opts.Hidden && isHiddenDir(name) && !alwaysScanDotDirs[name] {
				return fs.SkipDir
			}
			if excluded(opts.Exclude, relSlash(walkRoot, p), name) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if excluded(opts.Exclude, relSlash(walkRoot, p), d.Name()) {
			return nil
		}
		out = append(out, relSlash(walkRoot, p))
		return nil
	})
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, err
}

// isHiddenDir mirrors the hidden-name check in Run: a leading dot marks a
// hidden directory, with the alwaysScanDotDirs allow-list consulted separately.
func isHiddenDir(name string) bool {
	return strings.HasPrefix(name, ".")
}
