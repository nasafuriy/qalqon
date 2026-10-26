//go:build windows

package host

import (
	"golang.org/x/sys/windows"
)

// isElevated asks the process token whether it holds the elevated half of a
// split token. openCurrentProcessToken is query-only, so calling it changes
// nothing about the rights the process already had.
func isElevated() (bool, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false, err
	}
	defer token.Close()
	return token.IsElevated(), nil
}
