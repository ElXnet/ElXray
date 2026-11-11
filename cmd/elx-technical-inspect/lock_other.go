//go:build !linux

package main

import (
	"errors"
	"os"
)

func lockManagedPolicyState(string) (*os.File, error) {
	return nil, errors.New("offline managed journal forensics require Linux policy file locking")
}
