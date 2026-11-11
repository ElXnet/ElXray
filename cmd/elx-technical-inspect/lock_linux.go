//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockManagedPolicyState refuses to inspect a live managed process, rather
// than trusting a PID file or merely checking if a core socket exists.
func lockManagedPolicyState(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("policy state path must be absolute")
	}
	target := path + ".lock"
	info, err := os.Lstat(target)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("managed state lock must be private and regular")
	}
	f, err := os.OpenFile(target, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("running core still owns the managed policy lock")
	}
	return f, nil
}
