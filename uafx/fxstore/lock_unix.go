// SPDX-License-Identifier: MIT

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package fxstore

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockDir takes an exclusive flock on the lock file name. flock locks
// belong to the open file, so a second open in the same process conflicts
// too.
func lockDir(name string) (*os.File, error) {
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("fxstore: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("fxstore: lock: %w", err)
	}
	return f, nil
}

// syncDirectory fsyncs the directory dir, which makes a rename in it
// durable.
func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}
