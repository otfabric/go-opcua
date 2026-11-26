// SPDX-License-Identifier: MIT

//go:build windows

package fxstore

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// errSharingViolation is ERROR_SHARING_VIOLATION, which package syscall
// does not name.
const errSharingViolation = syscall.Errno(32)

// lockDir opens the lock file name without sharing: no other open of it,
// in this process or another, succeeds while it is open.
func lockDir(name string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("fxstore: %w", err)
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, errSharingViolation) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("fxstore: lock: %w", err)
	}
	return os.NewFile(uintptr(h), name), nil
}

// syncDirectory does nothing: Windows cannot fsync a directory. The
// durability of a rename rests on the metadata journal of the file system
// (FileStore.Durability is DurabilityProcessCrash).
func syncDirectory(string) error { return nil }
