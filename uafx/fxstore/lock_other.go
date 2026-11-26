// SPDX-License-Identifier: MIT

//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package fxstore

import (
	"errors"
	"io"
)

// errNoLock reports a platform on which FileStore cannot lock its
// directory.
var errNoLock = errors.New("fxstore: FileStore is not supported on this platform: no exclusive file lock")

func lockDir(string) (io.Closer, error) { return nil, errNoLock }

func syncDirectory(string) error { return errNoLock }
