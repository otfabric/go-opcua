// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package opcua

import "github.com/otfabric/go-opcua/logger"

// Logger is a printf-style leveled logging interface.
type Logger = logger.Logger

// NewStdLogger returns a Logger backed by the standard library log.Logger.
var NewStdLogger = logger.NewStdLogger

// NewSlogLogger returns a Logger backed by the given slog.Handler.
var NewSlogLogger = logger.NewSlogLogger

// NopLogger returns a Logger that discards all output.
var NopLogger = logger.NopLogger
