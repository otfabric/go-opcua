// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"log/slog"
)

// discardHandler is a slog.Handler that discards all log records.
// Enabled always returns false so callers pay no allocation cost.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler           { return d }

func silentLogger() *slog.Logger {
	return slog.New(discardHandler{})
}
