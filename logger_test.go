// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"log/slog"
	"testing"
)

func TestDefaultLoggerIsSilent(t *testing.T) {
	cfg, err := ApplyConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.logger == nil {
		t.Fatal("logger must be non-nil")
	}
	if cfg.logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("default logger should be disabled at Debug")
	}
	if cfg.logger.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("default logger should be disabled at Error")
	}
}

func TestWithLoggerNilRestoresSilent(t *testing.T) {
	cfg, err := ApplyConfig(WithLogger(slog.Default()), WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("WithLogger(nil) should restore silent default")
	}
}

func TestDiscardHandlerMethods(t *testing.T) {
	h := discardHandler{}
	ctx := context.Background()
	if h.Enabled(ctx, slog.LevelInfo) {
		t.Fatal("Enabled should be false")
	}
	if err := h.Handle(ctx, slog.Record{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if h.WithAttrs([]slog.Attr{slog.String("k", "v")}) != h {
		t.Fatal("WithAttrs should return same handler")
	}
	if h.WithGroup("g") != h {
		t.Fatal("WithGroup should return same handler")
	}
}
