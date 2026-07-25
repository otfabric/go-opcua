// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultServerLoggerIsSilent(t *testing.T) {
	s, err := New()
	require.NoError(t, err)
	require.NotNil(t, s.cfg.logger)
	require.False(t, s.cfg.logger.Enabled(context.Background(), slog.LevelError))
}

func TestSetLoggerNilRestoresSilent(t *testing.T) {
	s, err := New(SetLogger(slog.Default()), SetLogger(nil))
	require.NoError(t, err)
	require.False(t, s.cfg.logger.Enabled(context.Background(), slog.LevelInfo))
}

func TestWithSlogLoggerNilRestoresSilent(t *testing.T) {
	s, err := New(WithSlogLogger(slog.Default()), WithSlogLogger(nil))
	require.NoError(t, err)
	require.False(t, s.cfg.logger.Enabled(context.Background(), slog.LevelInfo))
}

func TestDiscardHandlerMethods(t *testing.T) {
	h := discardHandler{}
	ctx := context.Background()
	require.False(t, h.Enabled(ctx, slog.LevelInfo))
	require.NoError(t, h.Handle(ctx, slog.Record{}))
	require.Equal(t, h, h.WithAttrs([]slog.Attr{slog.String("k", "v")}))
	require.Equal(t, h, h.WithGroup("g"))
}
