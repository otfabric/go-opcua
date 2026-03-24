// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Package logger provides a configurable logging interface for the OPC UA library.
package logger

import (
	"fmt"
	"log"
	"log/slog"
	"os"
)

// Logger is a printf-style leveled logging interface.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// stdLogger wraps a stdlib *log.Logger.
type stdLogger struct {
	l *log.Logger
}

// NewStdLogger returns a Logger backed by the standard library log.Logger.
// If l is nil, a default logger writing to stdout is used.
func NewStdLogger(l *log.Logger) Logger {
	if l == nil {
		l = log.New(os.Stdout, "", log.LstdFlags)
	}
	return &stdLogger{l: l}
}

func (s *stdLogger) Debugf(format string, args ...any) {
	s.l.Printf("[DEBUG] "+format, args...)
}

func (s *stdLogger) Infof(format string, args ...any) {
	s.l.Printf("[INFO] "+format, args...)
}

func (s *stdLogger) Warnf(format string, args ...any) {
	s.l.Printf("[WARN] "+format, args...)
}

func (s *stdLogger) Errorf(format string, args ...any) {
	s.l.Printf("[ERROR] "+format, args...)
}

// slogLogger wraps an slog.Handler.
type slogLogger struct {
	l *slog.Logger
}

// NewSlogLogger returns a Logger backed by the given slog.Handler.
func NewSlogLogger(h slog.Handler) Logger {
	return &slogLogger{l: slog.New(h)}
}

func (s *slogLogger) Debugf(format string, args ...any) {
	s.l.Debug(fmt.Sprintf(format, args...))
}

func (s *slogLogger) Infof(format string, args ...any) {
	s.l.Info(fmt.Sprintf(format, args...))
}

func (s *slogLogger) Warnf(format string, args ...any) {
	s.l.Warn(fmt.Sprintf(format, args...))
}

func (s *slogLogger) Errorf(format string, args ...any) {
	s.l.Error(fmt.Sprintf(format, args...))
}

// nopLogger discards all log output.
type nopLogger struct{}

// NopLogger returns a Logger that discards all output.
func NopLogger() Logger {
	return &nopLogger{}
}

func (n *nopLogger) Debugf(string, ...any) {}
func (n *nopLogger) Infof(string, ...any)  {}
func (n *nopLogger) Warnf(string, ...any)  {}
func (n *nopLogger) Errorf(string, ...any) {}

// defaultLogger delegates to slog.Default() at call time, so it
// picks up any changes made via slog.SetDefault.
type defaultLogger struct{}

// Default returns a Logger that delegates to slog.Default().
// This is used when no Logger is explicitly configured.
func Default() Logger {
	return &defaultLogger{}
}

func (d *defaultLogger) Debugf(format string, args ...any) {
	slog.Default().Debug(fmt.Sprintf(format, args...))
}

func (d *defaultLogger) Infof(format string, args ...any) {
	slog.Default().Info(fmt.Sprintf(format, args...))
}

func (d *defaultLogger) Warnf(format string, args ...any) {
	slog.Default().Warn(fmt.Sprintf(format, args...))
}

func (d *defaultLogger) Errorf(format string, args ...any) {
	slog.Default().Error(fmt.Sprintf(format, args...))
}
