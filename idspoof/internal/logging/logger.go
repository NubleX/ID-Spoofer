package logging

import (
	"io"
	"log/slog"
	"os"
)

// Logger wraps slog and provides level-filtered output.
type Logger struct {
	inner *slog.Logger
	debug bool
	quiet bool
}

// New creates a logger. When logFile is non-empty, output goes to that file
// in addition to stderr (for non-quiet modes).
func New(quiet, debug bool, logFile string) (*Logger, error) {
	var writers []io.Writer

	if !quiet {
		writers = append(writers, os.Stderr)
	}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		writers = append(writers, f)
	}

	var w io.Writer
	switch len(writers) {
	case 0:
		w = io.Discard
	case 1:
		w = writers[0]
	default:
		w = io.MultiWriter(writers...)
	}

	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	return &Logger{
		inner: slog.New(handler),
		debug: debug,
		quiet: quiet,
	}, nil
}

func (l *Logger) Info(msg string, args ...any)  { l.inner.Info(msg, args...) }
func (l *Logger) Debug(msg string, args ...any) { l.inner.Debug(msg, args...) }
func (l *Logger) Warn(msg string, args ...any)  { l.inner.Warn(msg, args...) }
func (l *Logger) Error(msg string, args ...any) { l.inner.Error(msg, args...) }
