// Package log provides a standardized way to initialize
// github.com/rs/zerolog based loggers.
package log

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/KernelPryanic/goudpscan/pkg/ctxerr"

	"github.com/rs/zerolog"
)

func init() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	zerolog.TimeFieldFormat = time.RFC3339Nano
	Default = New(false, os.Stdout)
	zerolog.DefaultContextLogger = &Default
}

// Default is the default global logger.
var Default zerolog.Logger

// callerHook is a zerolog hook for post-processing log events.
type callerHook struct{}

var _ zerolog.Hook = callerHook{}

var logLevels = map[string]zerolog.Level{
	"trace":    zerolog.TraceLevel,
	"debug":    zerolog.DebugLevel,
	"info":     zerolog.InfoLevel,
	"warn":     zerolog.WarnLevel,
	"error":    zerolog.ErrorLevel,
	"fatal":    zerolog.FatalLevel,
	"panic":    zerolog.PanicLevel,
	"disabled": zerolog.Disabled,
	"":         zerolog.InfoLevel,
}

// SetLogLevel sets the log level for all logger instances.
// NOTE: Can be called at any time to change the log level.
func SetLogLevel(l string) {
	zerolog.SetGlobalLevel(logLevels[l])
}

// Run implements the zerolog.Hook interface.
func (h callerHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	errCtx := ctxerr.From(e.GetCtx())
	if errCtx.Err != nil {
		e.Fields(errCtx.Ctx)
		e.Err(errCtx.Err)
	}
	switch level {
	case zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel:
		_, file, line, ok := runtime.Caller(3)
		if ok {
			e.Str("file", fmt.Sprintf("%s:%d", file, line))
		}
	}
}

// New creates a New logger instance.
func New(consoleWriter bool, out io.Writer) zerolog.Logger {
	if out == nil {
		out = io.Writer(os.Stdout)
	}
	if consoleWriter {
		out = zerolog.ConsoleWriter{
			Out:        out,
			TimeFormat: "15:04:05.000",
		}
	}
	return zerolog.New(out).
		With().Timestamp().
		Logger().
		Hook(callerHook{})
}
