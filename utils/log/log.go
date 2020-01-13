package log

import (
	"fmt"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"io"
	"runtime"
	"strings"
)

var origLogger = logrus.New()
var baseLogger = logger{entry: logrus.NewEntry(origLogger)}

type Logger interface {
	Debug(...interface{})
	Debugln(...interface{})
	Debugf(string, ...interface{})

	Info(...interface{})
	Infoln(...interface{})
	Infof(string, ...interface{})

	Warn(...interface{})
	Warnln(...interface{})
	Warnf(string, ...interface{})

	Error(...interface{})
	Errorln(...interface{})
	Errorf(string, ...interface{})

	Fatal(...interface{})
	Fatalln(...interface{})
	Fatalf(string, ...interface{})

	With(key string, value interface{}) Logger

	SetFormat(string) error
	SetLevel(string) error
}

type logger struct {
	entry *logrus.Entry
}

func (l logger) With(key string, value interface{}) Logger {
	return logger{l.entry.WithField(key, value)}
}

func (l logger) Debug(args ...interface{}) {
	l.sourced().Debug(args...)
}

func (l logger) Debugln(args ...interface{}) {
	l.sourced().Debugln(args...)
}

func (l logger) Debugf(format string, args ...interface{}) {
	l.sourced().Debugf(format, args...)
}

func (l logger) Info(args ...interface{}) {
	l.sourced().Info(args...)
}

func (l logger) Infoln(args ...interface{}) {
	l.sourced().Infoln(args...)
}

func (l logger) Infof(format string, args ...interface{}) {
	l.sourced().Infof(format, args...)
}

func (l logger) Warn(args ...interface{}) {
	l.sourced().Warn(args...)
}

func (l logger) Warnln(args ...interface{}) {
	l.sourced().Warnln(args...)
}

func (l logger) Warnf(format string, args ...interface{}) {
	l.sourced().Warnf(format, args...)
}

func (l logger) Error(args ...interface{}) {
	l.sourced().Error(args...)
}

func (l logger) Errorln(args ...interface{}) {
	l.sourced().Errorln(args...)
}

func (l logger) Errorf(format string, args ...interface{}) {
	l.sourced().Errorf(format, args...)
}

func (l logger) Fatal(args ...interface{}) {
	l.sourced().Fatal(args...)
}

func (l logger) Fatalln(args ...interface{}) {
	l.sourced().Fatalln(args...)
}

func (l logger) Fatalf(format string, args ...interface{}) {
	l.sourced().Fatalf(format, args...)
}

func (l logger) SetLevel(level string) error {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}

	l.entry.Logger.Level = lvl
	return nil
}

func (l logger) SetFormat(format string) error {
	switch format {
	case "text":
		//origLogger.Formatter = &logrus.TextFormatter{ForceColors: true, DisableColors: true, FullTimestamp: true}
		origLogger.Formatter = &prefixed.TextFormatter{
			DisableColors:   true,
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			ForceFormatting: true,
		}
	case "json":
		origLogger.Formatter = &logrus.JSONFormatter{}
	default:
		return fmt.Errorf("unsupported logger format %s", format)
	}
	return nil
}

// sourced adds a source field to the logger that contains the file name and line where the logging happened
func (l logger) sourced() *logrus.Entry {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "<???>"
		line = 1
	} else {
		slash := strings.LastIndex(file, "/")
		file = file[slash+1:]
	}
	return l.entry.WithField("source", fmt.Sprintf("%s:%d", file, line))
}

func Base() Logger {
	return baseLogger
}

func NewLogger(w io.Writer) Logger {
	l := logrus.New()
	l.Out = w
	return logger{entry: logrus.NewEntry(l)}
}

func With(key string, value interface{}) Logger {
	return baseLogger.With(key, value)
}

func Debug(args ...interface{}) {
	baseLogger.sourced().Debug(args...)
}

func Debugln(args ...interface{}) {
	baseLogger.sourced().Debugln(args...)
}

func Debugf(format string, args ...interface{}) {
	baseLogger.sourced().Debugf(format, args...)
}

func Info(args ...interface{}) {
	baseLogger.sourced().Info(args...)
}

func Infoln(args ...interface{}) {
	baseLogger.sourced().Infoln(args...)
}

func Infof(format string, args ...interface{}) {
	baseLogger.sourced().Infof(format, args...)
}

func Warn(args ...interface{}) {
	baseLogger.sourced().Warn(args...)
}

func Warnln(args ...interface{}) {
	baseLogger.sourced().Warnln(args...)
}

func Warnf(format string, args ...interface{}) {
	baseLogger.sourced().Warnf(format, args...)
}

func Error(args ...interface{}) {
	baseLogger.sourced().Error(args...)
}

func Errorln(args ...interface{}) {
	baseLogger.sourced().Errorln(args...)
}

func Errorf(format string, args ...interface{}) {
	baseLogger.sourced().Errorf(format, args...)
}

func Fatal(args ...interface{}) {
	baseLogger.sourced().Fatal(args...)
}

func Fatalln(args ...interface{}) {
	baseLogger.sourced().Fatalln(args...)
}

func Fatalf(format string, args ...interface{}) {
	baseLogger.sourced().Fatalf(format, args...)
}

func AddHook(hook logrus.Hook) {
	origLogger.Hooks.Add(hook)
}

func SetOutput(w io.Writer) {
	origLogger.Out = w
}

func SetLevel(level string) error {
	return baseLogger.SetLevel(level)
}

func SetFormat(format string) error {
	return baseLogger.SetFormat(format)
}
