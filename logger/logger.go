package logger

import (
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
	"gopkg.in/natefinch/lumberjack.v2"
)

var once sync.Once
var log zerolog.Logger
var logLevel int

func Get() zerolog.Logger {
	once.Do(func() {
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
		zerolog.TimeFieldFormat = time.RFC3339Nano

		logLevel, err := strconv.Atoi(os.Getenv("LOG_LEVEL"))
		if err != nil {
			logLevel = int(zerolog.DebugLevel) // default to INFO
		}

		var output io.Writer = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}

		if os.Getenv("AGENT_ENV") == "production" {
			fileLogger := &lumberjack.Logger{
				Filename:   "akagent.log",
				MaxSize:    5,
				MaxBackups: 10,
				MaxAge:     14,
				Compress:   true,
			}
			output = zerolog.MultiLevelWriter(os.Stderr, fileLogger)
		}

		// var gitRevision string

		// buildInfo, ok := debug.ReadBuildInfo()
		// if ok {
		// 	for _, v := range buildInfo.Settings {
		// 		if v.Key == "vcs.revision" {
		// 			gitRevision = v.Value
		// 			break
		// 		}
		// 	}
		// }

		log = zerolog.New(output).
			Level(zerolog.Level(logLevel)).
			With().
			Timestamp().
			Logger()
	})

	return log
}

func Sublogger(componentName string) zerolog.Logger {
	return Get().Level(zerolog.Level(logLevel)).With().Str("sub", componentName).Logger()
}

func SetupLogLevel(debug bool) {
	if debug {
		log.Info().Msgf("log level: debug")
		logLevel = int(zerolog.DebugLevel)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		log.Info().Msgf("log level: info")
		logLevel = int(zerolog.InfoLevel)
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

// func InitializeDefaultLogger() zerolog.Logger {

// 	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
// 	// Default level for this example is info, unless debug flag is present
// 	zerolog.SetGlobalLevel(zerolog.InfoLevel)

// 	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
// 	// multi := zerolog.MultiLevelWriter(consoleWriter, os.Stdout)

// 	output.FormatLevel = func(i interface{}) string {
// 		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
// 	}
// 	output.FormatMessage = func(i interface{}) string {
// 		return fmt.Sprintf("%s", i)
// 	}
// 	output.FormatFieldName = func(i interface{}) string {
// 		return fmt.Sprintf("%s:", i)
// 	}
// 	// output.FormatFieldValue = func(i interface{}) string {
// 	// 	return strings.ToUpper(fmt.Sprintf("%s", i))
// 	// }
// 	return zerolog.New(output).With().Timestamp().Logger()
// }
