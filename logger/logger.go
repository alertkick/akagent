package logger

import (
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
	"gopkg.in/natefinch/lumberjack.v2"
)

var once sync.Once
var log zerolog.Logger
var logLevel int

// VerboseLevel controls the verbosity of byte/message dumps
// 0 = No raw bytes
// 1 = Truncated (100 chars)
// 2 = Full JSON
// 3 = Hex dump for debugging
var VerboseLevel int

// enabledSections contains the set of enabled log sections
// Sections are DISABLED by default - only explicitly enabled sections will log
// Use LOG_SECTIONS=all to enable all sections for debugging
var enabledSections map[string]bool
var allSectionsEnabled bool
var sectionsLock sync.RWMutex

// Log sections for filtering
const (
	SectionConnection = "connection"
	SectionHeartbeat  = "heartbeat"
	SectionMetrics    = "metrics"
	SectionFalco      = "falco"
	SectionAuth       = "auth"
	SectionProtocol   = "protocol"
)

func init() {
	// Parse VERBOSE_LEVEL environment variable
	if v, err := strconv.Atoi(os.Getenv("VERBOSE_LEVEL")); err == nil {
		VerboseLevel = v
	}

	// Parse LOG_SECTIONS environment variable (comma-separated)
	// Example: LOG_SECTIONS=metrics,falco,heartbeat
	// Use LOG_SECTIONS=all to enable all sections
	sectionsEnv := os.Getenv("LOG_SECTIONS")
	if sectionsEnv != "" {
		enabledSections = make(map[string]bool)
		for _, section := range strings.Split(sectionsEnv, ",") {
			section = strings.TrimSpace(strings.ToLower(section))
			if section == "all" {
				allSectionsEnabled = true
				break
			}
			if section != "" {
				enabledSections[section] = true
			}
		}
	}
}

// IsSectionEnabled checks if a log section is enabled
// Returns false by default - sections must be explicitly enabled via LOG_SECTIONS
func IsSectionEnabled(section string) bool {
	sectionsLock.RLock()
	defer sectionsLock.RUnlock()

	// If "all" was specified, all sections are enabled
	if allSectionsEnabled {
		return true
	}

	// Sections are disabled by default - must be explicitly enabled
	if enabledSections == nil || len(enabledSections) == 0 {
		return false
	}
	return enabledSections[section]
}

// EnableSection enables a log section at runtime
func EnableSection(section string) {
	sectionsLock.Lock()
	defer sectionsLock.Unlock()
	if enabledSections == nil {
		enabledSections = make(map[string]bool)
	}
	enabledSections[section] = true
}

// DisableSection disables a log section at runtime
func DisableSection(section string) {
	sectionsLock.Lock()
	defer sectionsLock.Unlock()
	if enabledSections != nil {
		delete(enabledSections, section)
	}
}

// SetVerboseLevel sets the verbose level from config
// This can override the VERBOSE_LEVEL environment variable
func SetVerboseLevel(level int) {
	VerboseLevel = level
}

// SetLogSections sets enabled sections from a comma-separated string
// This can override the LOG_SECTIONS environment variable
// Use "all" to enable all sections, empty string to disable all
func SetLogSections(sections string) {
	sectionsLock.Lock()
	defer sectionsLock.Unlock()

	if sections == "" {
		// Empty means disable all sections (default behavior)
		enabledSections = nil
		allSectionsEnabled = false
		return
	}

	enabledSections = make(map[string]bool)
	allSectionsEnabled = false

	for _, section := range strings.Split(sections, ",") {
		section = strings.TrimSpace(strings.ToLower(section))
		if section == "all" {
			allSectionsEnabled = true
			return
		}
		if section != "" {
			enabledSections[section] = true
		}
	}
}

// GetVerboseLevel returns the current verbose level
func GetVerboseLevel() int {
	return VerboseLevel
}

// GetEnabledSections returns a comma-separated string of enabled sections
func GetEnabledSections() string {
	sectionsLock.RLock()
	defer sectionsLock.RUnlock()

	if allSectionsEnabled {
		return "all"
	}
	if enabledSections == nil || len(enabledSections) == 0 {
		return ""
	}

	sections := make([]string, 0, len(enabledSections))
	for section := range enabledSections {
		sections = append(sections, section)
	}
	return strings.Join(sections, ",")
}

// FormatBytes formats byte data according to VerboseLevel
// Returns empty string if VerboseLevel is 0
func FormatBytes(data []byte) string {
	switch VerboseLevel {
	case 0:
		return ""
	case 1:
		s := string(data)
		if len(s) > 100 {
			return s[:97] + "..."
		}
		return s
	case 2:
		return string(data)
	case 3:
		return hex.EncodeToString(data)
	default:
		return ""
	}
}

// FormatString formats string data according to VerboseLevel
func FormatString(s string) string {
	switch VerboseLevel {
	case 0:
		return ""
	case 1:
		if len(s) > 100 {
			return s[:97] + "..."
		}
		return s
	case 2, 3:
		return s
	default:
		return ""
	}
}

func Get() zerolog.Logger {
	once.Do(func() {
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
		zerolog.TimeFieldFormat = time.RFC3339Nano

		logLevel, err := strconv.Atoi(os.Getenv("LOG_LEVEL"))
		if err != nil {
			logLevel = int(zerolog.DebugLevel) // default to DEBUG
		}

		var output io.Writer = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}

		if os.Getenv("AGENT_ENV") == "production" {
			fileLogger := &lumberjack.Logger{
				Filename:   "apagent.log",
				MaxSize:    5,
				MaxBackups: 10,
				MaxAge:     14,
				Compress:   true,
			}
			output = zerolog.MultiLevelWriter(os.Stderr, fileLogger)
		}

		log = zerolog.New(output).
			Level(zerolog.Level(logLevel)).
			With().
			Timestamp().
			Logger()
	})

	return log
}

func Sublogger(componentName string) zerolog.Logger {
	return Get().Level(zerolog.Level(logLevel)).With().Str("component", componentName).Logger()
}

// AgentLogger creates a logger with agent context
func AgentLogger(agentID, subdomain, component string) zerolog.Logger {
	return Get().Level(zerolog.Level(logLevel)).With().
		Str("agent_id", agentID).
		Str("subdomain", subdomain).
		Str("component", component).
		Logger()
}

// SectionLogger wraps a zerolog.Logger with section-based filtering
type SectionLogger struct {
	logger  zerolog.Logger
	section string
}

// NewSectionLogger creates a logger for a specific section
func NewSectionLogger(base zerolog.Logger, section string) *SectionLogger {
	return &SectionLogger{
		logger:  base.With().Str("section", section).Logger(),
		section: section,
	}
}

// Debug logs at debug level if section is enabled
func (s *SectionLogger) Debug() *zerolog.Event {
	if !IsSectionEnabled(s.section) {
		return nil
	}
	return s.logger.Debug()
}

// Info logs at info level if section is enabled
func (s *SectionLogger) Info() *zerolog.Event {
	if !IsSectionEnabled(s.section) {
		return nil
	}
	return s.logger.Info()
}

// Warn logs at warn level (always enabled)
func (s *SectionLogger) Warn() *zerolog.Event {
	return s.logger.Warn()
}

// Error logs at error level (always enabled)
func (s *SectionLogger) Error() *zerolog.Event {
	return s.logger.Error()
}

// Logger returns the underlying zerolog.Logger
func (s *SectionLogger) Logger() zerolog.Logger {
	return s.logger
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
