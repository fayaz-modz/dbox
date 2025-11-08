package logger

import (
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	Verbose bool
)

type DboxLogger struct {
	LogFile *os.File
}

func NewDboxLogger(logPath string) *DboxLogger {
	if logPath == "" {
		return &DboxLogger{}
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return &DboxLogger{}
	}

	return &DboxLogger{LogFile: logFile}
}

func (l *DboxLogger) Log(message string) {
	if l.LogFile != nil {
		timestamp := time.Now().Format(time.RFC3339)
		logEntry := fmt.Sprintf("[%s] DBOX: %s\n", timestamp, message)
		l.LogFile.WriteString(logEntry)
		l.LogFile.Sync()
	}
}

func (l *DboxLogger) Close() {
	if l.LogFile != nil {
		l.LogFile.Close()
	}
}

func LogInfo(format string, args ...any) {
	fmt.Printf("dbox: "+format+"\n", args...)
}

func LogVerbose(format string, args ...any) {
	if Verbose {
		fmt.Printf("dbox: "+format+"\n", args...)
	}
}

func LogDebug(format string, args ...any) {
	if Verbose {
		fmt.Printf("dbox: DEBUG: "+format+"\n", args...)
	}
}

func LogCommand(cmd string, args []string) {
	if Verbose {
		fmt.Printf("dbox: RUNNING: %s %s\n", cmd, strings.Join(args, " "))
	}
}
