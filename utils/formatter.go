package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// TableFormatter provides standardized table formatting for CLI output
type TableFormatter struct {
	writer   *tabwriter.Writer
	jsonMode bool
	headers  []string
	rows     [][]string
}

// NewTableFormatter creates a new table formatter with standard settings
func NewTableFormatter() *TableFormatter {
	return &TableFormatter{
		writer: tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0),
	}
}

// NewJSONFormatter creates a new table formatter that outputs JSON
func NewJSONFormatter() *TableFormatter {
	return &TableFormatter{
		jsonMode: true,
		headers:  []string{},
		rows:     [][]string{},
	}
}

// AddHeader adds a header row to the table
func (tf *TableFormatter) AddHeader(columns ...string) {
	if tf.jsonMode {
		tf.headers = columns
	} else {
		tf.AddRow(columns...)
	}
}

// AddRow adds a data row to the table
func (tf *TableFormatter) AddRow(columns ...string) {
	if tf.jsonMode {
		tf.rows = append(tf.rows, columns)
	} else {
		fmt.Fprintln(tf.writer, strings.Join(columns, "\t"))
	}
}

// Render flushes the table to stdout
func (tf *TableFormatter) Render() error {
	if tf.jsonMode {
		// Convert rows to JSON objects
		var result []map[string]string
		for _, row := range tf.rows {
			obj := make(map[string]string)
			for i, header := range tf.headers {
				if i < len(row) {
					obj[header] = row[i]
				} else {
					obj[header] = ""
				}
			}
			result = append(result, obj)
		}

		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(jsonData))
		return nil
	} else {
		return tf.writer.Flush()
	}
}

// PrintSectionHeader prints a standardized section header
func PrintSectionHeader(title string) {
	fmt.Printf("%s\n", title)
	fmt.Printf("%s\n", strings.Repeat("=", len(title)))
}

// PrintKeyValue prints a key-value pair in a consistent format
func PrintKeyValue(key, value string) {
	fmt.Printf("  %-18s : %s\n", key, value)
}

// PrintInfo prints an informational message
func PrintInfo(message string) {
	fmt.Printf("INFO: %s\n", message)
}

// PrintSuccess prints a success message
func PrintSuccess(message string) {
	fmt.Printf("✓ %s\n", message)
}

// PrintWarning prints a warning message
func PrintWarning(message string) {
	fmt.Printf("⚠ %s\n", message)
}

// PrintError prints an error message
func PrintError(message string) {
	fmt.Printf("✗ %s\n", message)
}

// PrintEmptyState prints a standardized message when no items are found
func PrintEmptyState(itemType string) {
	fmt.Printf("No %s found.\n", itemType)
}

// JSONMessage represents a structured JSON message
type JSONMessage struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// PrintJSONMessage prints a structured JSON message
func PrintJSONMessage(level, message string) {
	msg := JSONMessage{
		Level:   level,
		Message: message,
	}
	jsonData, _ := json.Marshal(msg)
	fmt.Println(string(jsonData))
}

// PrintJSONInfo prints an info message in JSON format
func PrintJSONInfo(message string) {
	PrintJSONMessage("info", message)
}

// PrintJSONSuccess prints a success message in JSON format
func PrintJSONSuccess(message string) {
	PrintJSONMessage("success", message)
}

// PrintJSONWarning prints a warning message in JSON format
func PrintJSONWarning(message string) {
	PrintJSONMessage("warning", message)
}

// PrintJSONError prints an error message in JSON format
func PrintJSONError(message string) {
	PrintJSONMessage("error", message)
}

// PrintJSONData prints structured data as JSON
func PrintJSONData(data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonData))
	return nil
}

// IsJSONMode checks if JSON output is enabled from context
func IsJSONMode(ctx interface{}) bool {
	if ctx == nil {
		return false
	}
	// Try to get context value - this works with context.Context
	if contexter, ok := ctx.(context.Context); ok {
		if jsonFlag := contexter.Value("json"); jsonFlag != nil {
			if enabled, ok := jsonFlag.(bool); ok {
				return enabled
			}
		}
	}
	return false
}
