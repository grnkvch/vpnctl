package output

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
)

const (
	ResultSchemaVersion = 1
	MaximumSafeDepth    = 32
	MaximumSafeItems    = 4096
	MaximumSafeString   = 4096
)

type Status string

const (
	StatusOK       Status = "ok"
	StatusPending  Status = "pending"
	StatusDegraded Status = "degraded"
	StatusFailed   Status = "failed"
)

type ExitCategory string

const (
	CategorySuccess     ExitCategory = "success"
	CategoryValidation  ExitCategory = "validation"
	CategoryConflict    ExitCategory = "conflict"
	CategoryUnavailable ExitCategory = "unavailable"
	CategoryInternal    ExitCategory = "internal"
)

type SafeObject map[string]any
type SafeList []any

type Result struct {
	SchemaVersion  int               `json:"schema_version"`
	Command        string            `json:"command"`
	Status         Status            `json:"status"`
	ExitCategory   ExitCategory      `json:"exit_category"`
	ResourceIDs    map[string]string `json:"resource_ids"`
	Warnings       []Message         `json:"warnings"`
	RequiresAction []Action          `json:"requires_action"`
	Data           SafeObject        `json:"data"`
	humanOnly      []humanOnlyField
	humanTables    []humanTable
}

type humanOnlyField struct {
	key   string
	value SensitivePath
}

type humanTable struct {
	title   string
	columns []string
	rows    [][]string
}

// Format keeps human-only sensitive fields out of generic log/debug output.
// Explicit user-facing rendering remains the sole path that may reveal them.
func (result Result) Format(state fmt.State, _ rune) {
	encoded, err := json.Marshal(result)
	if err != nil {
		_, _ = io.WriteString(state, "<vpnctl-result>")
		return
	}
	_, _ = state.Write(encoded)
}

type Message struct {
	Code        string            `json:"code"`
	Message     string            `json:"message"`
	ResourceIDs map[string]string `json:"resource_ids,omitempty"`
}

type Action struct {
	Code        string            `json:"code"`
	Message     string            `json:"message"`
	Command     string            `json:"command,omitempty"`
	ResourceIDs map[string]string `json:"resource_ids,omitempty"`
}

var (
	commandPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$`)
	codePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	safeKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

func NewResult(command string, status Status, category ExitCategory, data SafeObject) Result {
	if data == nil {
		data = SafeObject{}
	}
	return Result{
		SchemaVersion:  ResultSchemaVersion,
		Command:        command,
		Status:         status,
		ExitCategory:   category,
		ResourceIDs:    map[string]string{},
		Warnings:       []Message{},
		RequiresAction: []Action{},
		Data:           data,
	}
}

// AddHumanSensitivePath adds a value that may be rendered only to the concise
// human stream. The field is deliberately unexported from Result, so JSON and
// ordinary debug formatting cannot reveal webhook paths or derived URLs.
func (result *Result) AddHumanSensitivePath(key string, value SensitivePath) error {
	if result == nil {
		return fmt.Errorf("result is required")
	}
	if !safeKeyPattern.MatchString(key) {
		return fmt.Errorf("human-only key must be a stable lower-case identifier")
	}
	if err := value.Use(func(string) error { return nil }); err != nil {
		return err
	}
	for _, existing := range result.humanOnly {
		if existing.key == key {
			return fmt.Errorf("human-only key %q is duplicated", key)
		}
	}
	if len(result.humanOnly) >= MaximumSafeItems {
		return fmt.Errorf("human-only output contains too many entries")
	}
	result.humanOnly = append(result.humanOnly, humanOnlyField{key: key, value: value})
	return nil
}

// AddHumanTable attaches a non-JSON projection used by concise human output.
// It lets status keep one complete JSON document while showing only problems
// by default and expanding tables after an explicit --all.
func (result *Result) AddHumanTable(title string, columns []string, rows [][]string) error {
	if result == nil {
		return fmt.Errorf("result is required")
	}
	if !safeKeyPattern.MatchString(title) {
		return fmt.Errorf("human table title must be a stable lower-case identifier")
	}
	if len(columns) == 0 || len(columns) > MaximumSafeItems || len(rows) > MaximumSafeItems {
		return fmt.Errorf("human table dimensions are invalid")
	}
	for _, existing := range result.humanTables {
		if existing.title == title {
			return fmt.Errorf("human table %q is duplicated", title)
		}
	}
	clonedColumns := append([]string{}, columns...)
	seen := make(map[string]struct{}, len(clonedColumns))
	for _, column := range clonedColumns {
		if !safeKeyPattern.MatchString(column) {
			return fmt.Errorf("human table column must be a stable lower-case identifier")
		}
		if _, duplicate := seen[column]; duplicate {
			return fmt.Errorf("human table column %q is duplicated", column)
		}
		seen[column] = struct{}{}
	}
	clonedRows := make([][]string, len(rows))
	for rowIndex, row := range rows {
		if len(row) != len(clonedColumns) {
			return fmt.Errorf("human table row %d has %d cells, want %d", rowIndex, len(row), len(clonedColumns))
		}
		clonedRows[rowIndex] = append([]string{}, row...)
		for columnIndex, cell := range clonedRows[rowIndex] {
			if len(cell) > MaximumSafeString || strings.ContainsAny(cell, "\x00\t\r\n") {
				return fmt.Errorf("human table cell %d/%d must be a single line of at most %d bytes", rowIndex, columnIndex, MaximumSafeString)
			}
		}
	}
	result.humanTables = append(result.humanTables, humanTable{title: title, columns: clonedColumns, rows: clonedRows})
	return nil
}

func (result Result) Validate() error {
	if result.SchemaVersion != ResultSchemaVersion {
		return fmt.Errorf("schema_version must be %d", ResultSchemaVersion)
	}
	if !commandPattern.MatchString(result.Command) {
		return fmt.Errorf("command must be a stable dotted lower-case identifier")
	}
	if !validStatus(result.Status) {
		return fmt.Errorf("status %q is unsupported", result.Status)
	}
	if !validExitCategory(result.ExitCategory) {
		return fmt.Errorf("exit_category %q is unsupported", result.ExitCategory)
	}
	if err := validateStatusCategory(result.Status, result.ExitCategory); err != nil {
		return err
	}
	if err := validateResourceIDs("resource_ids", result.ResourceIDs, true); err != nil {
		return err
	}
	if result.Warnings == nil {
		return fmt.Errorf("warnings must be present as a JSON array")
	}
	for index, warning := range result.Warnings {
		if err := warning.Validate(); err != nil {
			return fmt.Errorf("warnings[%d]: %w", index, err)
		}
	}
	if result.RequiresAction == nil {
		return fmt.Errorf("requires_action must be present as a JSON array")
	}
	for index, action := range result.RequiresAction {
		if err := action.Validate(); err != nil {
			return fmt.Errorf("requires_action[%d]: %w", index, err)
		}
	}
	if result.Data == nil {
		return fmt.Errorf("data must be present as a JSON object")
	}
	if err := validateSafeObject("data", result.Data, 0); err != nil {
		return err
	}
	seenHumanOnly := make(map[string]struct{}, len(result.humanOnly))
	for index, field := range result.humanOnly {
		if !safeKeyPattern.MatchString(field.key) {
			return fmt.Errorf("human-only field %d has an invalid key", index)
		}
		if _, duplicate := seenHumanOnly[field.key]; duplicate {
			return fmt.Errorf("human-only field %q is duplicated", field.key)
		}
		seenHumanOnly[field.key] = struct{}{}
		if err := field.value.Use(func(string) error { return nil }); err != nil {
			return fmt.Errorf("human-only field %q: %w", field.key, err)
		}
	}
	seenTables := make(map[string]struct{}, len(result.humanTables))
	for index, table := range result.humanTables {
		if !safeKeyPattern.MatchString(table.title) || len(table.columns) == 0 || len(table.columns) > MaximumSafeItems || len(table.rows) > MaximumSafeItems {
			return fmt.Errorf("human table %d is invalid", index)
		}
		if _, duplicate := seenTables[table.title]; duplicate {
			return fmt.Errorf("human table %q is duplicated", table.title)
		}
		seenTables[table.title] = struct{}{}
		seenColumns := make(map[string]struct{}, len(table.columns))
		for _, column := range table.columns {
			if !safeKeyPattern.MatchString(column) {
				return fmt.Errorf("human table %q column is invalid", table.title)
			}
			if _, duplicate := seenColumns[column]; duplicate {
				return fmt.Errorf("human table %q column %q is duplicated", table.title, column)
			}
			seenColumns[column] = struct{}{}
		}
		for rowIndex, row := range table.rows {
			if len(row) != len(table.columns) {
				return fmt.Errorf("human table %q row %d has invalid width", table.title, rowIndex)
			}
			for _, cell := range row {
				if len(cell) > MaximumSafeString || strings.ContainsAny(cell, "\x00\t\r\n") {
					return fmt.Errorf("human table %q row %d has an invalid cell", table.title, rowIndex)
				}
			}
		}
	}
	return nil
}

func (message Message) Validate() error {
	if !codePattern.MatchString(message.Code) {
		return fmt.Errorf("code must be a stable lower-case identifier")
	}
	if err := validateHumanText("message", message.Message); err != nil {
		return err
	}
	return validateResourceIDs("resource_ids", message.ResourceIDs, false)
}

func (action Action) Validate() error {
	if !codePattern.MatchString(action.Code) {
		return fmt.Errorf("code must be a stable lower-case identifier")
	}
	if err := validateHumanText("message", action.Message); err != nil {
		return err
	}
	if action.Command != "" {
		if len(action.Command) > MaximumSafeString || strings.TrimSpace(action.Command) != action.Command || strings.ContainsAny(action.Command, "\x00\r\n") {
			return fmt.Errorf("command must be a trimmed single line of at most %d bytes", MaximumSafeString)
		}
	}
	return validateResourceIDs("resource_ids", action.ResourceIDs, false)
}

func validateHumanText(path, value string) error {
	if value == "" || len(value) > MaximumSafeString || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s must be a non-empty trimmed single line of at most %d bytes", path, MaximumSafeString)
	}
	return nil
}

func validateResourceIDs(path string, values map[string]string, required bool) error {
	if values == nil {
		if required {
			return fmt.Errorf("%s must be present as a JSON object", path)
		}
		return nil
	}
	if len(values) > MaximumSafeItems {
		return fmt.Errorf("%s contains too many entries", path)
	}
	for key, value := range values {
		if err := validateSafeKey(key); err != nil {
			return fmt.Errorf("%s.%s: %w", path, key, err)
		}
		if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s.%s must be a non-empty single-line identifier of at most 256 bytes", path, key)
		}
	}
	return nil
}

func validateSafeObject(path string, object SafeObject, depth int) error {
	if depth > MaximumSafeDepth {
		return fmt.Errorf("%s exceeds maximum nesting depth %d", path, MaximumSafeDepth)
	}
	if len(object) > MaximumSafeItems {
		return fmt.Errorf("%s contains too many entries", path)
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := validateSafeKey(key); err != nil {
			return fmt.Errorf("%s.%s: %w", path, key, err)
		}
		if err := validateSafeValue(path+"."+key, object[key], depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateSafeValue(path string, value any, depth int) error {
	switch typed := value.(type) {
	case nil, bool:
		return nil
	case string:
		if len(typed) > MaximumSafeString || strings.ContainsRune(typed, '\x00') {
			return fmt.Errorf("%s string exceeds safe limits", path)
		}
		return nil
	case json.Number:
		if _, err := typed.Float64(); err != nil {
			return fmt.Errorf("%s contains invalid JSON number: %w", path, err)
		}
		return nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return fmt.Errorf("%s contains non-finite number", path)
		}
		return nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return fmt.Errorf("%s contains non-finite number", path)
		}
		return nil
	case SafeObject:
		return validateSafeObject(path, typed, depth)
	case map[string]any:
		return validateSafeObject(path, SafeObject(typed), depth)
	case []any:
		return validateSafeList(path, SafeList(typed), depth)
	case SafeList:
		return validateSafeList(path, typed, depth)
	case []SafeObject:
		items := make(SafeList, len(typed))
		for index := range typed {
			items[index] = typed[index]
		}
		return validateSafeList(path, items, depth)
	case []string:
		items := make(SafeList, len(typed))
		for index := range typed {
			items[index] = typed[index]
		}
		return validateSafeList(path, items, depth)
	default:
		return fmt.Errorf("%s has unsupported value type %T", path, value)
	}
}

func validateSafeList(path string, values SafeList, depth int) error {
	if depth > MaximumSafeDepth {
		return fmt.Errorf("%s exceeds maximum nesting depth %d", path, MaximumSafeDepth)
	}
	if len(values) > MaximumSafeItems {
		return fmt.Errorf("%s contains too many entries", path)
	}
	for index, item := range values {
		if err := validateSafeValue(fmt.Sprintf("%s[%d]", path, index), item, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateSafeKey(key string) error {
	if !safeKeyPattern.MatchString(key) || !ClassifyField(key).AllowedInResult {
		return fmt.Errorf("key is not allowed by the safe output contract")
	}
	return nil
}

func validStatus(status Status) bool {
	return status == StatusOK || status == StatusPending || status == StatusDegraded || status == StatusFailed
}

func validExitCategory(category ExitCategory) bool {
	return category == CategorySuccess || category == CategoryValidation || category == CategoryConflict || category == CategoryUnavailable || category == CategoryInternal
}

func validateStatusCategory(status Status, category ExitCategory) error {
	switch status {
	case StatusOK, StatusPending:
		if category != CategorySuccess {
			return fmt.Errorf("status %s requires success exit_category", status)
		}
	case StatusDegraded:
		if category != CategoryUnavailable && category != CategoryConflict {
			return fmt.Errorf("degraded status requires unavailable or conflict exit_category")
		}
	case StatusFailed:
		if category == CategorySuccess {
			return fmt.Errorf("failed status cannot use success exit_category")
		}
	}
	return nil
}
