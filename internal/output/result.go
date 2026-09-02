package output

import (
	"encoding/json"
	"fmt"
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
	return validateSafeObject("data", result.Data, 0)
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
		if category != CategoryUnavailable {
			return fmt.Errorf("degraded status requires unavailable exit_category")
		}
	case StatusFailed:
		if category == CategorySuccess {
			return fmt.Errorf("failed status cannot use success exit_category")
		}
	}
	return nil
}
