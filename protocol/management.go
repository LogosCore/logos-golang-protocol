package protocol

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"time"
)

// This file defines module management: the manifest a module declares at
// module.register (manageable properties, triggerable actions, reported status
// values) and the core → module management RPC payloads that apply config and
// invoke actions. Core owns desired property values; the module is the
// authority on what it actually applied.

// ManagementSchemaV1 is the current manifest schema version.
const ManagementSchemaV1 = "1"

// Core → module management RPC operation types, sent to the module's rpc_queue.
const (
	TypeMgmtConfigApply  = "mgmt.config.apply"
	TypeMgmtActionInvoke = "mgmt.action.invoke"
	TypeMgmtStateGet     = "mgmt.state.get"
)

// Additional control-plane error codes used by management RPC.
const (
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeActionFailed = "action_failed"
)

// FieldType is the value type of a property, action parameter, or status value.
// Each maps to one UI control and one validation rule set.
type FieldType string

const (
	FieldString     FieldType = "string"
	FieldInt        FieldType = "int"
	FieldNumber     FieldType = "number"
	FieldBool       FieldType = "bool"
	FieldEnum       FieldType = "enum"
	FieldDuration   FieldType = "duration"    // Go duration string, e.g. "30s"
	FieldBytes      FieldType = "bytes"       // integer byte count
	FieldURL        FieldType = "url"         // absolute URL string
	FieldSecret     FieldType = "secret"      // write-only string; never echoed back
	FieldStringList FieldType = "string_list" // JSON array of strings
)

// ApplyMode says whether a property change takes effect immediately or only
// after the module restarts.
type ApplyMode string

const (
	ApplyLive    ApplyMode = "live"
	ApplyRestart ApplyMode = "restart"
)

// Risk classifies an action. Core maps risk to the permission required to
// invoke it; modules never decide authorization.
type Risk string

const (
	RiskLow  Risk = "low"
	RiskHigh Risk = "high"
)

// EnumOption is one allowed value of an enum field.
type EnumOption struct {
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

// FieldSpec describes a typed value plus its constraints and UI hints. It is
// shared by properties and action parameters.
//
// Min and Max are numbers for int/number/bytes, duration strings for duration,
// and ignored otherwise.
type FieldSpec struct {
	Key         string       `json:"key"`
	Type        FieldType    `json:"type"`
	Label       string       `json:"label,omitempty"`
	Description string       `json:"description,omitempty"`
	Group       string       `json:"group,omitempty"`
	Order       int          `json:"order,omitempty"`
	Unit        string       `json:"unit,omitempty"`
	Placeholder string       `json:"placeholder,omitempty"`
	Required    bool         `json:"required,omitempty"`
	Default     any          `json:"default,omitempty"`
	Min         any          `json:"min,omitempty"`
	Max         any          `json:"max,omitempty"`
	Pattern     string       `json:"pattern,omitempty"`
	MaxLength   int          `json:"max_length,omitempty"`
	Options     []EnumOption `json:"options,omitempty"`
}

// PropertySpec is a manageable property. Default is the module's own effective
// default (typically its env/config-file value), used when core holds no value.
type PropertySpec struct {
	FieldSpec
	Apply ApplyMode `json:"apply"`
}

// ActionSpec is an operator-triggerable action.
type ActionSpec struct {
	Name           string      `json:"name"`
	Label          string      `json:"label,omitempty"`
	Description    string      `json:"description,omitempty"`
	Risk           Risk        `json:"risk"`
	Confirm        string      `json:"confirm,omitempty"` // confirmation prompt shown before invoking
	Params         []FieldSpec `json:"params,omitempty"`
	TimeoutSeconds int         `json:"timeout_seconds,omitempty"`
}

// StatusSpec describes a read-only status value the module reports in its
// heartbeat metrics under Key.
type StatusSpec struct {
	Key         string    `json:"key"`
	Type        FieldType `json:"type"`
	Label       string    `json:"label,omitempty"`
	Description string    `json:"description,omitempty"`
	Unit        string    `json:"unit,omitempty"`
}

// ManagementManifest is declared by a module in module.register under
// "management".
type ManagementManifest struct {
	SchemaVersion string         `json:"schema_version"`
	Properties    []PropertySpec `json:"properties,omitempty"`
	Actions       []ActionSpec   `json:"actions,omitempty"`
	Status        []StatusSpec   `json:"status,omitempty"`
}

// ManagementConfig is the effective config core hands a module: in the
// module.register reply under config.management, and in mgmt.config.apply.
// Values holds every property core has a value for; a property absent from
// Values reverts to the module's own default. Applying it is idempotent.
type ManagementConfig struct {
	Revision int64          `json:"revision"`
	Values   map[string]any `json:"values"`
}

// Actor identifies who triggered a management operation, propagated by core
// for module-side audit logging.
type Actor struct {
	Type string `json:"type"` // user | agent | system
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// ConfigApplyRequest is the mgmt.config.apply payload.
type ConfigApplyRequest struct {
	ManagementConfig
	Actor *Actor `json:"actor,omitempty"`
}

// ConfigApplyReply is the mgmt.config.apply reply payload. AppliedRevision is
// the revision the module processed, even if some keys were rejected, so a
// rejected value never causes an endless re-apply loop.
type ConfigApplyReply struct {
	AppliedRevision int64             `json:"applied_revision"`
	Rejected        map[string]string `json:"rejected,omitempty"`         // key -> reason
	RestartRequired []string          `json:"restart_required,omitempty"` // changed restart-mode keys
}

// ActionInvokeRequest is the mgmt.action.invoke payload. Modules must treat a
// repeated InvocationID as the same invocation.
type ActionInvokeRequest struct {
	InvocationID string         `json:"invocation_id"`
	Action       string         `json:"action"`
	Params       map[string]any `json:"params,omitempty"`
	Actor        *Actor         `json:"actor,omitempty"`
}

// ActionInvokeReply is the mgmt.action.invoke success payload. Failures are
// error replies with code action_failed (or validation_failed / not_found).
type ActionInvokeReply struct {
	InvocationID string `json:"invocation_id"`
	Result       any    `json:"result,omitempty"`
}

// StateGetReply is the mgmt.state.get reply payload: the module's effective
// values (secrets redacted) and current status values.
type StateGetReply struct {
	AppliedRevision int64          `json:"applied_revision"`
	Values          map[string]any `json:"values"`
	Status          map[string]any `json:"status,omitempty"`
	RestartRequired []string       `json:"restart_required,omitempty"`
}

// --- validation ----------------------------------------------------------

// Manifest limits keep a misbehaving module from flooding core or the UI.
const (
	MaxManifestProperties = 64
	MaxManifestActions    = 32
	MaxManifestStatus     = 64
	MaxActionParams       = 16
	MaxEnumOptions        = 64
	MaxLabelLength        = 120
	MaxDescriptionLength  = 1000
	MaxActionTimeout      = 60 // seconds
)

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

var fieldTypes = map[FieldType]bool{
	FieldString: true, FieldInt: true, FieldNumber: true, FieldBool: true, FieldEnum: true,
	FieldDuration: true, FieldBytes: true, FieldURL: true, FieldSecret: true, FieldStringList: true,
}

// ValidateManifest checks a manifest's structure, limits, and that every
// declared default satisfies its own field spec.
func ValidateManifest(m ManagementManifest) error {
	if m.SchemaVersion != ManagementSchemaV1 {
		return fmt.Errorf("unsupported management schema_version %q", m.SchemaVersion)
	}
	if len(m.Properties) > MaxManifestProperties {
		return fmt.Errorf("too many properties (%d > %d)", len(m.Properties), MaxManifestProperties)
	}
	if len(m.Actions) > MaxManifestActions {
		return fmt.Errorf("too many actions (%d > %d)", len(m.Actions), MaxManifestActions)
	}
	if len(m.Status) > MaxManifestStatus {
		return fmt.Errorf("too many status values (%d > %d)", len(m.Status), MaxManifestStatus)
	}

	seen := map[string]bool{}
	for _, p := range m.Properties {
		if err := validateFieldSpec(p.FieldSpec); err != nil {
			return fmt.Errorf("property %q: %w", p.Key, err)
		}
		if seen[p.Key] {
			return fmt.Errorf("duplicate property key %q", p.Key)
		}
		seen[p.Key] = true
		if p.Apply != ApplyLive && p.Apply != ApplyRestart {
			return fmt.Errorf("property %q: apply must be %q or %q", p.Key, ApplyLive, ApplyRestart)
		}
	}

	seen = map[string]bool{}
	for _, a := range m.Actions {
		if !keyPattern.MatchString(a.Name) {
			return fmt.Errorf("action %q: name must match %s", a.Name, keyPattern)
		}
		if seen[a.Name] {
			return fmt.Errorf("duplicate action %q", a.Name)
		}
		seen[a.Name] = true
		if a.Risk != RiskLow && a.Risk != RiskHigh {
			return fmt.Errorf("action %q: risk must be %q or %q", a.Name, RiskLow, RiskHigh)
		}
		if err := validateText(a.Label, a.Description); err != nil {
			return fmt.Errorf("action %q: %w", a.Name, err)
		}
		if a.TimeoutSeconds < 0 || a.TimeoutSeconds > MaxActionTimeout {
			return fmt.Errorf("action %q: timeout_seconds must be 0..%d", a.Name, MaxActionTimeout)
		}
		if len(a.Params) > MaxActionParams {
			return fmt.Errorf("action %q: too many params", a.Name)
		}
		params := map[string]bool{}
		for _, p := range a.Params {
			if err := validateFieldSpec(p); err != nil {
				return fmt.Errorf("action %q param %q: %w", a.Name, p.Key, err)
			}
			if params[p.Key] {
				return fmt.Errorf("action %q: duplicate param %q", a.Name, p.Key)
			}
			params[p.Key] = true
		}
	}

	seen = map[string]bool{}
	for _, s := range m.Status {
		if !keyPattern.MatchString(s.Key) {
			return fmt.Errorf("status %q: key must match %s", s.Key, keyPattern)
		}
		if seen[s.Key] {
			return fmt.Errorf("duplicate status key %q", s.Key)
		}
		seen[s.Key] = true
		if !fieldTypes[s.Type] || s.Type == FieldSecret {
			return fmt.Errorf("status %q: invalid type %q", s.Key, s.Type)
		}
		if err := validateText(s.Label, s.Description); err != nil {
			return fmt.Errorf("status %q: %w", s.Key, err)
		}
	}
	return nil
}

func validateText(label, description string) error {
	if len(label) > MaxLabelLength {
		return fmt.Errorf("label longer than %d", MaxLabelLength)
	}
	if len(description) > MaxDescriptionLength {
		return fmt.Errorf("description longer than %d", MaxDescriptionLength)
	}
	return nil
}

func validateFieldSpec(f FieldSpec) error {
	if !keyPattern.MatchString(f.Key) {
		return fmt.Errorf("key must match %s", keyPattern)
	}
	if !fieldTypes[f.Type] {
		return fmt.Errorf("invalid type %q", f.Type)
	}
	if err := validateText(f.Label, f.Description); err != nil {
		return err
	}
	if f.Type == FieldEnum && (len(f.Options) == 0 || len(f.Options) > MaxEnumOptions) {
		return fmt.Errorf("enum needs 1..%d options", MaxEnumOptions)
	}
	if f.Pattern != "" {
		if _, err := regexp.Compile(f.Pattern); err != nil {
			return fmt.Errorf("invalid pattern: %w", err)
		}
	}
	switch f.Type {
	case FieldInt, FieldNumber, FieldBytes:
		for _, b := range []any{f.Min, f.Max} {
			if b != nil {
				if _, ok := toFloat(b); !ok {
					return fmt.Errorf("min/max must be numbers")
				}
			}
		}
	case FieldDuration:
		for _, b := range []any{f.Min, f.Max} {
			if b != nil {
				if _, err := toDuration(b); err != nil {
					return fmt.Errorf("min/max must be durations: %w", err)
				}
			}
		}
	}
	if f.Default != nil && f.Type != FieldSecret {
		if err := ValidateValue(f, f.Default); err != nil {
			return fmt.Errorf("default: %w", err)
		}
	}
	return nil
}

// ValidateValue checks v against f. v is a decoded JSON value (numbers may be
// float64, json.Number, or Go ints). A nil v is valid unless f is required.
// Core runs it before storing a value; the module runs it again before
// applying, since only the module knows its runtime constraints.
func ValidateValue(f FieldSpec, v any) error {
	if v == nil {
		if f.Required {
			return fmt.Errorf("value is required")
		}
		return nil
	}
	switch f.Type {
	case FieldString, FieldSecret, FieldURL, FieldEnum:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("must be a string")
		}
		return validateString(f, s)
	case FieldBool:
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("must be a boolean")
		}
	case FieldInt, FieldBytes, FieldNumber:
		n, ok := toFloat(v)
		if !ok {
			return fmt.Errorf("must be a number")
		}
		if f.Type != FieldNumber && n != math.Trunc(n) {
			return fmt.Errorf("must be an integer")
		}
		if f.Type == FieldBytes && n < 0 {
			return fmt.Errorf("must not be negative")
		}
		if lo, ok := toFloat(f.Min); ok && n < lo {
			return fmt.Errorf("must be >= %v", f.Min)
		}
		if hi, ok := toFloat(f.Max); ok && n > hi {
			return fmt.Errorf("must be <= %v", f.Max)
		}
	case FieldDuration:
		d, err := toDuration(v)
		if err != nil {
			return err
		}
		if f.Min != nil {
			if lo, err := toDuration(f.Min); err == nil && d < lo {
				return fmt.Errorf("must be >= %v", f.Min)
			}
		}
		if f.Max != nil {
			if hi, err := toDuration(f.Max); err == nil && d > hi {
				return fmt.Errorf("must be <= %v", f.Max)
			}
		}
	case FieldStringList:
		items, ok := v.([]any)
		if !ok {
			if ss, ok2 := v.([]string); ok2 {
				for _, s := range ss {
					items = append(items, s)
				}
			} else {
				return fmt.Errorf("must be a list of strings")
			}
		}
		for i, it := range items {
			s, ok := it.(string)
			if !ok {
				return fmt.Errorf("item %d must be a string", i)
			}
			if err := validateString(f, s); err != nil {
				return fmt.Errorf("item %d: %w", i, err)
			}
		}
	default:
		return fmt.Errorf("unknown type %q", f.Type)
	}
	return nil
}

func validateString(f FieldSpec, s string) error {
	if f.MaxLength > 0 && len(s) > f.MaxLength {
		return fmt.Errorf("longer than %d characters", f.MaxLength)
	}
	if f.Required && s == "" {
		return fmt.Errorf("value is required")
	}
	if f.Pattern != "" {
		re, err := regexp.Compile(f.Pattern)
		if err != nil {
			return fmt.Errorf("invalid pattern: %w", err)
		}
		if !re.MatchString(s) {
			return fmt.Errorf("must match %s", f.Pattern)
		}
	}
	switch f.Type {
	case FieldURL:
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("must be an absolute URL")
		}
	case FieldEnum:
		for _, o := range f.Options {
			if o.Value == s {
				return nil
			}
		}
		return fmt.Errorf("must be one of the declared options")
	}
	return nil
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func toDuration(v any) (time.Duration, error) {
	s, ok := v.(string)
	if !ok {
		return 0, fmt.Errorf("must be a duration string like \"30s\"")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("must be a duration string like \"30s\"")
	}
	return d, nil
}

// ParseDuration parses a duration value as validated by ValidateValue.
func ParseDuration(v any) (time.Duration, error) { return toDuration(v) }

// AsInt64 converts a numeric value as validated by ValidateValue.
func AsInt64(v any) (int64, bool) {
	f, ok := toFloat(v)
	if !ok || f != math.Trunc(f) {
		return 0, false
	}
	return int64(f), true
}
