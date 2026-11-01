package protocol

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
)

// This file defines the minion connection schema: the parameters a minion
// needs to reach a channel (for an HTTP channel: its base URL, TLS and
// check-in settings). A channel declares the schema at module.register under
// "connection"; operators fill in values for each place the channel is
// reachable at (a channel endpoint), and minions are built with those values.
//
// The schema describes what a minion is given, not how the channel runs: the
// channel's own settings are its management properties. Values are validated
// with the same FieldSpec rules as properties.

// ConnectionSchemaV1 is the connection schema format without kinds: its
// channel carries reverse-call connections only.
const ConnectionSchemaV1 = "1"

// ConnectionSchemaV2 is the format with kinds: the connection kinds the
// channel carries, each with fields of its own (docs:
// contracts/channel-core-connections/, The connection schema by kind).
const ConnectionSchemaV2 = "2"

// RegisterFieldConnection is the module.register key a channel declares its
// connection schema under.
const RegisterFieldConnection = "connection"

// MaxConnectionFields bounds a connection schema.
const MaxConnectionFields = 32

// ConnectionSchema is declared by a channel in module.register under
// "connection".
type ConnectionSchema struct {
	// SchemaVersion is the format of this structure (ConnectionSchemaV1).
	SchemaVersion string `json:"schema_version"`
	// Version is the version of the channel's parameter set, starting at 1.
	// A channel raises it when minions built against the previous set would
	// read the new one wrongly (a field removed, renamed or given a new
	// meaning). Adding an optional field does not need a new version.
	Version int         `json:"version"`
	Fields  []FieldSpec `json:"fields"`
	// Kinds are the connection kinds the channel carries (ConnectionSchemaV2
	// only), by kind (KindReverseCall, ...).
	Kinds map[string]ConnectionKind `json:"kinds,omitempty"`
}

// ConnectionKind is what one connection kind adds to the shared fields:
// Fields built into a minion, and, for a bind kind, Target, what operators
// fill in for each target.
type ConnectionKind struct {
	Fields []FieldSpec `json:"fields,omitempty"`
	Target []FieldSpec `json:"target,omitempty"`
}

// knownKinds are the connection kinds, in the order kinds are listed.
var knownKinds = []string{KindReverseCall, KindReversePersistent, KindBindCall, KindBindPersistent}

// KnownKind reports whether kind is a connection kind.
func KnownKind(kind string) bool { return slices.Contains(knownKinds, kind) }

// SupportedKinds are the kinds the channel carries: reverse-call alone for
// a schema without kinds.
func (s ConnectionSchema) SupportedKinds() []string {
	if len(s.Kinds) == 0 {
		return []string{KindReverseCall}
	}
	var out []string
	for _, k := range knownKinds {
		if _, ok := s.Kinds[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

// KindFields are the fields a connection of kind is built with: the shared
// ones, then the kind's own.
func (s ConnectionSchema) KindFields(kind string) []FieldSpec {
	k := s.Kinds[kind]
	out := make([]FieldSpec, 0, len(s.Fields)+len(k.Fields))
	return append(append(out, s.Fields...), k.Fields...)
}

// Field returns the field with key, if declared.
func (s ConnectionSchema) Field(key string) (FieldSpec, bool) {
	for _, f := range s.Fields {
		if f.Key == key {
			return f, true
		}
	}
	return FieldSpec{}, false
}

// ValidateConnectionSchema checks a schema's structure, limits, and that every
// declared default satisfies its own field spec.
func ValidateConnectionSchema(s ConnectionSchema) error {
	switch s.SchemaVersion {
	case ConnectionSchemaV1:
		if len(s.Kinds) > 0 {
			return fmt.Errorf("kinds need connection schema_version %q", ConnectionSchemaV2)
		}
	case ConnectionSchemaV2:
		if err := validateConnectionKinds(s); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported connection schema_version %q", s.SchemaVersion)
	}
	if s.Version < 1 {
		return fmt.Errorf("version must be at least 1")
	}
	if len(s.Fields) == 0 {
		return fmt.Errorf("at least one field is required")
	}
	if len(s.Fields) > MaxConnectionFields {
		return fmt.Errorf("too many fields (%d > %d)", len(s.Fields), MaxConnectionFields)
	}
	seen := map[string]bool{}
	for _, f := range s.Fields {
		if err := validateFieldSpec(f); err != nil {
			return fmt.Errorf("field %q: %w", f.Key, err)
		}
		if seen[f.Key] {
			return fmt.Errorf("duplicate field key %q", f.Key)
		}
		seen[f.Key] = true
	}
	return nil
}

// ValidateConnectionValues checks values against s: every key must be
// declared, every value valid, every required field set. It returns the
// problems by key (nil when there are none); an undeclared key is reported
// under its own name.
func ValidateConnectionValues(s ConnectionSchema, values map[string]any) map[string]string {
	return validateValues(s.Fields, values, "not a field of this channel's connection schema")
}

// validateConnectionKinds checks a schema's kinds: at least one, each a
// known kind; their fields and targets as any field, a kind's keys unique
// across the shared fields, its own and its target's; targets for bind
// kinds only.
func validateConnectionKinds(s ConnectionSchema) error {
	if len(s.Kinds) == 0 {
		return errors.New("kinds: at least one")
	}
	for _, kind := range slices.Sorted(maps.Keys(s.Kinds)) {
		if !KnownKind(kind) {
			return fmt.Errorf("kinds: %q is not a connection kind", kind)
		}
		k := s.Kinds[kind]
		if len(k.Target) > 0 && kind != KindBindCall && kind != KindBindPersistent {
			return fmt.Errorf("kinds.%s: only a bind kind has target fields", kind)
		}
		keys := map[string]bool{}
		for _, f := range s.Fields {
			keys[f.Key] = true
		}
		for _, f := range append(slices.Clone(k.Fields), k.Target...) {
			if err := validateFieldSpec(f); err != nil {
				return fmt.Errorf("kinds.%s: field %q: %w", kind, f.Key, err)
			}
			if keys[f.Key] {
				return fmt.Errorf("kinds.%s: duplicate field key %q", kind, f.Key)
			}
			keys[f.Key] = true
		}
	}
	return nil
}

// ResolveConnectionValues is what a minion is given: values over the schema's
// defaults, for declared fields only. Fields with neither are left out.
func ResolveConnectionValues(s ConnectionSchema, values map[string]any) map[string]any {
	return ResolveFieldValues(s.Fields, values)
}

// SortedProblemKeys returns the keys of a problems map in a stable order, for
// messages.
func SortedProblemKeys(problems map[string]string) []string {
	keys := make([]string, 0, len(problems))
	for k := range problems {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
