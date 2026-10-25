package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func validManifest() ManagementManifest {
	return ManagementManifest{
		SchemaVersion: ManagementSchemaV1,
		Properties: []PropertySpec{
			{FieldSpec: FieldSpec{Key: "max_body_bytes", Type: FieldBytes, Default: 1048576, Min: 17, Max: 67108864}, Apply: ApplyLive},
			{FieldSpec: FieldSpec{Key: "core_sync_timeout", Type: FieldDuration, Default: "30s", Min: "1s", Max: "120s"}, Apply: ApplyLive},
			{FieldSpec: FieldSpec{Key: "log_level", Type: FieldEnum, Default: "info", Options: []EnumOption{{Value: "info"}, {Value: "debug"}}}, Apply: ApplyLive},
			{FieldSpec: FieldSpec{Key: "sync_url", Type: FieldURL, Default: "http://core:8002"}, Apply: ApplyRestart},
		},
		Actions: []ActionSpec{
			{Name: "drain", Risk: RiskHigh, Confirm: "sure?"},
			{Name: "ping", Risk: RiskLow, Params: []FieldSpec{{Key: "count", Type: FieldInt, Min: 1, Max: 10}}},
		},
		Status: []StatusSpec{{Key: "requests_total", Type: FieldInt}},
	}
}

func TestValidateManifest_Valid(t *testing.T) {
	if err := ValidateManifest(validManifest()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateManifest_RoundTripJSON(t *testing.T) {
	raw, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	var m ManagementManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("decoded manifest invalid: %v", err)
	}
	if m.Properties[0].Key != "max_body_bytes" || m.Properties[0].Apply != ApplyLive {
		t.Fatalf("embedded FieldSpec not flattened: %s", raw)
	}
}

func TestValidateManifest_Invalid(t *testing.T) {
	cases := map[string]func(m *ManagementManifest){
		"schema":         func(m *ManagementManifest) { m.SchemaVersion = "2" },
		"bad key":        func(m *ManagementManifest) { m.Properties[0].Key = "Max-Body" },
		"dup key":        func(m *ManagementManifest) { m.Properties[1].Key = "max_body_bytes" },
		"bad type":       func(m *ManagementManifest) { m.Properties[0].Type = "blob" },
		"bad apply":      func(m *ManagementManifest) { m.Properties[0].Apply = "" },
		"enum no opts":   func(m *ManagementManifest) { m.Properties[2].Options = nil },
		"bad default":    func(m *ManagementManifest) { m.Properties[0].Default = 5 },
		"bad risk":       func(m *ManagementManifest) { m.Actions[0].Risk = "" },
		"dup action":     func(m *ManagementManifest) { m.Actions[1].Name = "drain" },
		"timeout":        func(m *ManagementManifest) { m.Actions[0].TimeoutSeconds = 61 },
		"secret status":  func(m *ManagementManifest) { m.Status[0].Type = FieldSecret },
		"bad duration":   func(m *ManagementManifest) { m.Properties[1].Min = "soon" },
		"long label":     func(m *ManagementManifest) { m.Properties[0].Label = strings.Repeat("x", 121) },
		"too many props": func(m *ManagementManifest) { m.Properties = make([]PropertySpec, 65) },
	}
	for name, mutate := range cases {
		m := validManifest()
		mutate(&m)
		if err := ValidateManifest(m); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestValidateValue(t *testing.T) {
	m := validManifest()
	bytesF, durF, enumF, urlF := m.Properties[0].FieldSpec, m.Properties[1].FieldSpec, m.Properties[2].FieldSpec, m.Properties[3].FieldSpec
	ok := []struct {
		f FieldSpec
		v any
	}{
		{bytesF, float64(2048)}, {bytesF, json.Number("17")}, {bytesF, nil},
		{durF, "5s"}, {enumF, "debug"}, {urlF, "https://core.example:8002"},
		{FieldSpec{Type: FieldBool}, true},
		{FieldSpec{Type: FieldStringList}, []any{"a", "b"}},
		{FieldSpec{Type: FieldNumber, Min: 0.5}, 0.75},
	}
	for i, c := range ok {
		if err := ValidateValue(c.f, c.v); err != nil {
			t.Errorf("ok case %d: %v", i, err)
		}
	}
	bad := []struct {
		f FieldSpec
		v any
	}{
		{bytesF, float64(16)}, {bytesF, 1.5}, {bytesF, "2048"}, {bytesF, float64(1 << 30)},
		{durF, "500ms"}, {durF, "3m"}, {durF, 30},
		{enumF, "trace"}, {urlF, "core:8002"},
		{FieldSpec{Type: FieldBool}, "true"},
		{FieldSpec{Type: FieldStringList}, []any{"a", 1}},
		{FieldSpec{Type: FieldString, Required: true}, nil},
		{FieldSpec{Type: FieldString, Pattern: "^a+$"}, "b"},
		{FieldSpec{Type: FieldString, MaxLength: 2}, "abc"},
	}
	for i, c := range bad {
		if err := ValidateValue(c.f, c.v); err == nil {
			t.Errorf("bad case %d (%v): expected error", i, c.v)
		}
	}
}

func TestEnumOptionDescription(t *testing.T) {
	enum := func(desc string) ManagementManifest {
		return ManagementManifest{SchemaVersion: ManagementSchemaV1, Properties: []PropertySpec{{
			FieldSpec: FieldSpec{Key: "level", Type: FieldEnum, Label: "Level",
				Options: []EnumOption{{Value: "warn", Label: "Warn", Description: desc}}},
			Apply: ApplyLive,
		}}}
	}
	if err := ValidateManifest(enum("Core problems only.")); err != nil {
		t.Fatalf("valid description: %v", err)
	}
	if err := ValidateManifest(enum(strings.Repeat("x", MaxDescriptionLength+1))); err == nil {
		t.Fatal("over-long option description accepted")
	}
}

func TestAsInt64(t *testing.T) {
	for _, c := range []struct {
		in   any
		want int64
		ok   bool
	}{
		{json.Number("9007199254740993"), 9007199254740993, true}, // beyond 2^53: exact
		{float64(42), 42, true},
		{int64(-7), -7, true},
		{1.5, 0, false},
		{1e19, 0, false}, // out of int64 range: refused, not wrapped
		{json.Number("1e19"), 0, false},
		{"5", 0, false},
	} {
		got, ok := AsInt64(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("AsInt64(%v) = %d, %v; want %d, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestValidateValueIntRange(t *testing.T) {
	f := FieldSpec{Key: "n", Type: FieldInt, Label: "N"}
	if err := ValidateValue(f, 1e19); err == nil {
		t.Error("1e19 accepted for an int without max")
	}
	if err := ValidateValue(f, json.Number("9007199254740993")); err != nil {
		t.Errorf("large exact int refused: %v", err)
	}
}

func TestStatusAlert(t *testing.T) {
	m := func(s StatusSpec) ManagementManifest {
		return ManagementManifest{SchemaVersion: ManagementSchemaV1, Status: []StatusSpec{s}}
	}
	for _, ok := range []StatusSpec{
		{Key: "draining", Type: FieldBool, Alert: true},
		{Key: "mode", Type: FieldEnum, Alert: "degraded"},
		{Key: "phase", Type: FieldString, Alert: "stuck"},
		{Key: "plain", Type: FieldBool},
	} {
		if err := ValidateManifest(m(ok)); err != nil {
			t.Errorf("%s: %v", ok.Key, err)
		}
	}
	for _, bad := range []StatusSpec{
		{Key: "draining", Type: FieldBool, Alert: "yes"},
		{Key: "count", Type: FieldInt, Alert: 0},
		{Key: "mode", Type: FieldEnum, Alert: 1},
	} {
		if err := ValidateManifest(m(bad)); err == nil {
			t.Errorf("%s: alert %v accepted", bad.Key, bad.Alert)
		}
	}
}
