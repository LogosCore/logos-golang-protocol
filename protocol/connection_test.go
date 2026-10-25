package protocol

import (
	"strings"
	"testing"
)

func validConnection() ConnectionSchema {
	return ConnectionSchema{
		SchemaVersion: ConnectionSchemaV1,
		Version:       1,
		Fields: []FieldSpec{
			{Key: "base_url", Type: FieldURL, Required: true, Pattern: `^https?://[^/?#\s]+$`},
			{Key: "tls_verify", Type: FieldBool, Default: false},
			{Key: "request_timeout", Type: FieldDuration, Default: "40s", Min: "35s"},
			{Key: "headers", Type: FieldStringList},
		},
	}
}

func TestValidateConnectionSchema(t *testing.T) {
	if err := ValidateConnectionSchema(validConnection()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*ConnectionSchema){
		"schema_version": func(s *ConnectionSchema) { s.SchemaVersion = "2" },
		"version":        func(s *ConnectionSchema) { s.Version = 0 },
		"no fields":      func(s *ConnectionSchema) { s.Fields = nil },
		"duplicate":      func(s *ConnectionSchema) { s.Fields = append(s.Fields, s.Fields[0]) },
		"bad default":    func(s *ConnectionSchema) { s.Fields[2].Default = "10s" },
		"bad key":        func(s *ConnectionSchema) { s.Fields[0].Key = "Base-URL" },
	}
	for name, mutate := range cases {
		s := validConnection()
		s.Fields = append([]FieldSpec(nil), s.Fields...)
		mutate(&s)
		if err := ValidateConnectionSchema(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateConnectionValues(t *testing.T) {
	s := validConnection()
	if p := ValidateConnectionValues(s, map[string]any{"base_url": "https://edge.example.com:8443"}); p != nil {
		t.Fatalf("valid values: %v", p)
	}
	p := ValidateConnectionValues(s, map[string]any{
		"base_url":        "https://edge.example.com/api",
		"request_timeout": "5s",
		"color":           "red",
	})
	for _, key := range []string{"base_url", "request_timeout", "color"} {
		if p[key] == "" {
			t.Errorf("no problem for %s: %v", key, p)
		}
	}
	if p := ValidateConnectionValues(s, map[string]any{}); !strings.Contains(p["base_url"], "required") {
		t.Errorf("missing required: %v", p)
	}
}

func TestResolveConnectionValues(t *testing.T) {
	got := ResolveConnectionValues(validConnection(), map[string]any{
		"base_url":   "https://edge.example.com",
		"tls_verify": true,
		"unknown":    1,
	})
	want := map[string]any{"base_url": "https://edge.example.com", "tls_verify": true, "request_timeout": "40s"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}
