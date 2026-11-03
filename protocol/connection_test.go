package protocol

import (
	"slices"
	"strings"
	"testing"
)

func validConnection() ConnectionSchema {
	shared := []FieldSpec{
		{Key: "base_url", Type: FieldURL, Required: true, Pattern: `^https?://[^/?#\s]+$`},
		{Key: "tls_verify", Type: FieldBool, Default: false},
		{Key: "request_timeout", Type: FieldDuration, Default: "40s", Min: "35s"},
		{Key: "headers", Type: FieldStringList},
	}
	return ConnectionSchema{
		SchemaVersion: ConnectionSchemaV2,
		Version:       1,
		Kinds: map[string]ConnectionKind{
			KindReverseCall:       {Fields: shared},
			KindReversePersistent: {Fields: append(slices.Clone(shared), FieldSpec{Key: "ws_backoff", Type: FieldDuration, Default: "60s"})},
			KindBindCall:          {Fields: []FieldSpec{{Key: "method", Type: FieldString}}, Target: []FieldSpec{{Key: "url", Type: FieldURL}}},
		},
	}
}

func TestValidateConnectionSchema(t *testing.T) {
	s := validConnection()
	if err := ValidateConnectionSchema(s); err != nil {
		t.Fatal(err)
	}
	if got := s.SupportedKinds(); !slices.Equal(got, []string{KindReverseCall, KindReversePersistent, KindBindCall}) {
		t.Fatalf("kinds %v", got)
	}
	if got := s.KindFields(KindReversePersistent); len(got) != 5 || got[4].Key != "ws_backoff" {
		t.Fatalf("fields %v", got)
	}
	if s.MessageLimit(KindReverseCall) != MaxMinionMessageSize {
		t.Fatal("no max_message: the protocol's limit")
	}
	small := validConnection()
	k := small.Kinds[KindReverseCall]
	k.MaxMessage = 4096
	small.Kinds[KindReverseCall] = k
	if err := ValidateConnectionSchema(small); err != nil || small.MessageLimit(KindReverseCall) != 4096 {
		t.Fatalf("a kind that carries little: %v %d", err, small.MessageLimit(KindReverseCall))
	}
	cases := map[string]func(*ConnectionSchema){
		"unsupported connection schema_version": func(s *ConnectionSchema) { s.SchemaVersion = "1" },
		"version must be":                       func(s *ConnectionSchema) { s.Version = 0 },
		"at least one":                          func(s *ConnectionSchema) { s.Kinds = nil },
		"not a connection kind": func(s *ConnectionSchema) {
			s.Kinds["sideways"] = ConnectionKind{Fields: s.Kinds[KindReverseCall].Fields}
		},
		"only a bind kind": func(s *ConnectionSchema) {
			k := s.Kinds[KindReverseCall]
			k.Target = k.Fields[:1]
			s.Kinds[KindReverseCall] = k
		},
		"at least one field":  func(s *ConnectionSchema) { s.Kinds[KindReverseCall] = ConnectionKind{} },
		"duplicate field key": func(s *ConnectionSchema) { k := s.Kinds[KindBindCall]; k.Target = k.Fields; s.Kinds[KindBindCall] = k },
		"default": func(s *ConnectionSchema) {
			k := s.Kinds[KindReverseCall]
			k.Fields = slices.Clone(k.Fields)
			k.Fields[2].Default = "10s"
			s.Kinds[KindReverseCall] = k
		},
		"max_message must be": func(s *ConnectionSchema) {
			k := s.Kinds[KindReverseCall]
			k.MaxMessage = 512
			s.Kinds[KindReverseCall] = k
		},
		"key must match": func(s *ConnectionSchema) {
			k := s.Kinds[KindReverseCall]
			k.Fields = slices.Clone(k.Fields)
			k.Fields[0].Key = "Base-URL"
			s.Kinds[KindReverseCall] = k
		},
	}
	for want, mutate := range cases {
		s := validConnection()
		mutate(&s)
		if err := ValidateConnectionSchema(s); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestValidateConnectionValues(t *testing.T) {
	s := validConnection()
	if p := ValidateConnectionValues(s, KindReverseCall, map[string]any{"base_url": "https://edge.example.com:8443"}); p != nil {
		t.Fatalf("valid values: %v", p)
	}
	p := ValidateConnectionValues(s, KindReverseCall, map[string]any{
		"base_url":        "https://edge.example.com/api",
		"request_timeout": "5s",
		"ws_backoff":      "1m",
	})
	for _, key := range []string{"base_url", "request_timeout", "ws_backoff"} {
		if p[key] == "" {
			t.Errorf("no problem for %s: %v", key, p)
		}
	}
	// ws_backoff is reverse-persistent's own.
	if p := ValidateConnectionValues(s, KindReversePersistent, map[string]any{"base_url": "https://a.example.com", "ws_backoff": "1m"}); p != nil {
		t.Errorf("reverse-persistent: %v", p)
	}
	if p := ValidateConnectionValues(s, KindReverseCall, map[string]any{}); !strings.Contains(p["base_url"], "required") {
		t.Errorf("missing required: %v", p)
	}
	if p := ValidateConnectionValues(s, KindBindPersistent, nil); p[""] == "" {
		t.Errorf("a kind the channel lacks: %v", p)
	}
}

func TestResolveConnectionValues(t *testing.T) {
	got := ResolveConnectionValues(validConnection(), KindReverseCall, map[string]any{
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
	if got := ResolveConnectionValues(validConnection(), KindReversePersistent, nil); got["ws_backoff"] != "60s" {
		t.Errorf("reverse-persistent's default: %v", got)
	}
}
