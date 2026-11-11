package protocol

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func validConnection() ConnectionSchema {
	shared := []FieldSpec{
		{Key: "base_url", Num: 1, Type: FieldURL, Required: true, Pattern: `^https?://[^/?#\s]+$`},
		{Key: "tls_verify", Num: 2, Type: FieldBool, Default: false},
		{Key: "request_timeout", Num: 3, Type: FieldDuration, Default: "40s", Min: "35s"},
		{Key: "headers", Num: 4, Type: FieldStringList},
	}
	return ConnectionSchema{
		SchemaVersion: ConnectionSchemaV2,
		Version:       1,
		Kinds: map[string]ConnectionKind{
			KindReverseCall: {Fields: shared},
			KindReversePersistent: {Fields: append(slices.Clone(shared),
				FieldSpec{Key: "ws_backoff", Num: 5, Type: FieldDuration, Default: "60s"})},
			KindBindCall: {Fields: []FieldSpec{{Key: "method", Num: 6, Type: FieldString}},
				Target: []FieldSpec{{Key: "url", Num: 7, Type: FieldURL}}},
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
	agentless := validConnection()
	b := agentless.Kinds[KindBindCall]
	b.Agentless = true
	agentless.Kinds[KindBindCall] = b
	if err := ValidateConnectionSchema(agentless); err != nil || !agentless.IsAgentless(KindBindCall) ||
		agentless.IsAgentless(KindReverseCall) || agentless.IsAgentless(KindBindPersistent) {
		t.Fatalf("an agentless bind kind: %v", err)
	}
	slow := validConnection()
	sk := slow.Kinds[KindBindCall]
	sk.MaxCall = "10m"
	slow.Kinds[KindBindCall] = sk
	if err := ValidateConnectionSchema(slow); err != nil || slow.CallLimit(KindBindCall) != 10*time.Minute ||
		validConnection().CallLimit(KindBindCall) != 0 || slow.CallLimit(KindReverseCall) != 0 {
		t.Fatalf("a bind-call kind's call limit: %v %s", err, slow.CallLimit(KindBindCall))
	}
	listening := validConnection()
	listening.Kinds[KindBindPersistent] = ConnectionKind{Fields: []FieldSpec{{Key: "listen_port", Num: 9, Type: FieldInt}}, MaxOpen: "2m"}
	if err := ValidateConnectionSchema(listening); err != nil || listening.OpenLimit(KindBindPersistent) != 2*time.Minute ||
		validConnection().OpenLimit(KindBindPersistent) != 0 || listening.OpenLimit(KindBindCall) != 0 {
		t.Fatalf("a bind-persistent kind's open limit: %v %s", err, listening.OpenLimit(KindBindPersistent))
	}
	cases := map[string]func(*ConnectionSchema){
		"unsupported connection schema_version": func(s *ConnectionSchema) { s.SchemaVersion = "1" },
		"only a bind-persistent kind says max_open": func(s *ConnectionSchema) {
			k := s.Kinds[KindBindCall]
			k.MaxOpen = "1m"
			s.Kinds[KindBindCall] = k
		},
		"max_open must be a duration": func(s *ConnectionSchema) {
			s.Kinds[KindBindPersistent] = ConnectionKind{Fields: []FieldSpec{{Key: "listen_port", Num: 9, Type: FieldInt}}, MaxOpen: "soon"}
		},
		"only a bind-call kind says max_call": func(s *ConnectionSchema) {
			k := s.Kinds[KindReverseCall]
			k.MaxCall = "1m"
			s.Kinds[KindReverseCall] = k
		},
		"max_call must be a duration": func(s *ConnectionSchema) {
			k := s.Kinds[KindBindCall]
			k.MaxCall = "2h"
			s.Kinds[KindBindCall] = k
		},
		"only a bind kind is agentless": func(s *ConnectionSchema) {
			k := s.Kinds[KindReverseCall]
			k.Agentless = true
			s.Kinds[KindReverseCall] = k
		},
		"version must be": func(s *ConnectionSchema) { s.Version = 0 },
		"at least one":    func(s *ConnectionSchema) { s.Kinds = nil },
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

// Every field of a connection schema has a number, its target's too, one
// numbering for the whole schema: a key keeps its number in every kind, and a
// kind's fields and its target's never share one.
func TestConnectionSchemaNumbers(t *testing.T) {
	s := validConnection()
	if err := ValidateConnectionSchema(s); err != nil {
		t.Fatal(err)
	}
	for _, kind := range s.SupportedKinds() {
		if !s.Numbered(kind) {
			t.Errorf("%s: numbered", kind)
		}
	}
	stale := validConnection() // stored before numbers were required
	k := stale.Kinds[KindReverseCall]
	k.Fields = []FieldSpec{{Key: "base_url", Type: FieldURL}}
	stale.Kinds[KindReverseCall] = k
	if stale.Numbered(KindReverseCall) || s.Numbered(KindBindPersistent) {
		t.Error("a kind without numbers, or one the channel does not carry, is not numbered")
	}
	cases := map[string]func(*ConnectionSchema){
		`kinds.reverse-call: field "tls_verify": a num is required`: func(s *ConnectionSchema) { s.Kinds[KindReverseCall].Fields[1].Num = 0 },
		`kinds.bind-call: field "url": a num is required`:           func(s *ConnectionSchema) { s.Kinds[KindBindCall].Target[0].Num = 0 },
		`field "base_url": num 8 here, 1 elsewhere`:                 func(s *ConnectionSchema) { s.Kinds[KindReversePersistent].Fields[0].Num = 8 },
		`field "ws_backoff": num 1 is "base_url"'s`:                 func(s *ConnectionSchema) { s.Kinds[KindReversePersistent].Fields[4].Num = 1 },
		`field "url": num 6 is "method"'s`:                          func(s *ConnectionSchema) { s.Kinds[KindBindCall].Target[0].Num = 6 },
		"num must be 1 to 65535":                                    func(s *ConnectionSchema) { s.Kinds[KindBindCall].Fields[0].Num = MaxFieldNumber + 1 },
	}
	for want, mutate := range cases {
		s := validConnection()
		mutate(&s)
		if err := ValidateConnectionSchema(s); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	// A module's own fields have no numbers.
	if err := validateFieldSpec(FieldSpec{Key: "log_level", Type: FieldString, Num: 1}); err == nil ||
		!strings.Contains(err.Error(), "a module's own fields have none") {
		t.Errorf("a property with a num: %v", err)
	}
}
