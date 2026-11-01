package protocol

import (
	"slices"
	"strings"
	"testing"
)

func TestConnectionSchemaKinds(t *testing.T) {
	base := []FieldSpec{{Key: "base_url", Type: FieldURL, Required: true}}
	ok := ConnectionSchema{SchemaVersion: ConnectionSchemaV2, Version: 1, Fields: base, Kinds: map[string]ConnectionKind{
		KindReversePersistent: {Fields: []FieldSpec{{Key: "ws_backoff", Type: FieldDuration}}},
		KindReverseCall:       {},
		KindBindCall:          {Target: []FieldSpec{{Key: "url", Type: FieldURL}}},
	}}
	if err := ValidateConnectionSchema(ok); err != nil {
		t.Fatal(err)
	}
	if got := ok.SupportedKinds(); !slices.Equal(got, []string{KindReverseCall, KindReversePersistent, KindBindCall}) {
		t.Fatalf("kinds %v", got)
	}
	if got := ok.KindFields(KindReversePersistent); len(got) != 2 || got[1].Key != "ws_backoff" {
		t.Fatalf("fields %v", got)
	}
	v1 := ConnectionSchema{SchemaVersion: ConnectionSchemaV1, Version: 1, Fields: base}
	if got := v1.SupportedKinds(); !slices.Equal(got, []string{KindReverseCall}) {
		t.Fatalf("v1 kinds %v", got)
	}
	for want, s := range map[string]ConnectionSchema{
		"kinds need":            {SchemaVersion: ConnectionSchemaV1, Version: 1, Fields: base, Kinds: ok.Kinds},
		"at least one":          {SchemaVersion: ConnectionSchemaV2, Version: 1, Fields: base},
		"not a connection kind": {SchemaVersion: ConnectionSchemaV2, Version: 1, Fields: base, Kinds: map[string]ConnectionKind{"sideways": {}}},
		"only a bind kind":      {SchemaVersion: ConnectionSchemaV2, Version: 1, Fields: base, Kinds: map[string]ConnectionKind{KindReverseCall: {Target: base}}},
		"duplicate field key":   {SchemaVersion: ConnectionSchemaV2, Version: 1, Fields: base, Kinds: map[string]ConnectionKind{KindReverseCall: {Fields: base}}},
	} {
		if err := ValidateConnectionSchema(s); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestBuildKinds(t *testing.T) {
	s := exampleBuildSchema(t)
	http, _ := s.Channel("http")
	if !slices.Equal(http.KindList(), []string{KindReverseCall}) {
		t.Fatalf("no kinds: %v", http.KindList())
	}
	for i := range s.Channels {
		if s.Channels[i].ModuleName == "http" {
			s.Channels[i].Kinds = []string{KindReversePersistent, KindReverseCall}
		}
	}
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	elf, _ := s.Target("linux-elf")
	if got := s.TargetKinds(elf, "http"); !slices.Equal(got, []string{KindReversePersistent, KindReverseCall}) {
		t.Fatalf("target kinds %v", got)
	}
	if got := UsableKinds(s.TargetKinds(elf, "http"), []string{KindReverseCall}); !slices.Equal(got, []string{KindReverseCall}) {
		t.Fatalf("usable %v", got)
	}
	// A target narrows them, to kinds the factory lists only.
	for i := range s.Targets {
		if s.Targets[i].ID == "linux-elf" {
			s.Targets[i].Channels = []ChannelVersions{{ModuleName: "http", Versions: []int{2}, Kinds: []string{KindReverseCall}}}
		}
	}
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	elf, _ = s.Target("linux-elf")
	if got := s.TargetKinds(elf, "http"); !slices.Equal(got, []string{KindReverseCall}) {
		t.Fatalf("narrowed %v", got)
	}
	s.Targets[len(s.Targets)-1].Channels = nil
	for i := range s.Targets {
		if s.Targets[i].ID == "linux-elf" {
			s.Targets[i].Channels = []ChannelVersions{{ModuleName: "http", Versions: []int{2}, Kinds: []string{KindBindCall}}}
		}
	}
	if err := ValidateBuildSchema(s); err == nil || !strings.Contains(err.Error(), "not one the factory lists") {
		t.Fatalf("a kind the factory lacks: %v", err)
	}
	if err := validateChannelVersions(ChannelVersions{ModuleName: "x", Versions: []int{1}, Kinds: []string{"up"}}); err == nil {
		t.Fatal("an unknown kind passed")
	}
}
