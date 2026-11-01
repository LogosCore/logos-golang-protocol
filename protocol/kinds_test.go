package protocol

import (
	"slices"
	"strings"
	"testing"
)

func TestBuildKinds(t *testing.T) {
	s := exampleBuildSchema(t)
	elf, _ := s.Target("linux-elf")
	if got := s.TargetKinds(elf, "http"); !slices.Equal(got, []string{KindReverseCall, KindReversePersistent}) {
		t.Fatalf("target kinds %v", got)
	}
	if got := UsableKinds(s.TargetKinds(elf, "http"), []string{KindReversePersistent}); !slices.Equal(got, []string{KindReversePersistent}) {
		t.Fatalf("usable %v", got)
	}
	// A target narrows them, to kinds the factory lists only.
	at := slices.IndexFunc(s.Targets, func(t BuildTarget) bool { return t.ID == "linux-elf" })
	s.Targets[at].Channels = []ChannelVersions{{ModuleName: "http", Versions: []int{2}, Kinds: []string{KindReversePersistent}}}
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	if got := s.TargetKinds(s.Targets[at], "http"); !slices.Equal(got, []string{KindReversePersistent}) {
		t.Fatalf("narrowed %v", got)
	}
	s.Targets[at].Channels[0].Kinds = []string{KindBindCall}
	if err := ValidateBuildSchema(s); err == nil || !strings.Contains(err.Error(), "not one the factory lists") {
		t.Fatalf("a kind the factory lacks: %v", err)
	}
	if err := validateChannelVersions(ChannelVersions{ModuleName: "x", Versions: []int{1}, Kinds: []string{"up"}}); err == nil {
		t.Fatal("an unknown kind passed")
	}
}
