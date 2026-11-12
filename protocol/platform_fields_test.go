package protocol

import (
	"reflect"
	"strings"
	"testing"
)

func TestFieldOnPlatform(t *testing.T) {
	cases := []struct {
		platforms []string
		platform  string
		want      bool
	}{
		{nil, "linux/arm", true},
		{[]string{"linux/arm"}, "linux/arm", true},
		{[]string{"linux/arm"}, "linux/arm64", false},
		{[]string{"linux/arm"}, "windows/arm", false},
		{[]string{"any/arm"}, "windows/arm", true},
		{[]string{"any/arm"}, "linux/amd64", false},
		{[]string{"windows/any"}, "windows/386", true},
		{[]string{"any/any"}, "linux/amd64", true},
		{[]string{"linux/amd64", "linux/arm"}, "linux/arm", true},
		// A build's own "any" is a platform like the others: only "any"
		// in the field's matches it.
		{[]string{"linux/arm"}, "linux/any", false},
		{[]string{"linux/arm"}, "", false},
	}
	for _, c := range cases {
		f := FieldSpec{Key: "goarm", Platforms: c.platforms}
		if got := f.OnPlatform(c.platform); got != c.want {
			t.Errorf("%v on %q = %v, want %v", c.platforms, c.platform, got, c.want)
		}
	}
}

// The docs' example: linux-elf's goarm is for linux/arm alone.
func TestPlatformFields(t *testing.T) {
	s := exampleBuildSchema(t)
	elf := target(t, s, "linux-elf")
	keys := func(fields []FieldSpec) []string {
		out := []string{}
		for _, f := range fields {
			out = append(out, f.Key)
		}
		return out
	}
	if got := keys(s.PlatformFields(elf, "linux/arm")); !reflect.DeepEqual(got, []string{"kill_date", "guardrails", "debug", "goarm"}) {
		t.Fatalf("linux/arm fields = %v", got)
	}
	if got := keys(s.PlatformFields(elf, "linux/amd64")); !reflect.DeepEqual(got, []string{"kill_date", "guardrails", "debug"}) {
		t.Fatalf("linux/amd64 fields = %v", got)
	}
	if got := len(s.TargetFields(elf)); got != 4 {
		t.Fatalf("target fields = %d, want all 4", got)
	}
}

func TestFieldPlatformsSchema(t *testing.T) {
	goarm := func(platforms ...string) FieldSpec {
		return FieldSpec{Key: "goarm", Num: 9, Type: FieldEnum, Default: "7", Options: []EnumOption{{Value: "7"}, {Value: "6"}}, Platforms: platforms}
	}
	withTarget := func(f FieldSpec) BuildSchema {
		s := exampleBuildSchema(t)
		for i := range s.Targets {
			if s.Targets[i].ID == "linux-elf" {
				s.Targets[i].Fields = []FieldSpec{f}
			}
		}
		return s
	}
	shared := func(f FieldSpec) BuildSchema {
		s := withTarget(FieldSpec{Key: "strip", Num: 8, Type: FieldBool})
		s.Fields = append(s.Fields, f)
		return s
	}
	for _, s := range []BuildSchema{
		withTarget(goarm("linux/arm")),
		withTarget(goarm("any/arm")),
		withTarget(goarm("linux/arm", "linux/arm64")),
		// A shared field's platforms are any target's.
		shared(goarm("linux/arm")),
		shared(goarm("windows/any")),
	} {
		if err := ValidateBuildSchema(s); err != nil {
			t.Errorf("refused: %v", err)
		}
	}

	bad := map[string]BuildSchema{
		"must be os/arch":                withTarget(goarm("arm")),
		"duplicate platform":             withTarget(goarm("linux/arm", "linux/arm")),
		"matches none its builds can be": withTarget(goarm("windows/arm64")), // linux-elf builds none
		"matches none its builds":        shared(goarm("darwin/arm64")),
		"too many platforms": withTarget(goarm("linux/arm", "any/arm", "linux/any", "any/any", "linux/1", "linux/2", "linux/3",
			"linux/4", "linux/5", "linux/6", "linux/7", "linux/8", "linux/9", "linux/10", "linux/11", "linux/12", "linux/13")),
	}
	// Only a build's fields have platforms: a connection kind's, a
	// command's params and a module's properties are refused them.
	kind := exampleBuildSchema(t)
	kind.Channels[0].Kinds[0].Fields[0].Platforms = []string{"linux/arm"}
	bad["only for a build's fields"] = kind
	for want, s := range bad {
		if err := ValidateBuildSchema(s); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	cmd := exampleBuildSchema(t)
	cmd.Commands[0].Params[0].Platforms = []string{"linux/arm"}
	if err := ValidateBuildSchema(cmd); err == nil || !strings.Contains(err.Error(), "only for a build's fields") {
		t.Errorf("a command param with platforms: %v", err)
	}
	if err := validateFieldSpec(FieldSpec{Key: "level", Type: FieldString, Platforms: []string{"linux/arm"}}); err == nil {
		t.Error("a module's field with platforms was taken")
	}
	if err := validateConnectionFieldSpec(FieldSpec{Key: "host", Type: FieldString, Platforms: []string{"linux/arm"}}); err == nil {
		t.Error("a connection field with platforms was taken")
	}
}

// A value is for a field of the build's platform: one for another is
// refused ("only for ..."), and the field's default goes in no minion config
// of another platform.
func TestRequestPlatformFields(t *testing.T) {
	s := exampleBuildSchema(t)
	s.MinionConfig = true
	req := func(platform string, values map[string]any) BuildRequest {
		r := exampleBuildRequest(t)
		r.Target, r.Platform, r.Values, r.Commands = "linux-elf", platform, values, nil
		return r
	}

	if p := ValidateBuildRequest(s, req("linux/arm", map[string]any{"goarm": "6"})); p["values.goarm"] != "" {
		t.Fatalf("goarm on linux/arm refused: %v", p)
	}
	p := ValidateBuildRequest(s, req("linux/amd64", map[string]any{"goarm": "6"}))
	if p["values.goarm"] != "only for linux/arm" {
		t.Fatalf("goarm on linux/amd64: %v", p)
	}
	if p := ValidateBuildRequest(s, req("linux/arm", map[string]any{"goarm": "8"})); p["values.goarm"] == "" {
		t.Fatal("goarm 8 taken")
	}

	elf := target(t, s, "linux-elf")
	if v := ResolveFieldValues(s.PlatformFields(elf, "linux/arm"), nil); v["goarm"] != "7" {
		t.Fatalf("linux/arm's default goarm = %v", v["goarm"])
	}
	if v := ResolveFieldValues(s.PlatformFields(elf, "linux/amd64"), nil); v["goarm"] != nil {
		t.Fatalf("linux/amd64 has goarm %v", v["goarm"])
	}
}
