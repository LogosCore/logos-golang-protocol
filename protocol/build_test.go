package protocol

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// docBuildSchema is the example of the Minion Build contract page
// (logos-docs, contracts/minion-build), verbatim.
const docBuildSchema = `{
  "schema_version": "1",
  "version": 1,
  "channels": [
    {
      "module_name": "http", "versions": [2],
      "fields": [
        {
          "key": "method", "type": "enum", "label": "Method", "default": "POST",
          "options": [{ "value": "GET" }, { "value": "POST" }, { "value": "PUT" }]
        },
        {
          "key": "path_prefix", "type": "string", "label": "Path prefix", "default": "/",
          "description": "Every request path starts with it, e.g. /cdn/assets/ when the front forwards only that path.",
          "pattern": "^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$", "max_length": 256
        }
      ]
    },
    { "module_name": "dns", "versions": [1] }
  ],
  "crypto": "aes-256-cbc-hmac-sha256",
  "fields": [
    { "key": "kill_date", "type": "datetime", "label": "Kill date", "group": "Limits", "order": 1 },
    {
      "key": "guardrails", "type": "enum_list", "label": "Run only if", "group": "Limits", "order": 2,
      "options": [
        { "value": "domain_joined", "label": "Domain-joined" },
        { "value": "no_debugger", "label": "No debugger attached" }
      ]
    },
    { "key": "debug", "type": "bool", "label": "Debug build", "default": false, "group": "Build", "order": 3 }
  ],
  "targets": [
    {
      "id": "windows-exe", "label": "Windows executable", "format": "exe",
      "platforms": ["windows/amd64", "windows/386", "windows/arm64"],
      "fields": [
        { "key": "icon", "type": "file", "label": "Icon", "accept": [".ico"], "max_size": 262144, "group": "Appearance", "order": 4 }
      ]
    },
    {
      "id": "windows-service", "label": "Windows service", "format": "exe",
      "platforms": ["windows/amd64"],
      "fields": [
        {
          "key": "service_name", "type": "string", "label": "Service name", "required": true,
          "pattern": "^[A-Za-z0-9_-]{1,64}$", "group": "Service", "order": 4
        }
      ]
    },
    { "id": "linux-elf", "label": "Linux binary", "format": "elf", "platforms": ["linux/amd64", "linux/arm64"] },
    {
      "id": "shellcode", "label": "Shellcode", "format": "bin",
      "platforms": ["windows/amd64", "linux/amd64"],
      "channels": [{ "module_name": "http", "versions": [2] }]
    }
  ],
  "commands": [
    {
      "id": "sleep", "label": "Sleep", "required": true,
      "description": "Changes how long the minion waits between check-ins.",
      "params": [
        { "key": "interval", "type": "duration", "label": "Interval", "required": true },
        { "key": "jitter", "type": "int", "label": "Jitter", "unit": "%", "min": 0, "max": 100, "default": 0 }
      ]
    },
    { "id": "exit", "label": "Exit", "required": true },
    {
      "id": "shell", "label": "Run a command", "default": true,
      "params": [{ "key": "command", "type": "string", "label": "Command", "required": true }]
    },
    {
      "id": "download", "label": "Download a file", "default": true,
      "params": [{ "key": "path", "type": "string", "label": "Path", "required": true }]
    },
    { "id": "screenshot", "label": "Screenshot", "targets": ["windows-exe"] }
  ]
}`

// exampleBuildSchema decodes docBuildSchema afresh, so callers may mutate it.
func exampleBuildSchema(t *testing.T) BuildSchema {
	t.Helper()
	var s BuildSchema
	if err := json.Unmarshal([]byte(docBuildSchema), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func target(t *testing.T, s BuildSchema, id string) BuildTarget {
	t.Helper()
	tg, ok := s.Target(id)
	if !ok {
		t.Fatalf("no target %q", id)
	}
	return tg
}

func TestBuildSchemaDocExample(t *testing.T) {
	s := exampleBuildSchema(t)
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	if http, ok := s.Channel("http"); !ok || len(http.Fields) != 2 || !reflect.DeepEqual(http.Versions, []int{2}) {
		t.Fatalf("http channel not decoded (embedded ChannelVersions): %+v", http)
	}

	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var again BuildSchema
	if err := json.Unmarshal(raw, &again); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBuildSchema(again); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !reflect.DeepEqual(again, s) {
		t.Fatalf("round trip changed the schema:\n%s", raw)
	}
}

func TestBuildSchemaTargets(t *testing.T) {
	s := exampleBuildSchema(t)

	var keys []string
	for _, f := range s.TargetFields(target(t, s, "windows-service")) {
		keys = append(keys, f.Key)
	}
	if want := []string{"kill_date", "guardrails", "debug", "service_name"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("TargetFields = %v, want %v (shared first)", keys, want)
	}

	elf, shellcode := target(t, s, "linux-elf"), target(t, s, "shellcode")
	if got := s.TargetChannels(elf); len(got) != 2 {
		t.Errorf("linux-elf channels = %v, want the factory's two", got)
	}
	for _, c := range []struct {
		t       BuildTarget
		channel string
		version int
		want    bool
	}{
		{elf, "http", 2, true},
		{elf, "dns", 1, true},
		{elf, "http", 3, false}, // a version the factory does not list
		{elf, "smtp", 1, false},
		{shellcode, "http", 2, true},
		{shellcode, "dns", 1, false}, // narrowed away
	} {
		if got := s.Supports(c.t, c.channel, c.version); got != c.want {
			t.Errorf("Supports(%s, %s, %d) = %v, want %v", c.t.ID, c.channel, c.version, got, c.want)
		}
	}
	if !elf.HasPlatform("linux/arm64") || elf.HasPlatform("windows/amd64") {
		t.Error("HasPlatform")
	}
	if _, ok := s.Target("macos-app"); ok {
		t.Error("unknown target found")
	}
}

func TestBuildSchemaCommands(t *testing.T) {
	s := exampleBuildSchema(t)
	ids := func(cs []BuildCommand) []string {
		var out []string
		for _, c := range cs {
			out = append(out, c.ID)
		}
		return out
	}
	exe, elf := target(t, s, "windows-exe"), target(t, s, "linux-elf")
	if got, want := ids(s.TargetCommands(exe)), []string{"sleep", "exit", "shell", "download", "screenshot"}; !reflect.DeepEqual(got, want) {
		t.Errorf("windows-exe commands = %v, want %v", got, want)
	}
	if got, want := ids(s.TargetCommands(elf)), []string{"sleep", "exit", "shell", "download"}; !reflect.DeepEqual(got, want) {
		t.Errorf("linux-elf commands = %v, want %v (no screenshot)", got, want)
	}
	// Required and default ones, in the schema's order; screenshot is neither.
	if got, want := s.DefaultCommands(exe), []string{"sleep", "exit", "shell", "download"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DefaultCommands = %v, want %v", got, want)
	}
	if c, ok := s.Command("sleep"); !ok || len(c.Params) != 2 || !c.Required {
		t.Errorf("Command(sleep) = %+v, %v", c, ok)
	}
	if _, ok := s.Command("keylog"); ok {
		t.Error("unknown command found")
	}
	if got := (BuildSchema{}).DefaultCommands(exe); got == nil || len(got) != 0 {
		t.Errorf("no commands: DefaultCommands = %#v, want an empty list", got)
	}
}

func TestValidateBuildSchema_Invalid(t *testing.T) {
	// Each case names the error it must cause, so none passes for another
	// reason.
	cases := []struct {
		want   string
		mutate func(s *BuildSchema)
	}{
		{`unsupported build schema_version "2"`, func(s *BuildSchema) { s.SchemaVersion = "2" }},
		{"version must be at least 1", func(s *BuildSchema) { s.Version = 0 }},
		{"at least one channel", func(s *BuildSchema) { s.Channels = nil }},
		{`duplicate channel "dns"`, func(s *BuildSchema) { s.Channels = append(s.Channels, s.Channels[1]) }},
		{"needs 1..16 versions", func(s *BuildSchema) { s.Channels[1].Versions = nil }},
		{"versions start at 1", func(s *BuildSchema) { s.Channels[1].Versions = []int{0} }},
		{"duplicate version 1", func(s *BuildSchema) { s.Channels[1].Versions = []int{1, 1} }},
		{"module_name must be", func(s *BuildSchema) { s.Channels[1].ModuleName = "my dns" }},
		{`channel "http": field "method": default`, func(s *BuildSchema) { s.Channels[0].Fields[0].Default = "PATCH" }},
		{`channel "http": duplicate field key "method"`, func(s *BuildSchema) {
			s.Channels[0].Fields = append(s.Channels[0].Fields, s.Channels[0].Fields[0])
		}},
		{`crypto suite "X25519!"`, func(s *BuildSchema) { s.Crypto = "X25519!" }},
		{`field "kill_date": invalid type "blob"`, func(s *BuildSchema) { s.Fields[0].Type = "blob" }},
		{"at least one target", func(s *BuildSchema) { s.Targets = nil }},
		{"too many targets", func(s *BuildSchema) { s.Targets = make([]BuildTarget, MaxBuildTargets+1) }},
		{`duplicate target "linux-elf"`, func(s *BuildSchema) { s.Targets = append(s.Targets, s.Targets[2]) }},
		{"id must match", func(s *BuildSchema) { s.Targets[0].ID = "Windows EXE" }},
		{"format must match", func(s *BuildSchema) { s.Targets[0].Format = "EXE" }},
		{"needs 1..16 platforms", func(s *BuildSchema) { s.Targets[0].Platforms = nil }},
		{`platform "windows" must be os/arch`, func(s *BuildSchema) { s.Targets[0].Platforms = []string{"windows"} }},
		{`duplicate platform "windows/amd64"`, func(s *BuildSchema) {
			s.Targets[0].Platforms = []string{"windows/amd64", "windows/amd64"}
		}},
		{`target "windows-exe": duplicate field key "debug"`, func(s *BuildSchema) { s.Targets[0].Fields[0].Key = "debug" }},
		{"a file field has no default", func(s *BuildSchema) { s.Targets[0].Fields[0].Default = "f-1" }},
		{"label longer than", func(s *BuildSchema) { s.Targets[0].Label = strings.Repeat("x", MaxLabelLength+1) }},
		{`channel "smtp" is not one the factory lists`, func(s *BuildSchema) {
			s.Targets[3].Channels = []ChannelVersions{{ModuleName: "smtp", Versions: []int{1}}}
		}},
		{`channel "http": version 3 is not one the factory lists`, func(s *BuildSchema) {
			s.Targets[3].Channels = []ChannelVersions{{ModuleName: "http", Versions: []int{3}}}
		}},
		{`target "shellcode": duplicate channel "http"`, func(s *BuildSchema) {
			s.Targets[3].Channels = append(s.Targets[3].Channels, s.Targets[3].Channels[0])
		}},
		{"too many commands", func(s *BuildSchema) { s.Commands = make([]BuildCommand, MaxBuildCommands+1) }},
		{`command "Shell": id must match`, func(s *BuildSchema) { s.Commands[2].ID = "Shell" }},
		{`command "fs.ls": id must match`, func(s *BuildSchema) { s.Commands[2].ID = "fs.ls" }},
		{`duplicate command "exit"`, func(s *BuildSchema) { s.Commands = append(s.Commands, s.Commands[1]) }},
		{`command "exit": label longer than`, func(s *BuildSchema) { s.Commands[1].Label = strings.Repeat("x", MaxLabelLength+1) }},
		{`command "screenshot": target "macos-app" is not one the factory lists`, func(s *BuildSchema) {
			s.Commands[4].Targets = []string{"macos-app"}
		}},
		{`command "screenshot": duplicate target "windows-exe"`, func(s *BuildSchema) {
			s.Commands[4].Targets = []string{"windows-exe", "windows-exe"}
		}},
		{`command "sleep": too many params`, func(s *BuildSchema) { s.Commands[0].Params = make([]FieldSpec, MaxCommandParams+1) }},
		{`command "sleep": duplicate param "interval"`, func(s *BuildSchema) {
			s.Commands[0].Params = append(s.Commands[0].Params, s.Commands[0].Params[0])
		}},
		{`command "sleep": param "jitter": default`, func(s *BuildSchema) { s.Commands[0].Params[1].Default = 200 }},
		// A task hands no files to a minion.
		{`command "shell": param "command": type file is only for build schemas`, func(s *BuildSchema) {
			s.Commands[2].Params[0].Type = FieldFile
		}},
	}
	for _, c := range cases {
		s := exampleBuildSchema(t)
		c.mutate(&s)
		if err := ValidateBuildSchema(s); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want an error containing %q, got %v", c.want, err)
		}
	}
}

func TestBuildTargetFieldLimit(t *testing.T) {
	s := exampleBuildSchema(t)
	for i := 0; len(s.Fields)+len(s.Targets[1].Fields) <= MaxBuildTargetFields; i++ {
		s.Targets[1].Fields = append(s.Targets[1].Fields, FieldSpec{Key: "extra_" + string(rune('a'+i%26)) + strings.Repeat("x", i/26), Type: FieldBool})
	}
	if err := ValidateBuildSchema(s); err == nil || !strings.Contains(err.Error(), "too many fields") {
		t.Fatalf("over %d fields with the shared ones: %v", MaxBuildTargetFields, err)
	}
}

func TestFieldDatetime(t *testing.T) {
	f := FieldSpec{Key: "kill_date", Type: FieldDatetime, Min: "2026-01-01T00:00:00Z", Max: "2030-01-01T00:00:00Z"}
	if err := validateFieldSpec(f); err != nil {
		t.Fatal(err)
	}
	if err := validateFieldSpec(FieldSpec{Key: "d", Type: FieldDatetime, Min: "tomorrow"}); err == nil {
		t.Error("min that is not a timestamp accepted")
	}
	for _, v := range []any{"2027-01-31T00:00:00Z", "2027-01-31T00:00:00.5+02:00", nil} {
		if err := ValidateValue(f, v); err != nil {
			t.Errorf("%v: %v", v, err)
		}
	}
	for _, v := range []any{"2027-01-31", "31.01.2027", 1769817600, "2025-12-31T23:59:59Z", "2030-01-01T00:00:01Z"} {
		if err := ValidateValue(f, v); err == nil {
			t.Errorf("%v: accepted", v)
		}
	}
	if got, err := ParseDatetime("2027-01-31T02:00:00+02:00"); err != nil || got.UTC().Hour() != 0 {
		t.Errorf("ParseDatetime = %v, %v", got, err)
	}
}

func TestFieldEnumList(t *testing.T) {
	f := FieldSpec{Key: "guardrails", Type: FieldEnumList, MaxItems: 2,
		Options: []EnumOption{{Value: "domain_joined"}, {Value: "no_debugger"}, {Value: "no_vm"}}}
	if err := validateFieldSpec(f); err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{[]any{"domain_joined"}, []string{"no_vm", "no_debugger"}, []any{}, nil} {
		if err := ValidateValue(f, v); err != nil {
			t.Errorf("%v: %v", v, err)
		}
	}
	for name, v := range map[string]any{
		"twice":     []any{"no_vm", "no_vm"},
		"unknown":   []any{"no_sandbox"},
		"not text":  []any{1},
		"not list":  "no_vm",
		"too many":  []any{"domain_joined", "no_debugger", "no_vm"},
		"map value": map[string]any{"no_vm": true},
	} {
		if err := ValidateValue(f, v); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	required := f
	required.Required = true
	if err := ValidateValue(required, []any{}); err == nil {
		t.Error("required enum_list accepted an empty list")
	}

	for name, spec := range map[string]FieldSpec{
		"no options":    {Key: "g", Type: FieldEnumList},
		"bad default":   {Key: "g", Type: FieldEnumList, Options: f.Options, Default: []any{"no_sandbox"}},
		"negative max":  {Key: "g", Type: FieldEnumList, Options: f.Options, MaxItems: -1},
		"string accept": {Key: "g", Type: FieldEnumList, Options: f.Options, Accept: []string{".ico"}},
	} {
		if err := validateFieldSpec(spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFieldFile(t *testing.T) {
	f := FieldSpec{Key: "icon", Type: FieldFile, Accept: []string{".ico", "image/x-icon", "image/*"}, MaxSize: 1024}
	if err := validateBuildFieldSpec(f); err != nil {
		t.Fatal(err)
	}
	// Only a build hands files to a module.
	if err := validateFieldSpec(f); err == nil {
		t.Error("file accepted outside a build schema")
	}
	if err := ValidateManifest(ManagementManifest{SchemaVersion: ManagementSchemaV1,
		Properties: []PropertySpec{{FieldSpec: f, Apply: ApplyLive}}}); err == nil {
		t.Error("file property accepted")
	}
	if err := ValidateManifest(ManagementManifest{SchemaVersion: ManagementSchemaV1,
		Status: []StatusSpec{{Key: "icon", Type: FieldFile}}}); err == nil {
		t.Error("file status value accepted")
	}
	if err := ValidateConnectionSchema(ConnectionSchema{SchemaVersion: ConnectionSchemaV1, Version: 1,
		Fields: []FieldSpec{f}}); err == nil {
		t.Error("file connection field accepted")
	}

	for name, spec := range map[string]FieldSpec{
		"default":           {Key: "icon", Type: FieldFile, Default: "f-1"},
		"accept no dot":     {Key: "icon", Type: FieldFile, Accept: []string{"ico"}},
		"accept no subtype": {Key: "icon", Type: FieldFile, Accept: []string{"image"}},
		"too many accept":   {Key: "icon", Type: FieldFile, Accept: make([]string, MaxAcceptEntries+1)},
		"negative size":     {Key: "icon", Type: FieldFile, MaxSize: -1},
		"accept on string":  {Key: "name", Type: FieldString, Accept: []string{".ico"}},
		"max_size on bytes": {Key: "size", Type: FieldBytes, MaxSize: 10},
	} {
		if err := validateBuildFieldSpec(spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if err := ValidateValue(f, "0f9a2c1e-6f1b-4a43-9d4e-2b9b3c1d7e55"); err != nil {
		t.Errorf("file id: %v", err)
	}
	for _, v := range []any{"", 7, strings.Repeat("x", MaxFileIDLength+1)} {
		if err := ValidateValue(f, v); err == nil {
			t.Errorf("%v: accepted as a file id", v)
		}
	}

	for _, ok := range []BuildFile{
		{Name: "APP.ICO", Size: 10},
		{Name: "favicon", MediaType: "image/x-icon", Size: 10},
		{Name: "logo.png", MediaType: "image/png; charset=binary", Size: 1024},
	} {
		if err := ValidateFile(f, ok); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []BuildFile{
		{Name: "app.exe", MediaType: "application/octet-stream", Size: 10},
		{Name: "app.ico", Size: 1025},
		{Name: "ico", Size: 10},
	} {
		if err := ValidateFile(f, bad); err == nil {
			t.Errorf("%+v: accepted", bad)
		}
	}
	if err := ValidateFile(FieldSpec{Key: "any", Type: FieldFile}, BuildFile{Name: "x.bin", Size: 1 << 40}); err != nil {
		t.Errorf("no accept and no max_size: %v", err)
	}
}

func TestValidateFieldValues(t *testing.T) {
	fields := []FieldSpec{
		{Key: "name", Type: FieldString, Required: true},
		{Key: "mode", Type: FieldEnum, Required: true, Default: "fast", Options: []EnumOption{{Value: "fast"}, {Value: "slow"}}},
		{Key: "debug", Type: FieldBool, Default: false},
		{Key: "note", Type: FieldString},
	}
	if p := ValidateFieldValues(fields, map[string]any{"name": "x"}); p != nil {
		t.Fatalf("valid: %v", p)
	}
	p := ValidateFieldValues(fields, map[string]any{"mode": "warp", "color": "red"})
	if p["name"] != "value is required" || p["mode"] == "" || p["color"] != "not a declared field" || len(p) != 3 {
		t.Fatalf("problems = %v", p)
	}

	got := ResolveFieldValues(fields, map[string]any{"name": "x", "color": "red", "note": nil})
	want := map[string]any{"name": "x", "mode": "fast", "debug": false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveFieldValues = %v, want %v", got, want)
	}
}
