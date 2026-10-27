package protocol

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The examples of the Minion Build contract page (logos-docs,
// contracts/minion-build), verbatim.
const (
	docBuildRequest = `{
  "minion_id": "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f",
  "target": "windows-exe",
  "platform": "windows/amd64",
  "schema_version": 1,
  "values": {
    "kill_date": "2027-01-31T00:00:00Z",
    "guardrails": ["domain_joined"],
    "debug": false,
    "icon": "0f9a2c1e-6f1b-4a43-9d4e-2b9b3c1d7e55"
  },
  "connections": [
    {
      "endpoint": {
        "format": "logos.channel-endpoint.v1",
        "name": "edge-eu",
        "channel": { "module_name": "http", "schema_version": 2 },
        "params": { "base_url": "https://edge-eu.example.com", "tls_verify": false, "request_timeout": "40s" }
      },
      "values": { "method": "POST", "path_prefix": "/cdn/assets/" }
    }
  ],
  "files": {
    "0f9a2c1e-6f1b-4a43-9d4e-2b9b3c1d7e55": {
      "id": "0f9a2c1e-6f1b-4a43-9d4e-2b9b3c1d7e55", "name": "app.ico", "size": 4286,
      "sha256": "9f2c41d0e5a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2",
      "media_type": "image/x-icon",
      "url": "http://logos-seaweedfs-s3:8333/…?X-Amz-Signature=…"
    }
  },
  "crypto": { "suite": "x25519-xchacha20poly1305", "material": { "…": "…" } },
  "artifact": { "upload_url": "http://logos-seaweedfs-s3:8333/…?X-Amz-Signature=…", "max_size": 268435456 },
  "deadline": "2026-10-26T14:30:00Z",
  "actor": { "type": "user", "id": "f140266c-…", "name": "admin" }
}`

	docBuildSucceeded = `{
  "minion_id": "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f",
  "status": "succeeded",
  "artifact": {
    "filename": "WinTelemetry.exe", "size": 2412544,
    "sha256": "28afe4a10a4a7d593623dcd1eee11f519b056d2bfdda4c7b0bd7a57fc3a5fc8b",
    "media_type": "application/vnd.microsoft.portable-executable"
  },
  "capabilities": ["shell", "upload", "download"],
  "warnings": ["debug build: strings are not obfuscated"],
  "log": "…"
}`

	docBuildFailed = `{
  "minion_id": "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f",
  "status": "failed",
  "error": { "code": "compile_failed", "message": "go build exited with status 1" },
  "log": "…"
}`

	docBuildReply = `{
  "minion_id": "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f",
  "accepted": true,
  "steps": [
    { "id": "fetch", "label": "Fetch files" },
    { "id": "compile", "label": "Compile" },
    { "id": "sign", "label": "Sign" },
    { "id": "upload", "label": "Upload" }
  ]
}`

	docBuildProgress = `{ "minion_id": "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f", "step": "compile", "message": "Compiling windows/amd64" }`
)

const iconID = "0f9a2c1e-6f1b-4a43-9d4e-2b9b3c1d7e55"

// exampleBuildRequest decodes docBuildRequest afresh, so callers may mutate it.
func exampleBuildRequest(t *testing.T) BuildRequest {
	t.Helper()
	var r BuildRequest
	if err := json.Unmarshal([]byte(docBuildRequest), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBuildRequestDocExample(t *testing.T) {
	s, r := exampleBuildSchema(t), exampleBuildRequest(t)
	if p := ValidateBuildRequest(s, r); p != nil {
		t.Fatalf("problems: %v", p)
	}
	if r.Connections[0].Endpoint.Channel.ModuleName != "http" || r.Files[iconID].Name != "app.ico" ||
		r.Crypto.Suite != "x25519-xchacha20poly1305" || !json.Valid(r.Crypto.Material) {
		t.Fatalf("decoded: %+v", r)
	}
	if want := time.Date(2026, 10, 26, 14, 30, 0, 0, time.UTC); !r.Deadline.Equal(want) {
		t.Fatalf("deadline = %v, want %v", r.Deadline, want)
	}

	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var again BuildRequest
	if err := json.Unmarshal(raw, &again); err != nil {
		t.Fatal(err)
	}
	if p := ValidateBuildRequest(s, again); p != nil {
		t.Fatalf("round trip: %v\n%s", p, raw)
	}
}

func TestValidateBuildRequest_Problems(t *testing.T) {
	s := exampleBuildSchema(t)
	file := func(edit func(f *BuildFile)) func(r *BuildRequest) {
		return func(r *BuildRequest) {
			f := r.Files[iconID]
			edit(&f)
			r.Files[iconID] = f
		}
	}
	// Each case must cause exactly one problem, under key.
	cases := []struct {
		key    string
		mutate func(r *BuildRequest)
	}{
		{"minion_id", func(r *BuildRequest) { r.MinionID = "" }},
		{"minion_id", func(r *BuildRequest) { r.MinionID = strings.ToUpper(r.MinionID) }},
		{"minion_id", func(r *BuildRequest) { r.MinionID = "5b0c4f6e-8a1d-1c2b-9e7f-3d2a1b0c9e8f" }}, // version 1
		{"schema_version", func(r *BuildRequest) { r.SchemaVersion = 2 }},
		{"target", func(r *BuildRequest) { r.Target = "macos-app" }},
		{"platform", func(r *BuildRequest) { r.Platform = "linux/amd64" }},
		{"values.color", func(r *BuildRequest) { r.Values["color"] = "red" }},
		{"values.guardrails", func(r *BuildRequest) { r.Values["guardrails"] = []any{"no_sandbox"} }},
		{"values.kill_date", func(r *BuildRequest) { r.Values["kill_date"] = "2027-01-31" }},
		{"values.icon", func(r *BuildRequest) { r.Values["icon"] = "not-in-files" }},
		{"values.icon", file(func(f *BuildFile) { f.Size = 262145 })},
		{"values.icon", file(func(f *BuildFile) { f.Name, f.MediaType = "app.png", "image/png" })},
		{"files." + iconID, file(func(f *BuildFile) { f.SHA256 = "9f2c…" })},
		{"files." + iconID, file(func(f *BuildFile) { f.ID = "another-file" })},
		{"files." + iconID, file(func(f *BuildFile) { f.URL = "/build-files/app.ico" })},
		{"connections", func(r *BuildRequest) { r.Connections = nil }},
		{"connections[0]", func(r *BuildRequest) { r.Connections[0].Endpoint.Format = "logos.channel-endpoint.v2" }},
		{"connections[0]", func(r *BuildRequest) { r.Connections[0].Endpoint.Channel.SchemaVersion = 3 }},
		{"connections[0]", func(r *BuildRequest) { r.Connections[0].Endpoint.Channel.ModuleName = "smtp" }},
		{"connections[0].values.method", func(r *BuildRequest) { r.Connections[0].Values["method"] = "PATCH" }},
		{"connections[0].values.color", func(r *BuildRequest) { r.Connections[0].Values["color"] = "red" }},
		{"crypto", func(r *BuildRequest) { r.Crypto = nil }},
		{"crypto", func(r *BuildRequest) { r.Crypto.Suite = "rot13" }},
		{"artifact.upload_url", func(r *BuildRequest) { r.Artifact.UploadURL = "seaweedfs:8333/artifact" }},
		{"artifact.max_size", func(r *BuildRequest) { r.Artifact.MaxSize = 0 }},
		{"deadline", func(r *BuildRequest) { r.Deadline = time.Time{} }},
	}
	for _, c := range cases {
		r := exampleBuildRequest(t)
		c.mutate(&r)
		if p := ValidateBuildRequest(s, r); p[c.key] == "" || len(p) != 1 {
			t.Errorf("want one problem under %q, got %v", c.key, p)
		}
	}
}

func TestValidateBuildRequest_TargetFields(t *testing.T) {
	// The service target has no icon and needs a service name.
	r := exampleBuildRequest(t)
	r.Target = "windows-service"
	p := ValidateBuildRequest(exampleBuildSchema(t), r)
	if p["values.icon"] != "not a declared field" || p["values.service_name"] != "value is required" || len(p) != 2 {
		t.Fatalf("problems = %v", p)
	}
}

func TestValidateBuildRequest_ShellcodeCannotUseDNS(t *testing.T) {
	s, r := exampleBuildSchema(t), exampleBuildRequest(t)
	r.Connections = append(r.Connections, BuildConnection{Endpoint: ChannelEndpointExport{
		Format: ChannelEndpointExportV1, Name: "dns-backup",
		Channel: ExportChannel{ModuleName: "dns", SchemaVersion: 1},
	}})
	if p := ValidateBuildRequest(s, r); p != nil {
		t.Fatalf("windows-exe with a dns endpoint: %v", p)
	}
	r.Target, r.Values = "shellcode", map[string]any{}
	if p := ValidateBuildRequest(s, r); p["connections[1]"] == "" || len(p) != 1 {
		t.Fatalf("shellcode with a dns endpoint: %v", p)
	}
}

func TestValidateBuildRequest_ConnectionFile(t *testing.T) {
	s, r := exampleBuildSchema(t), exampleBuildRequest(t)
	s.Channels[0].Fields = append(s.Channels[0].Fields, FieldSpec{Key: "client_cert", Type: FieldFile, Accept: []string{".pem"}})
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	r.Files["cert-1"] = BuildFile{ID: "cert-1", Name: "client.pem", Size: 1200,
		SHA256: strings.Repeat("0a", 32), URL: "http://logos-seaweedfs-s3:8333/cert-1"}
	r.Connections[0].Values["client_cert"] = "cert-1"
	if p := ValidateBuildRequest(s, r); p != nil {
		t.Fatalf("file connection parameter: %v", p)
	}
	r.Connections[0].Values["client_cert"] = iconID // an .ico
	if p := ValidateBuildRequest(s, r); p["connections[0].values.client_cert"] == "" || len(p) != 1 {
		t.Fatalf("wrong file kind: %v", p)
	}
}

func TestValidateBuildRequest_NoCrypto(t *testing.T) {
	s, r := exampleBuildSchema(t), exampleBuildRequest(t)
	s.Crypto = nil
	if p := ValidateBuildRequest(s, r); p["crypto"] == "" || len(p) != 1 {
		t.Fatalf("crypto for a factory without suites: %v", p)
	}
	r.Crypto = nil
	if p := ValidateBuildRequest(s, r); p != nil {
		t.Fatalf("no crypto: %v", p)
	}
}

func TestBuildResultDocExamples(t *testing.T) {
	for _, doc := range []string{docBuildSucceeded, docBuildFailed} {
		var r BuildResult
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", r.Status, err)
		}
	}
}

func TestBuildResult_Invalid(t *testing.T) {
	decode := func(doc string) BuildResult {
		var r BuildResult
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := []struct {
		want   string
		doc    string
		mutate func(r *BuildResult)
	}{
		{"minion_id must be a lowercase UUIDv4", docBuildSucceeded, func(r *BuildResult) { r.MinionID = "" }},
		{"status must be", docBuildSucceeded, func(r *BuildResult) { r.Status = "done" }},
		{"needs its artifact", docBuildSucceeded, func(r *BuildResult) { r.Artifact = nil }},
		{"has no error", docBuildSucceeded, func(r *BuildResult) { r.Error = &BuildError{Code: "oops"} }},
		{"plain file name", docBuildSucceeded, func(r *BuildResult) { r.Artifact.Filename = "../WinTelemetry.exe" }},
		{"plain file name", docBuildSucceeded, func(r *BuildResult) { r.Artifact.Filename = "Win\nTelemetry.exe" }},
		{"size must not be negative", docBuildSucceeded, func(r *BuildResult) { r.Artifact.Size = -1 }},
		{"sha256 must be", docBuildSucceeded, func(r *BuildResult) { r.Artifact.SHA256 = "4be1…" }},
		{`capability "Shell"`, docBuildSucceeded, func(r *BuildResult) { r.Capabilities = []string{"Shell"} }},
		{`duplicate capability "shell"`, docBuildSucceeded, func(r *BuildResult) { r.Capabilities = []string{"shell", "shell"} }},
		{"too many warnings", docBuildSucceeded, func(r *BuildResult) { r.Warnings = make([]string, MaxBuildWarnings+1) }},
		{"log longer than", docBuildSucceeded, func(r *BuildResult) { r.Log = strings.Repeat("x", MaxBuildLogBytes+1) }},
		{"needs an error code", docBuildFailed, func(r *BuildResult) { r.Error = nil }},
		{"needs an error code", docBuildFailed, func(r *BuildResult) { r.Error.Code = "Compile Failed" }},
		{"has no artifact", docBuildFailed, func(r *BuildResult) { r.Artifact = &BuildArtifact{} }},
	}
	for _, c := range cases {
		r := decode(c.doc)
		c.mutate(&r)
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want an error containing %q, got %v", c.want, err)
		}
	}
}

func TestBuildProgress(t *testing.T) {
	p := BuildProgress{MinionID: "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f", Step: "compile", Message: "compiling 3 of 10"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	bare := BuildProgress{MinionID: p.MinionID, Step: "link_2"}
	if err := bare.Validate(); err != nil {
		t.Fatalf("no message: %v", err)
	}
	if raw, _ := json.Marshal(bare); strings.Contains(string(raw), "message") {
		t.Errorf("an empty message sent: %s", raw)
	}
	for name, bad := range map[string]BuildProgress{
		"minion_id":    {MinionID: "b-1", Step: "compile"},
		"step":         {MinionID: p.MinionID, Step: "Compile"},
		"dotted step":  {MinionID: p.MinionID, Step: "go.build"},
		"no step":      {MinionID: p.MinionID},
		"long message": {MinionID: p.MinionID, Step: "compile", Message: strings.Repeat("x", MaxBuildMessageLength+1)},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDocReplyAndProgress(t *testing.T) {
	var r BuildReply
	if err := json.Unmarshal([]byte(docBuildReply), &r); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil || len(r.Steps) != 4 || r.Steps[1] != (BuildStep{ID: "compile", Label: "Compile"}) {
		t.Errorf("the documented reply: %v %+v", err, r)
	}
	var p BuildProgress
	if err := json.Unmarshal([]byte(docBuildProgress), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil || p.Step != "compile" {
		t.Errorf("the documented progress: %v %+v", err, p)
	}
}

func TestBuildReply(t *testing.T) {
	steps := []BuildStep{{ID: "fetch", Label: "Fetch sources"}, {ID: "compile", Label: "Compile"}, {ID: "sign-2", Label: "Подписать"}}
	r := BuildReply{MinionID: "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f", Accepted: true, Steps: steps}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), `"steps":[{"id":"fetch","label":"Fetch sources"}`) {
		t.Errorf("reply on the wire: %s", raw)
	}

	many := make([]BuildStep, MaxBuildSteps+1)
	for i := range many {
		many[i] = BuildStep{ID: fmt.Sprintf("s%d", i), Label: "Step"}
	}
	if err := ValidateBuildSteps(many[:MaxBuildSteps]); err != nil {
		t.Errorf("a plan of %d steps: %v", MaxBuildSteps, err)
	}
	long := strings.Repeat("ж", MaxBuildStepLabelLength) // two bytes each: counted in characters
	if err := ValidateBuildSteps([]BuildStep{{ID: "a", Label: long}}); err != nil {
		t.Errorf("a label of %d characters: %v", MaxBuildStepLabelLength, err)
	}
	for name, c := range map[string]struct {
		reply BuildReply
		want  string
	}{
		"no plan":       {BuildReply{MinionID: r.MinionID, Accepted: true}, "at least one step"},
		"too many":      {BuildReply{MinionID: r.MinionID, Accepted: true, Steps: many}, "too many"},
		"dotted id":     {BuildReply{MinionID: r.MinionID, Accepted: true, Steps: []BuildStep{{ID: "go.build", Label: "Build"}}}, "id must match"},
		"same id":       {BuildReply{MinionID: r.MinionID, Accepted: true, Steps: []BuildStep{{ID: "a", Label: "A"}, {ID: "a", Label: "B"}}}, "used twice"},
		"no label":      {BuildReply{MinionID: r.MinionID, Accepted: true, Steps: []BuildStep{{ID: "a", Label: " "}}}, "label must be 1.."},
		"long label":    {BuildReply{MinionID: r.MinionID, Accepted: true, Steps: []BuildStep{{ID: "a", Label: long + "ж"}}}, "label must be 1.."},
		"two lines":     {BuildReply{MinionID: r.MinionID, Accepted: true, Steps: []BuildStep{{ID: "a", Label: "Build\nand sign"}}}, "one line"},
		"not accepted":  {BuildReply{MinionID: r.MinionID, Steps: steps}, "accepted must be true"},
		"bad minion id": {BuildReply{MinionID: "b-1", Accepted: true, Steps: steps}, "minion_id"},
	} {
		if err := c.reply.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", name, c.want, err)
		}
	}
}
