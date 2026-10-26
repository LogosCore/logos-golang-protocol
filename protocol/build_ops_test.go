package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The examples of the Minion Build contract page (logos-docs,
// contracts/minion-build), verbatim.
const (
	docBuildRequest = `{
  "build_id": "01M6A3Q9X7J0B5KQZC2V1RS8TN",
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
  "actor": { "type": "user", "id": "6ab79922…", "name": "admin" }
}`

	docBuildSucceeded = `{
  "build_id": "01M6A3Q9X7J0B5KQZC2V1RS8TN",
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
  "build_id": "01M6A3Q9X7J0B5KQZC2V1RS8TN",
  "status": "failed",
  "error": { "code": "compile_failed", "message": "go build exited with status 1" },
  "log": "…"
}`
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
		{"build_id", func(r *BuildRequest) { r.BuildID = "build-1" }},
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
		{"build_id must be a ULID", docBuildSucceeded, func(r *BuildResult) { r.BuildID = "" }},
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
	pct := 40
	p := BuildProgress{BuildID: "01M6A3Q9X7J0B5KQZC2V1RS8TN", Step: "compile", Message: "Compiling windows/amd64", Percent: &pct}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	unknown := p
	unknown.Percent = nil
	if err := unknown.Validate(); err != nil {
		t.Fatalf("no percent: %v", err)
	}
	if raw, _ := json.Marshal(unknown); strings.Contains(string(raw), "percent") {
		t.Errorf("unknown percent sent: %s", raw)
	}

	over, zero := 101, 0
	for name, bad := range map[string]BuildProgress{
		"build_id":     {BuildID: "b-1", Step: "compile"},
		"step":         {BuildID: p.BuildID, Step: "Compile"},
		"no step":      {BuildID: p.BuildID},
		"percent":      {BuildID: p.BuildID, Step: "compile", Percent: &over},
		"long message": {BuildID: p.BuildID, Step: "compile", Message: strings.Repeat("x", MaxBuildMessageLength+1)},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (BuildProgress{BuildID: p.BuildID, Step: "queued", Percent: &zero}).Validate(); err != nil {
		t.Errorf("0%%: %v", err)
	}
}
