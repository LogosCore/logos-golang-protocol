package protocol

import "testing"

func TestLogsStartRequestValidate(t *testing.T) {
	ok := LogsStartRequest{StreamID: "01JABC-x_1", MinLevel: LogDebug, LeaseSeconds: 30, Backlog: 200}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid request: %v", err)
	}
	for name, r := range map[string]LogsStartRequest{
		"empty id":   {},
		"bad id":     {StreamID: "a b"},
		"bad level":  {StreamID: "s", MinLevel: "trace"},
		"long lease": {StreamID: "s", LeaseSeconds: MaxLogLeaseSeconds + 1},
		"backlog":    {StreamID: "s", Backlog: MaxLogBacklog + 1},
	} {
		if r.Validate() == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLogLevelRank(t *testing.T) {
	if !(LogDebug.Rank() < LogInfo.Rank() && LogInfo.Rank() < LogWarn.Rank() && LogWarn.Rank() < LogError.Rank()) {
		t.Error("levels out of order")
	}
	if LogLevel("x").Rank() != LogInfo.Rank() || LogLevel("x").Valid() {
		t.Error("unknown level should rank as info and be invalid")
	}
}

func TestManifestCapabilities(t *testing.T) {
	m := ManagementManifest{SchemaVersion: ManagementSchemaV1, Capabilities: []string{CapabilityLogs, "future"}}
	if err := ValidateManifest(m); err != nil {
		t.Fatal(err)
	}
	if !m.Has(CapabilityLogs) || m.Has("other") {
		t.Error("Has")
	}
}
