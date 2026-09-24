package protocol

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func coreSource() Source { return Source{Service: ServiceCore, Instance: "core-1"} }

func TestNewULID_ParsesAndIsUnique(t *testing.T) {
	a := NewULID()
	b := NewULID()
	if _, err := ulid.Parse(a); err != nil {
		t.Fatalf("NewULID produced unparseable ULID %q: %v", a, err)
	}
	if a == b {
		t.Fatalf("expected distinct ULIDs, got %q twice", a)
	}
}

func TestNewReply_EchoesCorrelationAndType(t *testing.T) {
	req := Envelope{CorrelationID: "corr-123", Type: "module.register", Version: EnvelopeVersionV1}

	reply, err := NewReply(req, coreSource(), map[string]any{"registered": true})
	if err != nil {
		t.Fatalf("NewReply error: %v", err)
	}
	if reply.CorrelationID != "corr-123" {
		t.Errorf("correlation_id = %q, want corr-123", reply.CorrelationID)
	}
	if reply.Type != "module.register" {
		t.Errorf("type = %q, want module.register", reply.Type)
	}
	if reply.Status != StatusOK || reply.Error != nil {
		t.Errorf("status/err = %q/%+v, want ok/nil", reply.Status, reply.Error)
	}
	if reply.Source.Service != ServiceCore {
		t.Errorf("source.service = %q, want %q", reply.Source.Service, ServiceCore)
	}
	if _, err := ulid.Parse(reply.MessageID); err != nil {
		t.Errorf("reply message_id %q not a ULID: %v", reply.MessageID, err)
	}
	ts, err := time.Parse(time.RFC3339, reply.Timestamp)
	if err != nil {
		t.Errorf("timestamp %q not RFC3339: %v", reply.Timestamp, err)
	} else if ts.Location() != time.UTC {
		t.Errorf("timestamp not UTC: %v", ts.Location())
	}
	var p map[string]any
	if err := json.Unmarshal(reply.Payload, &p); err != nil || p["registered"] != true {
		t.Errorf("payload = %s (err %v)", reply.Payload, err)
	}
}

func TestNewReply_NilPayloadIsEmptyObject(t *testing.T) {
	reply, err := NewReply(Envelope{Version: EnvelopeVersionV1}, coreSource(), nil)
	if err != nil {
		t.Fatalf("NewReply error: %v", err)
	}
	if string(reply.Payload) != "{}" {
		t.Errorf("nil payload = %q, want {}", reply.Payload)
	}
}

func TestNewErrorReply_Shape(t *testing.T) {
	req := Envelope{CorrelationID: "corr-9", Type: "module.heartbeat", Version: EnvelopeVersionV1}
	reply := NewErrorReply(req, coreSource(), CodeUnknownInstance, "no such instance")

	if reply.Status != StatusError {
		t.Errorf("status = %q, want %q", reply.Status, StatusError)
	}
	if reply.Error == nil || reply.Error.Code != CodeUnknownInstance {
		t.Fatalf("error = %+v, want code %q", reply.Error, CodeUnknownInstance)
	}
	if reply.CorrelationID != "corr-9" {
		t.Errorf("correlation_id = %q, want corr-9", reply.CorrelationID)
	}
	if string(reply.Payload) != "{}" {
		t.Errorf("error payload = %q, want {}", reply.Payload)
	}
}

func TestReplyEnvelope_RoundTripErrorIsNullOnSuccess(t *testing.T) {
	reply, err := NewReply(Envelope{CorrelationID: "c1", Version: EnvelopeVersionV1}, coreSource(), map[string]any{"ok": true})
	if err != nil {
		t.Fatalf("NewReply: %v", err)
	}
	data, err := json.Marshal(reply)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &asMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(asMap["error"]) != "null" {
		t.Errorf("error field = %s, want null on success", asMap["error"])
	}
}

func TestNewEvent_NoCorrelationID(t *testing.T) {
	env, err := NewEvent("module.registered", EnvelopeVersionV1, coreSource(), map[string]any{"instance": "http-1"})
	if err != nil {
		t.Fatalf("NewEvent error: %v", err)
	}
	if env.CorrelationID != "" {
		t.Errorf("event correlation_id = %q, want empty", env.CorrelationID)
	}
	// correlation_id must be omitted from the wire form for events.
	data, _ := json.Marshal(env)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(data, &m)
	if _, present := m["correlation_id"]; present {
		t.Errorf("correlation_id should be omitted on events, got %s", data)
	}
}

func TestMajorVersion(t *testing.T) {
	tests := []struct {
		in     string
		want   int
		wantOK bool
	}{
		{"1.0", 1, true},
		{"2.5", 2, true},
		{"1", 1, true},
		{"", 0, false},
		{"x.1", 0, false},
	}
	for _, tc := range tests {
		got, ok := MajorVersion(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("MajorVersion(%q) = (%d,%v), want (%d,%v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}
