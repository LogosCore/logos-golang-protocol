package protocol

import (
	"errors"
	"testing"
	"time"
)

func TestValidateInbound_Valid(t *testing.T) {
	msg := validInboundMessage()

	if err := ValidateInbound(msg); err != nil {
		t.Fatalf("ValidateInbound() error = %v, want nil", err)
	}
}

func TestValidateOutbound_Valid(t *testing.T) {
	msg := validOutboundMessage()

	if err := ValidateOutbound(msg); err != nil {
		t.Fatalf("ValidateOutbound() error = %v, want nil", err)
	}
}

func TestValidateInbound_MissingRequiredField(t *testing.T) {
	msg := validInboundMessage()
	msg.MessageID = ""

	err := ValidateInbound(msg)
	assertValidationCode(t, err, ErrCodeMissingField)
}

func TestValidateInbound_InvalidTimestamp(t *testing.T) {
	msg := validInboundMessage()
	msg.Timestamp = "not-a-timestamp"

	err := ValidateInbound(msg)
	assertValidationCode(t, err, ErrCodeInvalidTimestamp)
}

func TestValidateOutbound_InvalidType(t *testing.T) {
	msg := validOutboundMessage()
	msg.Type = TypeInboundAgentMessage

	err := ValidateOutbound(msg)
	assertValidationCode(t, err, ErrCodeInvalidType)
}

func TestValidateOutbound_MissingSourceField(t *testing.T) {
	msg := validOutboundMessage()
	msg.Source.Tenant = ""

	err := ValidateOutbound(msg)
	assertValidationCode(t, err, ErrCodeMissingField)
}

func assertValidationCode(t *testing.T, err error, wantCode string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected validation error with code %q, got nil", wantCode)
	}

	var vErr *ValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if vErr.Code != wantCode {
		t.Fatalf("validation code = %q, want %q", vErr.Code, wantCode)
	}
}

func validInboundMessage() InboundAgentMessage {
	return InboundAgentMessage{
		MessageID: "msg-in-1",
		Type:      TypeInboundAgentMessage,
		Version:   VersionV1,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source: SourceInfo{
			Module:         "agent",
			ModuleInstance: "agent-1",
			Transport:      "ws",
			Tenant:         "default",
		},
		ID:            "agent-123",
		EncryptedData: "ciphertext",
		Meta: MessageMeta{
			"trace_id": "trace-1",
		},
	}
}

func validOutboundMessage() OutboundAgentMessage {
	return OutboundAgentMessage{
		MessageID: "msg-out-1",
		Type:      TypeOutboundAgentMessage,
		Version:   VersionV1,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source: SourceInfo{
			Module:         "logos",
			ModuleInstance: "logos-1",
			Transport:      "ws",
			Tenant:         "default",
		},
		ID:            "agent-123",
		EncryptedData: "ciphertext",
		Meta: MessageMeta{
			"trace_id": "trace-2",
		},
	}
}
