package protocol

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

const testBuildID = "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f"

func validInboundMessage() InboundMinionMessage {
	return InboundMinionMessage{
		MessageID:       "c4ca4238-a0b9-4382-8dcc-509a6f75849b",
		BuildID:         testBuildID,
		ChannelInstance: "http-main",
		TraceParent:     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		Data:            []byte{0xff, 0xfe, 0x00, 0x80}, // not UTF-8: raw bytes travel as they are
	}
}

func TestValidateInbound(t *testing.T) {
	if err := ValidateInbound(validInboundMessage()); err != nil {
		t.Fatalf("valid message: %v", err)
	}
	for name, c := range map[string]struct {
		mutate func(m *InboundMinionMessage)
		code   string
	}{
		"no message id":     {func(m *InboundMinionMessage) { m.MessageID = "" }, ErrCodeMissingField},
		"message id format": {func(m *InboundMinionMessage) { m.MessageID = "msg-1" }, ErrCodeInvalidValue},
		"no build id":       {func(m *InboundMinionMessage) { m.BuildID = "" }, ErrCodeMissingField},
		"uppercase minion":  {func(m *InboundMinionMessage) { m.BuildID = strings.ToUpper(testBuildID) }, ErrCodeInvalidValue},
		"no instance":       {func(m *InboundMinionMessage) { m.ChannelInstance = " " }, ErrCodeMissingField},
		"long instance":     {func(m *InboundMinionMessage) { m.ChannelInstance = strings.Repeat("a", MaxChannelInstanceLength+1) }, ErrCodeInvalidValue},
		"empty body":        {func(m *InboundMinionMessage) { m.Data = nil }, ErrCodeMissingField},
	} {
		m := validInboundMessage()
		c.mutate(&m)
		var vErr *ValidationError
		if err := ValidateInbound(m); !errors.As(err, &vErr) || vErr.Code != c.code {
			t.Errorf("%s: %v, want code %s", name, err, c.code)
		}
	}
}

// Core's reply may carry nothing: it has nothing for the minion.
func TestValidateOutbound(t *testing.T) {
	m := OutboundMinionMessage{MessageID: "3c9d2b7e-5a41-4f08-b6e2-91d7c0a4e8f3", BuildID: testBuildID}
	if err := ValidateOutbound(m); err != nil {
		t.Fatalf("empty reply: %v", err)
	}
	m.BuildID = ""
	if !IsValidationCode(ValidateOutbound(m), ErrCodeMissingField) {
		t.Fatal("a reply without a build id passed")
	}
}

func TestHeadersRoundTrip(t *testing.T) {
	in := validInboundMessage()
	h := http.Header{}
	in.SetHeaders(h)
	if _, set := h[HeaderPeerAddress]; set {
		t.Fatal("no peer address, yet the header is set")
	}
	in.PeerAddress = "203.0.113.7"
	h = http.Header{}
	in.SetHeaders(h)
	if h.Get("Content-Type") != SyncContentType {
		t.Fatalf("content type %q", h.Get("Content-Type"))
	}
	got := InboundFromHeaders(h)
	got.Data = in.Data
	if got.MessageID != in.MessageID || got.BuildID != in.BuildID || got.ChannelInstance != in.ChannelInstance || got.TraceParent != in.TraceParent ||
		got.PeerAddress != in.PeerAddress {
		t.Fatalf("inbound %+v, want %+v", got, in)
	}

	out := OutboundMinionMessage{MessageID: "3c9d2b7e-5a41-4f08-b6e2-91d7c0a4e8f3", BuildID: testBuildID}
	h = http.Header{}
	out.SetHeaders(h)
	if h.Get("Content-Type") != "" || h.Get(HeaderTraceParent) != "" {
		t.Fatalf("empty reply headers %v: no content type, no traceparent", h)
	}
	out.Data = []byte{1}
	out.TraceParent = in.TraceParent
	h = http.Header{}
	out.SetHeaders(h)
	if back := OutboundFromHeaders(h); back.MessageID != out.MessageID || back.BuildID != out.BuildID ||
		back.TraceParent != out.TraceParent || h.Get("Content-Type") != SyncContentType {
		t.Fatalf("outbound %+v, headers %v", back, h)
	}
}
