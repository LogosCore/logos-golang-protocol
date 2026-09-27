package protocol_test

import (
	"errors"
	"fmt"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// ExampleValidateInbound builds a canonical inbound minion message the way a
// channel module does, then validates it. A failure carries a typed,
// machine-readable code.
func ExampleValidateInbound() {
	msg := protocol.InboundMinionMessage{
		MessageID: protocol.NewULID(),
		Type:      protocol.TypeInboundMinionMessage,
		Version:   protocol.VersionV1,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source: protocol.SourceInfo{
			Module:         "http-channel",
			ModuleInstance: "http-channel-1",
			Transport:      "http",
			Tenant:         "default",
		},
		ID:            "minion-123",
		EncryptedData: "base64-or-ciphertext",
		Meta: protocol.MessageMeta{
			"trace_id": "trace-1",
		},
	}

	if err := protocol.ValidateInbound(msg); err != nil {
		fmt.Println("unexpected:", err)
		return
	}
	fmt.Println("inbound message is valid")

	msg.EncryptedData = ""

	var vErr *protocol.ValidationError
	if err := protocol.ValidateInbound(msg); errors.As(err, &vErr) {
		fmt.Printf("validation failed: code=%s message=%s\n", vErr.Code, vErr.Message)
	}

	// Output:
	// inbound message is valid
	// validation failed: code=missing_field message=encrypted_data is required
}

// ExampleValidateOutbound shows core's reply: it answers an existing id and so
// carries no Source.
func ExampleValidateOutbound() {
	msg := protocol.OutboundMinionMessage{
		MessageID:     protocol.NewULID(),
		Type:          protocol.TypeOutboundMinionMessage,
		Version:       protocol.VersionV1,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		ID:            "minion-123",
		EncryptedData: "base64-or-ciphertext",
	}

	if err := protocol.ValidateOutbound(msg); err != nil {
		fmt.Println("unexpected:", err)
		return
	}
	fmt.Println("outbound message is valid")

	// Output:
	// outbound message is valid
}
