package protocol_test

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// ExampleValidateInbound builds a sync request the way a channel module does:
// the minion's ciphertext as the body, the rest in headers. A failure carries
// a typed, machine-readable code.
func ExampleValidateInbound() {
	msg := protocol.InboundMinionMessage{
		MessageID:       protocol.NewID(),
		BuildID:         "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f",
		ChannelInstance: "http-channel-1",
		Data:            []byte{0x8f, 0x00, 0xc3, 0x1e}, // ciphertext: any bytes
	}
	if err := protocol.ValidateInbound(msg); err != nil {
		fmt.Println("unexpected:", err)
		return
	}
	req, _ := http.NewRequest(http.MethodPost, "http://core"+protocol.SyncPath, bytes.NewReader(msg.Data))
	msg.SetHeaders(req.Header)
	fmt.Println(req.Header.Get("Content-Type"), req.Header.Get(protocol.HeaderChannelInstance))

	msg.Data = nil
	var vErr *protocol.ValidationError
	if err := protocol.ValidateInbound(msg); errors.As(err, &vErr) {
		fmt.Printf("validation failed: code=%s\n", vErr.Code)
	}

	// Output:
	// application/octet-stream http-channel-1
	// validation failed: code=missing_field
}

// ExampleValidateOutbound shows core's reply. Its Data may be empty when core
// has nothing for the minion: the reply is then 204 No Content.
func ExampleValidateOutbound() {
	msg := protocol.OutboundMinionMessage{
		MessageID: protocol.NewID(),
		BuildID:   "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f",
	}
	if err := protocol.ValidateOutbound(msg); err != nil {
		fmt.Println("unexpected:", err)
		return
	}
	fmt.Println("an empty reply is valid")

	// Output:
	// an empty reply is valid
}
