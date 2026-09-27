# logos-golang-protocol

Shared Go protocol contracts for Logos.

## Install

```bash
go get github.com/logoscore/logos-golang-protocol@latest
```

## Quick Usage

```go
package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

func main() {
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
		var vErr *protocol.ValidationError
		if errors.As(err, &vErr) {
			fmt.Printf("validation failed: code=%s message=%s\n", vErr.Code, vErr.Message)
		}
	}
}
```

`OutboundMinionMessage` (core's reply, validated with `ValidateOutbound`) carries no
`Source`: it answers an existing `id`.
