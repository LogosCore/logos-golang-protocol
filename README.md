# logos-golang-protocol

Shared Go protocol contracts for Logos: the canonical data-plane minion messages
and the control-plane AMQP envelope, with validation helpers and typed errors.

## Install

```bash
go get github.com/logoscore/logos-golang-protocol@latest
```

## Quick Usage

Runnable examples live in [`protocol/example_test.go`](protocol/example_test.go)
and are compiled and executed by `go test ./...`, so they cannot drift from the
API:

```bash
go test -run Example -v ./protocol
```

- `ExampleValidateInbound` — build an `InboundMinionMessage` the way a channel
  module does, validate it, and read the typed `*ValidationError` code when a
  field is missing.
- `ExampleValidateOutbound` — core's reply. `OutboundMinionMessage` carries no
  `Source`: it answers an existing `id`.

Full API reference: [pkg.go.dev](https://pkg.go.dev/github.com/logoscore/logos-golang-protocol/protocol).
