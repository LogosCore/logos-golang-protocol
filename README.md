# logos-golang-protocol

Shared Go protocol contracts for Logos: the canonical data-plane minion messages
and the control-plane AMQP envelope, with validation helpers and typed errors.
It also holds what modules declare at registration and the operations that
follow: the management manifest, live log streaming, a channel's minion
connection schema, and a factory's build schema with the build operations
(`factory.build`, `.cancel`, `.progress`, `.result`).

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
  module does (the minion's ciphertext as `Data`, sent as the raw body of the
  sync call, its ids in `Logos-*` headers via `SetHeaders`), validate it, and
  read the typed `*ValidationError` code when a field is missing.
- `ExampleValidateOutbound` — core's reply. Its `Data` may be empty: core has
  nothing for the minion and answers 204.

Full API reference: [pkg.go.dev](https://pkg.go.dev/github.com/logoscore/logos-golang-protocol/protocol).
