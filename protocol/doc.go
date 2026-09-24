// Package protocol defines canonical channel<->Logos message contracts for Logos.
//
// It is the single source of truth shared by core and all modules, covering both
// planes:
//
//   - data-plane: HTTP minion-sync messages (inbound/outbound.minion_message),
//     carrying opaque encrypted blobs (messages.go)
//   - control-plane: the AMQP envelope used by RPC requests, RPC replies, and
//     events between core and modules (envelope.go)
//
// It provides:
//   - stable message structs for inbound/outbound minion sync flows
//   - the shared control-plane Envelope / ReplyEnvelope and helpers
//   - constants for canonical type, version, status, and error-code fields
//   - validation helpers with typed, machine-readable errors
package protocol
