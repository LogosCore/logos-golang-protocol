# CLAUDE.md

`logos-golang-protocol` (`github.com/logoscore/logos-golang-protocol`, one
package, `protocol`): the contracts core, the modules and the minions share,
as Go types, constants and validators. What crosses a boundary between them is
defined here once; core, the three SDKs (module-core, channel-core,
factory-core), every module and the Go minions (BOB's, the SSH channel's)
import it. Its only dependency is the CBOR library. The docs site
(https://logoscore.github.io/logos-docs/, sources in `../logos-docs`) is the
contracts' prose; each file here names its page (`docs: contracts/...`).

## Commands

```bash
go build ./... && go vet ./... && go test ./...
golangci-lint run ./...
GOARCH=386 go vet ./... && GOOS=windows GOARCH=386 go build ./... && GOARCH=arm go build ./...
```

The last line is CI's 32-bit step: minions are built for `linux/386`,
`windows/386` and ARM, so the package compiles where `int` is 32 bits. CI
(`.github/workflows/ci.yml`: module-core's file plus that step) runs
everything here, golangci-lint v2.13.2 with its default linters and no
config, on pushes to `main`, on `v*` tags and on pull requests. Keep 0
issues. Runnable examples are in `protocol/example_test.go`.

## Layout (`protocol/`)

| | |
|---|---|
| The planes | `envelope.go` (the AMQP envelope: RPCs, replies, events), `messages.go` (the sync call's headers and messages), `link.go` (the control link), `connections.go` (connection sockets), `failover.go` |
| Registration | `management.go` (the manifest, its RPCs), `action_conditions.go`, `logs.go` (live log streaming), `icon.go`, `connection.go` (a channel's minion connection schema), `build.go` and `build_ops.go` (a factory's build schema; build requests, progress and results), `build_log.go` (the live build log, `factory.build.log`), `error_codes.go` (minion error codes: their checks, and each build's own, drawn by core), `minion_config.go` (the numbered CBOR config core makes for a build), `credentials.go` |
| Minion messages | `minion_messages.go` (the message, its item numbers, staging and hello), `minion_frame.go` and `crypto.go` (the sealed frame, the suites), `compression.go` (the packed item), `codecs.go`, `json_envelope.go` and `factory_link.go` (envelopes, and a factory's own over its link), `task_args.go`, `task_results.go`, `result_data.go`, `listings.go`, `volumes.go`, `file_transfer.go`, `identity.go`, `machine_id.go`, `feedback.go`, `max_tasks.go`, `tunnels.go`, `icmp.go`, `vpn.go`, `delegation.go` |
| Shared | `validate.go`, `errors.go` (`ValidationError` and its codes), `doc.go` |

## Conventions

- **The docs first.** A change to a contract goes on its page before the
  code, and the page's facts are read from here (logos-docs, Contributing →
  Changing the Protocol). Five tests copy the docs' examples verbatim
  (`TestBuildSchemaDocExample`, `TestBuildRequestDocExample` and
  `TestBuildResultDocExamples` from Minion Build, `TestDocsConditionsExample`
  from Module Management, `TestJSONEnvelopeDocExample` from Codecs): change
  an example, change its test.
- **Numbers are never reused**: item types and keys (the wire format's
  Registry, pinned by `TestRegistry`), error codes, a schema's field `num`s,
  commands' `op`s and params' `num`s. A new one takes a number never used;
  one that goes leaves its number unused, as minions keep the numbers they
  were built with.
- **Receivers ignore what they do not know**, so an optional key needs no new
  version; the exceptions are on the minion messages' page (Changing these
  formats).
- **One set of checks.** Every type that crosses has a validator, and core
  checks what modules and minions send with the same ones a module's tests
  run (`ValidateBuildMessage`, `ValidateMessageHead`, `ValidateBuildRequest`,
  `ReadTunnel`, …).
- **No backward compatibility for now** (pre-1.0): rename or remove freely;
  every repository a change reaches moves in the same release round.

## Releasing

A `vX.Y.Z` tag is the release: minor for anything on the wire or in a
schema, patch for a fix that changes no format. A round tags the protocol,
then moves the repositories that use it in dependency order (Contributing →
Changing the Protocol, Releasing). Each new version gets its line on the
docs' Protocol Releases page. Until a tag, other repositories build against
this checkout through a git-ignored `go.work`.
