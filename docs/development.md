# Development

Daochi's canonical server implementation is written in Ziran. Source files at
the repository root define HTTP handlers, protocol values, storage, node trust,
sync and account services. The build generates their Go output; generated
`.zi.go` and `.zi_test.go` files are ignored and must not be edited by hand.

## Requirements and build

Use Go 1.26, a C compiler, CMake and the Ziran launcher. The package lock selects
the exact Ziran toolchain. The Makefile builds the required liboqs implementation
and sets the cgo flags for Go, liboqs and SQLite.

```sh
make generate
make build
make test-ziran
```

Generation checks canonical `.zi` sources and creates the native executable
entry through the compiler. `make build` regenerates when source or toolchain
inputs change. CI generates from the locked toolchain before testing and
deployment. `ZIRAN` overrides the launcher when validating a local toolchain.

For development against the canonical local Ziran checkout, an ignored
`ziran.local.toml` can select it:

```toml
[overrides]
ziran = "../../ziranlang/ziran"
```

General compiler and standard-library changes belong in Ziran upstream. Publish
them there first, then update this project's toolchain through Ziran's package
commands. Do not hand-edit lockfiles or downstream dependency source copies.

## Tests

`make test-ziran` runs the application suite against generated Go from source,
then saves checked `.zir`, generates Go from that IR and runs the suite again.
Independent fixtures cover native types, signatures, SQL behavior, protocol
bytes, cancellation, replay prevention and resource cleanup.

```sh
make test-ziran GOFLAGS='-mod=mod -race -count=1'
```

Keep test concurrency within the managed machine budget. Tests do not use the
owner's display. Visual or window-management tests require a private display
and isolated processes. The separate compression benchmark Go module owns its
experimental dependencies and is excluded from application package discovery.

## Ownership and boundaries

- Daochi owns node and server policy, authenticated protocol handling, storage,
  quotas, replication and operational endpoints.
- Daochi Client is the independent Ziran protocol library. Applications supply
  key storage, merge policy and platform transport; the server does not receive
  client private keys.
- Reusable language, codec, I/O and native binding capabilities belong in Ziran.
  Widgets and application UI belong in their corresponding libraries and apps.
- Native Go tests and independent fixtures verify generated behavior. Keep
  regression coverage when changing the implementation language or backend.

The [HTTP compression guide](compression.md) describes encoder ownership,
negotiation, bounded decoding and the benchmark. The
[encrypted record profile](encrypted-record-profile-v1.md) defines private
record envelopes and compression before encryption.

## Deployment verification

Use the existing GitHub deployment workflow and its backup, readiness and
rollback path. Builds stamp `version.zi` through the native Go string variable;
an unstamped development build reports `dev`. Confirm the actual installed
`build_version` through `/api/v1/node` and verify readiness and negotiated
responses separately from GitHub CI. A build or a pushed commit does not prove
the installed service changed.
