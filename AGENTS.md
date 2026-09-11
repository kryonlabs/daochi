# Daochi Repository Rules

Daochi is a local-first sync and trusted-node network. Keep the protocol secure,
the public-node path convenient, and the implementation easy to audit.

## Clean Naming Rule

Use direct names inside the Daochi codebase. Do not prefix internal types and
functions with `Daochi` when package or protocol context already makes their
meaning clear. Keep `Daochi` only where it prevents wire-level ambiguity, such
as `X-Daochi-*` headers and `daochi://` URIs. Do not add new `Ksync` or `Inbe`
compatibility names; migrate maintained callers to the clean surface.

## Readability Rule

Write conventional, fully readable code. Never compress multiple statements,
branches, declarations, or error checks onto one line. Avoid dense one-line
handlers and clever control flow. Use descriptive names, focused helpers, and
explicit validation and error paths.

Run `gofmt` on changed Go files, run `git diff --check`, and inspect the final
diff before considering a change complete.

## Mesh Safety Rule

Discovery does not imply trust. New peer and replication paths must authenticate
node identity, reject replays, enforce explicit data scopes, and preserve the
zero-configuration public-node path. Add tests for unauthorized, malformed,
expired, and partition/reconnection behavior with every mesh protocol change.
