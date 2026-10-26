# Daochi Encrypted Record Profile v1

This profile defines the recommended client-side shape for records stored in
Daochi `encrypted_records`. The relay still treats ciphertext as opaque data:
it validates metadata, assigns versions, exports, imports, and deletes records,
but it does not need plaintext or content keys.

## Goals

- one interoperable envelope for new clients;
- unique nonces per encrypted record version;
- room for key rotation without changing the relay schema;
- deterministic associated data so records cannot be silently moved between
  accounts, apps, collections, or IDs.

## Record Envelope

Store the JSON envelope bytes as the encrypted record ciphertext payload:

```json
{
  "profile": "daochi-record-v1",
  "alg": "xchacha20poly1305",
  "key_id": "main-2026-09",
  "nonce": "base64url-24-byte-nonce",
  "aad": {
    "account_id": "sha256-public-key-hex",
    "app_id": "exampleapp",
    "collection": "private.exampleapp.v1.records",
    "id": "record-id",
    "schema": "exampleapp.note.v1"
  },
  "ciphertext": "base64url-ciphertext-with-tag"
}
```

The Daochi record metadata outside the envelope remains authoritative for sync
routing: `app_id`, `collection`, `id`, `key_id`, `nonce`, `updated_at`, and
server version. Clients should keep the envelope AAD equal to that metadata and
reject a decrypted record when it differs.

## Encryption Rules

- Use XChaCha20-Poly1305 with a fresh 24-byte random nonce for every write.
- Never reuse the same `(key_id, nonce)` pair for the same account.
- Bind `account_id`, `app_id`, `collection`, `id`, and app schema name as
  associated data.
- Keep record keys client-side. Daochi nodes must not receive content keys.
- Use base64url without padding for binary fields in JSON examples and tests.

## Key Rotation

Clients rotate by writing new record versions with a new `key_id`. Old records
may remain readable with old local keys until the app finishes re-encryption.
Daochi does not delete old keys, distribute new keys, or infer rotation status;
that policy belongs to the account and app.

## Test Vector Shape

Every app adopting this profile should publish at least one test vector with:

- plaintext JSON;
- account ID, app ID, collection, record ID, schema, and key ID;
- 32-byte content key;
- 24-byte nonce;
- final envelope JSON.

The vector should be small enough to paste into a client unit test and should
prove that AAD changes cause decryption failure.

## Server Boundary

Daochi may index record metadata and expose public or social projections by
design, but this profile is for private app records. Anything that should be
server-readable must use a separate public, friends, shared, or legacy surface
with that choice made explicit by the app.


## Optional packed record representation

Protocol v6 uploads may attach `packed_nonce` and `packed_ciphertext` together.
These carry a second, independently encrypted representation of the same JSON;
the identity `nonce` and `ciphertext` remain authoritative. Nodes advertise
`record-gzip-v1` and use the optional representation only for record pages with
`record_encoding:"gzip-v1"`. The optional copy counts toward account storage,
is skipped when it would exceed quota, and is invalidated by identity updates.
It is a local cache: mesh replication and account export retain the identity
copy, so losing the optional copy cannot lose account data.

Before encryption, gzip-v1 is an eight-byte ASCII `DAOGZIP1` marker, a four-byte
little-endian uncompressed length, and one complete gzip stream. The current
client packs structured JSON of at least 512 bytes only when the whole frame
saves at least 64 bytes. Authenticate the envelope and AAD before parsing this
frame. Reject a claimed length above the app's record bound (absolute ceiling
8 MiB), checksum failure, truncation, concatenated streams or trailing bytes.
The uncompressed document and its content hash stay identical to the identity
representation. Media blobs retain their content-addressed encryption.

## HTTP compression and page metadata

The node advertises `http-gzip-v1`, accepts `Content-Encoding: gzip` on JSON
requests, and gzip-encodes sync responses when negotiated by `Accept-Encoding`.
Both compressed wire bytes and decoded JSON must fit the existing request bound.
Transaction body digests cover the decoded JSON bytes, before HTTP compression.
Response `Vary` retains both the origin and encoding selectors.

`record-pages-metadata-v1` permits `include_metadata:true` on a record page.
The terminal page includes account profile/social metadata, capabilities,
package sequence and quota. Intermediate pages retain the saved cursor and do
not advance the account watermark. Older nodes can still use the full sync path.

## One-time legacy reward migration

The separate `/api/v1/rewards/migration` surface imports earned Shovey Classic
progress when upgrading reward validation. At the first upgraded startup, the
node atomically freezes existing canonical encrypted game-progress records. An
immutable marker prevents later uploads or backdated timestamps from replacing
that baseline. The authenticated client opens and validates its frozen record
locally, then submits only its nonce-prefix HChaCha20 subkey, scoped to that
random record version. Account private keys and reusable record keys stay local.

This is an explicit, limited disclosure of the frozen progress document for
reward eligibility, separate from opaque sync. The node authenticates the
original associated data and ciphertext, retains only earned unlocks and
completion marks plus provenance, and discards the opening key and plaintext.
It never invents route evidence or credits Dew during migration. New progress
still requires normal qualifying evidence; normal claims remain once per
account. Frozen snapshots and imported progress are removed on account deletion.
