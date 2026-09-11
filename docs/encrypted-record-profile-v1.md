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
