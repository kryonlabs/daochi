# Daochi Developer Quickstart

This is the shortest path for a new app to use Daochi without depending on a
server-owned account secret.

## 1. Create an Account Key

Generate an ML-DSA-44 keypair on the client. The account ID is the lowercase
hex SHA-256 hash of the public key bytes.

Keep the private key on the device. The relay receives the public key and
signatures, not the private key.

## 2. Request a Challenge

```sh
curl "$DAOCHI/api/v1/sync/challenge?user_id=$ACCOUNT_ID"
```

The response contains a single-use nonce. Sign the canonical message with the
account private key:

```text
daochi-sync-v1
POST
/api/v1/sync/login
<sha256 hex of exact login body bytes>
<challenge nonce hex>
```

## 3. Login

Post the signed login JSON to receive a bearer token and server time:

```sh
curl -X POST "$DAOCHI/api/v1/sync/login" \
  -H "Content-Type: application/json" \
  -d @login.json
```

Bearer tokens are operational credentials. When one expires or receives `401`,
repeat challenge and login as long as the local account key still exists.

## 4. Register an App Manifest

New apps should use signed manifests:

```sh
curl -X POST "$DAOCHI/api/v1/apps/register-signed" \
  -H "Content-Type: application/json" \
  -d @manifest.json
```

The manifest declares:

- app ID and display metadata;
- active Ed25519 app keys;
- owned collection prefixes;
- capabilities and token policies;
- compatibility windows when needed.

## 5. Write One Encrypted Record

Use the encrypted record profile for the ciphertext envelope, then sync it:

```json
{
  "protocol_version": 6,
  "app_id": "exampleapp",
  "user_id_hash": "account-id",
  "client_id": "example-client-1",
  "encrypted_records": [
    {
      "collection": "private.exampleapp.v1.records",
      "id": "note-1",
      "key_id": "main-2026-09",
      "nonce": "base64url-24-byte-nonce",
      "ciphertext": "base64url-envelope-json"
    }
  ]
}
```

Protocol v6 strict requests also include `X-Daochi-Tx`, signed by the account
key and an active app key.

## 6. Read It Back

Call sync again with the last seen server version. Daochi returns records newer
than that version and does not need to parse the ciphertext.

```sh
curl -X POST "$DAOCHI/api/v1/sync" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Daochi-User: $ACCOUNT_ID" \
  -H "X-Daochi-Since-Version: $SERVER_VERSION" \
  -d @sync.json
```

## 7. Inspect Trust and Sync State

Useful checks while developing:

- `GET /api/v1/apps/{app_id}` for app manifest state;
- `GET /api/v1/apps/{app_id}/collections` for collection ownership;
- `GET /api/v1/sync/diagnostics` for account sync state;
- `GET /api/v1/node` for node identity, protocol bounds, and public usage;
- `GET /openapi.json` for the current API contract.
