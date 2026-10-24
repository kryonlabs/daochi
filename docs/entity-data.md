# Entity data

An account keeps one private copy of each thing it owns, such as a photo or a
game level, no matter which app created it or which apps show it. Diary and
Photos show the same photo record; Shovey's editor on the phone and on the
desktop edit the same level record. No app keeps a copy of its own.

Every node registers `entity` as a built-in app. Its collections are
`private.entity.v1.<kind>`, and its blobs live at `/api/v1/blobs/entity/`.

## Access

- Any app of the account may write entity records, but only in a protocol v6
  sync request, which the account key signs. A bearer token alone cannot
  write them; an unsigned request is refused with `entity records need a
  signed request`.
- The request names the writing app's own `app_id`. Writing entity records
  never opens another app's collections.
- Entity records arrive in the account's normal sync replies.
- Blobs are `PUT`/`GET`/`DELETE /api/v1/blobs/entity/<address>`. Any active
  app of the account signs the transaction with its own app ID and device key;
  the blob belongs to the account, not to that app. `DELETE` also works on an
  app's own blobs, stops them counting toward the account's storage and
  succeeds again for a blob already gone.
- Everything is private by default. Sharing stays an explicit step: a
  publication, a friends collection or an app grant.

## Keys

All keys come from the account private key (the ML-DSA-44 secret key bytes),
so every app of the account derives the same ones:

- record key of kind `K`: `HMAC-SHA256(account_private_key, "daochi-entity-v1/records/" + K)`,
  with record `key_id` `entity-v1`;
- content key of kind `K` for content hash `H`, the lowercase SHA-256 hex of
  the whole plain content:
  `HMAC-SHA256(HMAC-SHA256(account_private_key, "daochi-entity-v1/blobs/" + K), H)`;
- chunk key of chunk `i` (decimal, from 0): `HMAC-SHA256(content key, "chunk/" + i)`.

Records use the [encrypted record profile](encrypted-record-profile-v1.md)
(`daochi-record-v1`, XChaCha20-Poly1305 with a fresh 24-byte nonce) with the
record key of their kind and key ID `entity-v1`. The associated data is
`{"account_id": <the account's user_id_hash>, "app_id": "entity", "collection",
"id", "schema"}`. In the sync request, `ciphertext` is the envelope JSON and
`nonce` the nonce, both base64url without padding, and `key_id` is `entity-v1`.

Content is cut into chunks of 8 MiB (8388608 bytes); only the last chunk is
shorter. Chunk `i` is ChaCha20-Poly1305 of its plain bytes with its chunk key,
a zero nonce and the associated data `daochi-entity-v1/blob/` + `K` + `/` + `i`.
Its address is the SHA-256 of the sealed bytes, so every sealed chunk stays
below the node's 16 MiB blob limit. A reader opens every chunk in order and
checks the SHA-256 of the joined plain bytes against `H`. Because the keys
belong to the content, the same photo always seals to the same chunks, and the
node stores them once. DaochiClient's `entity.zi` implements these rules.

## Kinds

`private.entity.v1.photos`: one record per photo, with record ID `H`, the
lowercase SHA-256 of the original bytes, and schema `entity.photo.v1`:

```json
{"hash": "H", "size": 123456, "type": "image/jpeg", "taken_at": 1792800000,
 "width": 4032, "height": 3024,
 "blobs": [{"address": "sealed chunk address", "size": 123472}],
 "preview": {"hash": "SHA-256 of the preview", "size": 20480, "type": "image/jpeg",
             "blobs": [{"address": "sealed chunk address", "size": 20496}]},
 "added_at": 1792800500}
```

`size` is the plain size of the whole content; each `blobs` entry gives one
chunk's address and sealed size, in chunk order. The preview is content of its
own under kind `photos`, keyed by its own hash. Optional fields that apps keep
when they know them: `name` (original file name), `trashed` (true while in the
trash), `day` (capture day `YYYY-MM-DD` on the camera's clock), `taken`
(capture time as local ISO 8601 with its offset) and `capture` (true when the
camera recorded the date). Readers keep fields they do not know when they write
a record back.

Albums are `private.entity.v1.albums` records that list photo hashes. A Diary
entry names a photo by its hash, `{"photo": "H"}`, and never stores the bytes.

`private.entity.v1.levels`: one record per level collection, with a random
128-bit hexadecimal record ID chosen when it is created and schema
`entity.levels.v1`. The plain text is the `shovey-levels-1` collection
document (`format`, `edition`, `title`, `levels`) plus `updated_at`. Editor
drafts are saved here, so they follow the account to every device. Publishing
a collection is still the separate publications request.

New kinds use the next free name under `private.entity.v1.` and document their
schema here first.

## Moving existing data

Each app moves its own copies the first time it runs a release with entity
data, one item at a time so the node never needs room for a second copy of
the whole library:

1. Read the old copy (Diary photo blob, Inbe media library record, Photos app
   media record, Shovey draft).
2. Write the entity chunks and record. If the record for that hash already
   exists, keep it and only add missing fields.
3. Point the old entry at the entity record (for example Diary's
   `{"photo": "H"}`).
4. After the node confirmed the entity record and chunks, delete the old
   blobs with `DELETE` and tombstone the old record.

All of an account's apps use the account's one key, so they all derive the
same entity keys and see the same records.

Older app releases can still read their old collections through 2027-10-24.
After that the old collections and blobs may be removed.
