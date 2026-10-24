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
- Blobs are `PUT`/`GET /api/v1/blobs/entity/<address>`. Any active app of the
  account signs the transaction with its own app ID and device key; the blob
  belongs to the account, not to that app.
- Everything is private by default. Sharing stays an explicit step: a
  publication, a friends collection or an app grant.

## Keys

All keys come from the account private key (the ML-DSA-44 secret key bytes),
so every app of the account derives the same ones:

- record key of kind `K`: `HMAC-SHA256(account_private_key, "daochi-entity-v1/records/" + K)`,
  with record `key_id` `entity-v1`;
- blob key of kind `K` for content hash `H`:
  `HMAC-SHA256(HMAC-SHA256(account_private_key, "daochi-entity-v1/blobs/" + K), H)`.

Records use the [encrypted record profile](encrypted-record-profile-v1.md)
with `app_id` `entity` in the associated data. A blob is
ChaCha20-Poly1305 of the plain bytes with its blob key, a zero nonce and the
associated data `daochi-entity-v1/blob/` + `K`; its address is the SHA-256 of
the sealed bytes. Because the key belongs to the content, the same photo always
seals to the same blob, and the node stores it once.

## Kinds

`private.entity.v1.photos`: one record per photo, with record ID `H`, the
lowercase SHA-256 of the original bytes, and schema `entity.photo.v1`:

```json
{"hash": "H", "size": 123456, "type": "image/jpeg", "taken_at": 1792800000,
 "width": 4032, "height": 3024, "blob": "sealed address", "blob_size": 123472,
 "preview": "sealed address of the preview, optional", "added_at": 1792800500}
```

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
data:

1. Read the old copy (Diary photo blob, Inbe media library record, Photos app
   media record, Shovey draft).
2. Write the entity record and blob. If the record for that hash already
   exists, keep it and only add missing fields.
3. Point the old entry at the entity record (for example Diary's
   `{"photo": "H"}`).
4. Delete the old copy only after the node confirmed the entity record and
   blob.

Older app releases can still read their old collections through 2027-10-24.
After that the old collections and blobs may be removed.
