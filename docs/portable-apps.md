# Signed ZIB delivery

Registered applications may publish portable releases in a node-owned package
directory alongside the database: `DAOCHI_DB.packages/APP_ID/`. These are code
artifacts, separate from account records and sync collections. This does not
change app registration, registry approvals, private-data scopes or tokens.

The read-only endpoints are:

- `GET /api/v1/packages/APP_ID/latest`: signed release metadata, without caching.
- `GET /api/v1/packages/APP_ID/SHA256.zib`: immutable bundle bytes.

Independently versioned applications use release v2:

- `GET /api/v2/packages/APP_ID/latest`: signed metadata with compatibility
  versions, delivery variants and exact dependencies; never cached.
- `GET /api/v2/packages/APP_ID/SHA256.zib`: an immutable signed delivery variant.

Release v2 uses runtime `kryon-app-v1`. It signs `host_api`, `module_api` and
`data_schema`, an ordered list of `module` and optional `standalone` artifacts,
and a sorted list of exact dependency IDs, numeric versions, hashes and sizes.
Each app retains its own version and increasing sequence. Updating a child does
not change the parent release. Signature, registry status and active publisher
key checks apply to the latest descriptor and to archived artifacts alike.
These APIs serve releases; they do not register publishers or grant approval.

To stage this format, pass `--format-version 2`, `--host-api N` and
`--module-api N` to `scripts/stage-zib-release.py`. Add `--standalone FILE`
for a separate standalone artifact and `--dependency RELEASE.json` for each
exact module dependency. The importer locks publication per app, rejects
version/sequence rollback and publishes immutable artifacts before updating
`latest-v2.json`. The node verifies the registered publisher when serving them.

Each release has `app_id`, positive monotonically increasing `sequence`,
`version`, `runtime`, lowercase `sha256`, `size`, `key_id` and hexadecimal
`signature`. The signature is Ed25519 over these UTF-8 bytes, with a trailing
newline after every field:

```text
daochi-zib-release-v1
APP_ID
SEQUENCE
VERSION
RUNTIME
SHA256
SIZE
KEY_ID
```

The current runtime contract is `kryon-desktop-v1`. Publishers must verify that
their exported application runs in the reusable Kryon player before staging
a release. A bundle containing unsupported native services is not a portable
release merely because it has a `.zib` extension.

The node verifies the publisher against the application's active registered
Ed25519 key and rejects suspended apps, expired manifests/keys, invalid
signatures and hash/size mismatches. Keep older bundle files and their
`SHA256.zib.json` metadata so a client that read an earlier release can finish
its download while a newer release is published. Revoking a key also prevents
its archived files from being served.

On the node, stage a previously verified bundle using an app-owned release key:

```sh
python3 scripts/stage-zib-release.py --store PATH_TO_DB.packages \
  --app APP_ID --key-id KEY_ID --key PRIVATE_ED25519_PEM \
  --sequence SEQUENCE --version VERSION APP.zib
```

The helper reads the signing key directly, never logs it, retains immutable
previous files, and publishes `latest.json` last through atomic renames and
filesystem syncs. The key must already be registered with the node. Staging
does not register an app or grant a new publishing approval. Live package
publication and node deployment are operational actions separate from these
code and fixture checks. Packages are not yet replicated through the mesh.
