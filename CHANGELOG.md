# Changelog

## [Unreleased]

- Accept full Lumi developer reports up to 32 KiB of UTF-8 text without truncation, preserving account privacy and retry identity.

- Refuse an account backup upload unless it holds only the nonce and sealed bytes after its header, so a plain key can't be stored as a backup.

- Accept Sign in with Google tokens from the Waozi web client on the production node.

- Answer an empty Monero deposit list as an empty array, so the Dew site no longer says the node is not answering for accounts without deposits.

- Keep a password-sealed account backup the node cannot open, released for a login proof; unknown accounts get the same answer as wrong passwords.

- Store passkey-sealed account copies the node can't open, and find an account from a linked Google account when a node sets `DAOCHI_GOOGLE_SIGNIN_CLIENT_IDS`.

- Add Shovey Island as an account unlock with a confirmed Dew price, a 40% launch offer and purchase restoration across devices.

- Require SHA-256 wallet RPC Digest authentication and canonical filesystem components for blob and package requests.

- Count daily Wurm check-ins by the node's UTC clock and grant each daily Dew reward once per account.

- Revoke signed-in sessions durably on logout and device revocation, including active sync connections.
- Bind Google Play credits to the purchasing account and recover pending consumption and refunds in the background.
- Enforce storage allowances atomically across mesh imports and preserve paid deposits when wallet results are incomplete.
- Verify complete gameplay evidence before granting new rewards; retain imported legacy progress without treating unverified marks as proof.
