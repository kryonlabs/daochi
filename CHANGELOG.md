# Changelog

## [Unreleased]

- Require SHA-256 wallet RPC Digest authentication and canonical filesystem components for blob and package requests.

- Count daily Wurm check-ins by the node's UTC clock and grant each daily Dew reward once per account.

- Revoke signed-in sessions durably on logout and device revocation, including active sync connections.
- Bind Google Play credits to the purchasing account and recover pending consumption and refunds in the background.
- Enforce storage allowances atomically across mesh imports and preserve paid deposits when wallet results are incomplete.
- Verify complete gameplay evidence before granting new rewards; retain imported legacy progress without treating unverified marks as proof.
