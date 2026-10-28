# Premium usernames

Usernames (account aliases) accept **4–32 characters** from `a-z`, `0-9` and
`_`. Whitespace and a leading `@` are removed and letters become lowercase.

The Waozi public node enables `DAOCHI_PREMIUM_ALIASES_ENABLED=true` through
`deploy/node.env`. Other nodes keep free claims unless their operator enables
the policy. Prices are one-time DEW charges for a new claim:

- Any four-character username: 100 DEW.
- A listed common given name or word: 250 DEW.
- A listed brand or product name: 1,000 DEW.

The highest matching tier wins. This includes four-character names containing
digits or underscores. Other names remain free. Only exact normalized catalog
matches qualify: `google` is premium, while `google_fan` is free. A purchase
does not verify brand affiliation or grant rights to a trademark.

**Existing usernames are untouched.** Enabling the policy does not change any
account, take a username away, or create a debit. An account may keep or set
its current username again for free, including a grandfathered short username.
Names held by another account cannot be bought. Renaming releases the old name;
a later claim of an available premium name is a new purchase. Names are not
reserved forever for accounts that once used them.

## Catalog

`alias_catalog.zi` is the reviewed, deterministic catalog; the node does not
fetch a changing list during a claim. Its initial selection uses the first
50 male and female given names in the US Social Security Administration's
[1926–2025 names](https://www.ssa.gov/OACT/babynames/decades/century.html),
excluding names shorter than four characters, plus common international names.
Recognizable brands are informed by
[Kantar BrandZ](https://www.kantar.com/Campaigns/BrandZ/Global), with additional
software, service and Waozi ecosystem names. The remaining words are a curated
selection of desirable handles. This is a seed catalog, not a claim of a global
username popularity ranking. Catalog changes never alter current ownership.

## Quote and purchase API

`GET /api/v1/account/alias?alias=google` requires the account bearer. It returns
`alias`, `enabled`, `available`, `owned`, `premium`, `category`, `price_units`,
`units_per_dew`, `minimum_length` and `maximum_length`. One DEW is 1,000,000
integer ledger units. A quote for the caller's current name costs zero. An
unavailable name may show its catalog price but cannot be purchased. Quotes
do not reserve a name. All responses use `Cache-Control: private, no-store`.

After showing the quote and receiving the user's purchase confirmation, send
`POST /api/v1/account/alias/purchase` with the same bearer:

```json
{"alias":"google","price_units":1000000000,"request_id":"persistent-claim-0001"}
```

The price must match the server's current price; `request_id` must contain
8–128 characters from letters, digits, `.`, `_`, `:` or `-`. A successful
purchase returns `alias`, `price_units` and a signed ledger `receipt_id`.
The account's alias, signed DEW debit and retry record commit in one SQLite
transaction. The receipt uses `app_id=entity`, `source_type=username` and the
name as `source_ref`, so it appears in the account's DEW activity.

Retry an uncertain paid purchase with the exact same request ID, name and price:
it returns the original receipt without another debit. Reusing a paid request
ID for another name or price returns 409. Retrying a purchase after a subsequent
rename also returns 409 and cannot restore the earlier name. A failed purchase
leaves both the old username and balance intact.

The existing `POST /api/v1/account/alias` remains the free-claim API. On nodes
with this policy it refuses new premium claims with 402 and never debits DEW,
even if a client adds purchase fields. Existing apps must add the quote and
explicit purchase flow to sell premium names. Standard free names and keeping
the current name continue to work through that API.

Invalid input returns 400, missing authentication 401, missing account 404,
insufficient DEW or an unconfirmed premium claim 402, an unavailable name,
changed price or conflicting retry 409, and service/issuer failures 503.
`GET /api/v1/node` advertises `premium-usernames-v1` only on enabled nodes.
