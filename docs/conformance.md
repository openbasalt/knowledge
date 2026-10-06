# Conformance

The conformance suite checks that a server implements
[protocol version 0](protocol.md). It talks to the server only over HTTP,
so it applies to any implementation, and it validates every payload it
receives against the JSON schemas in [`schemas/`](../schemas).

## Running it

Against any server, with the trust file of the namespaces it serves:

```sh
kb conformance -url https://knowledge.example.org -trust trust.json
```

Against `kbd` built from this repository's seed content, with throwaway
keys (what CI runs):

```sh
make conformance            # scripts/sample-bundle.sh dist/sample --conformance
go test ./conformance/      # the same suite against kbd's handler in process
```

The suite needs a fixture: a namespace the client trusts, a query that
must find a known entry and suggest a known pack, and a query whose
conditions must exclude that entry. `conformance.BasaltFixture()` fits the
seed content (a GTX 1070, PCI `10de:1b81`, must find `nvidia-legacy-580`;
an RTX 4060, `10de:2882`, must not). Other namespaces pass their own
`conformance.Fixture` from Go.

The suite honors rate limits: a 429 with a `Retry-After` of at most 60
seconds is waited out and retried, so it runs against a server with its
production limits (more slowly).

## Checks

MUST checks fail the run; SHOULD checks are reported.

| Id | Level | What it checks |
|---|---|---|
| `discovery.signed` | MUST | discovery is `application/json`, valid against its schema, signed by the online key under a delegation that the pinned keyring verifies, fresh |
| `discovery.version` | MUST | `versions` lists `0` |
| `discovery.privacy` | MUST | `privacy.service` includes `no-accounts`, `no-cookies`, `no-query-logging`; `privacy.hosting` is a complete statement (declared or not) |
| `discovery.hosting_declared` | SHOULD | the operator declares what the hosting layer logs (`privacy.hosting.declared` is `true`) |
| `search.match` | MUST | the fixture query returns the expected entry first and suggests the expected pack; the response and every entry verify, the nonce and request digest match |
| `search.schema` | MUST | the request and the response follow their schemas; the response has `Cache-Control: no-store` |
| `search.excludes` | MUST | conditions exclude the expected entry for hardware they do not cover |
| `search.free_text_with_consent` | MUST | free text with `consent: question` is accepted |
| `search.free_text_without_consent` | MUST | free text with another consent value gets a signed `free_text_without_consent` error |
| `search.unknown_field` | MUST | a request with an extra field (a machine id) gets a signed `invalid_request` |
| `search.sentence_as_error_code` | MUST | a sentence in `errors` gets a signed `invalid_request` |
| `search.too_large` | MUST | a body over 8 KiB gets 413 `payload_too_large` |
| `search.method` | MUST | GET on search gets 405 `method_not_allowed` |
| `search.media_type` | MUST | a non-JSON body gets 415 `unsupported_media_type` |
| `version.unsupported` | MUST | `/kb/v999/` gets a signed `unsupported_version` listing `0` |
| `namespace.unknown` | MUST | an unknown namespace gets a signed `unknown_namespace` |
| `entry.fetch` | MUST | the expected entry follows its schema and verifies |
| `entry.not_found` | MUST | an unknown entry gets a signed `not_found` |
| `catalog.packs` | MUST | the catalog verifies; every pack follows its schema, matches the catalog's size and digest, and verifies with every entry inside |
| `keyring.current` | MUST | the keyring follows its schema and the client can follow it from the pinned version |
| `ratelimit.headers` | MUST | `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` are present |
| `static.etag` | SHOULD | static files carry an `ETag` and `If-None-Match` gives 304 |

Every check that reads a response also fails if the server sets a cookie.

## What the unit tests add

The suite checks the wire. The repository's tests (`go test -race ./...`)
also check what the wire cannot show:

- the client refuses an edited response, an unsigned response, an edited
  discovery document, an edited entry, a replayed response (other nonce),
  a stale response, a corrupted pack from a mirror, and reports unsigned
  errors as unverified (`client/client_test.go`);
- keyring rotation needs the old and the new root keys, keeps
  revocations, and a revoked publisher verifies nothing
  (`signing/signing_test.go`, `client/client_test.go`);
- the server's log holds no free text, hardware id, entry id or client
  address, the rate limiter keeps no address and rotates its key daily
  (`internal/server`, `internal/ratelimit`);
- builds are reproducible and refuse a key that is not a publisher key
  (`internal/build`);
- the content rules hold for every seed entry (`internal/source`).
