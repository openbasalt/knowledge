# OpenBasalt Knowledge protocol, version 0

Status: draft. Version 0 may still change in incompatible ways; every
change updates this document, the JSON schemas in [`schemas/`](../schemas)
and the conformance suite ([conformance.md](conformance.md)) together.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose and model

The protocol lets an operating system assistant (or any agent) find and
fetch short, reviewed knowledge entries about the machine it runs on: a
driver guide for one GPU family, the fix for a known error, how to free
disk space. It is built for three properties at once:

- Integrity without trusting the transport. Every entry is signed by the
  namespace's publisher; every dynamic answer is signed by a server key the
  publisher delegated. A client verifies everything and refuses anything
  unsigned or mismatched. HTTPS protects privacy; signatures protect
  content.
- Privacy by construction. A query is a small structured object made of
  identifiers (intent, component, hardware ids, package versions, error
  codes). Free text is optional, needs the person's consent, and is never
  logged by the service. There are no accounts, no machine identifiers and
  no cookies. What the hosting layer in front of a server logs (client
  addresses, paths) is stated by its operator in discovery, so clients can
  tell the person before anything is sent.
- Content is data. An entry can propose steps only as identifiers of the
  client's own closed action set. A client validates them with its own
  rules and asks the person before anything changes. Nothing in an entry
  is ever executed by a server or by the protocol.

Parties:

| Party | Role |
|---|---|
| Publisher | Owns a namespace (for example `basalt` or `fedora`), reviews content, signs entries, packs and catalogs with offline keys |
| Server | Serves one or more namespaces over HTTPS, answers searches, signs dynamic responses with an online key delegated by each namespace's publisher |
| Mirror | Serves the publisher's static files unchanged (no search) |
| Client | Pins publisher keyrings, sends minimized queries, verifies every answer |

Namespaces make the protocol distribution neutral: each distribution (or
project) publishes its own namespace with its own keys. A server may host
several namespaces; a client trusts only the namespaces it pinned.

## 2. Signatures

### 2.1 Algorithm

Ed25519 (RFC 8032). Keys are raw 32-byte public keys; signatures are 64
bytes. Verification needs only Go's standard library (`crypto/ed25519`) or
any common crypto library.

A key id is the first 16 bytes of the SHA-256 of the raw public key, as 32
lower case hex digits.

Why Ed25519 and not OpenPGP: OpenPGP verification is not in Go's standard
library (`golang.org/x/crypto/openpgp` is frozen and deprecated) and its
packet format has many options a strict verifier must refuse one by one.
Ed25519 has one key type, deterministic signatures (so builds are
reproducible), small keys and no parsing ambiguity; it is what minisign,
signify, SSH and TUF implementations use. A distribution that already
trusts an OpenPGP release key can carry that trust over: ship the pinned
keyring (section 2.3) inside a package signed with the release key, or
publish a detached OpenPGP signature of the keyring file next to it.

### 2.2 Envelope

Every signed object travels in an envelope with the DSSE v1 layout:

```json
{
  "payloadType": "application/vnd.openbasalt.knowledge.entry+json",
  "payload": "<base64 of the payload bytes>",
  "signatures": [{"keyid": "<32 hex>", "sig": "<base64 of 64 bytes>"}]
}
```

The signature covers the pre-authentication encoding (PAE) of the payload
type and the exact payload bytes:

```
"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

where LEN is the decimal byte length. No JSON canonicalization is needed:
the payload bytes are signed as they are, and a payload can never be
accepted as another type. Base64 is the standard alphabet with padding.

A verifier MUST check the payload type, MUST ignore signatures by keys it
does not trust (so keys can be added before every client knows them),
MUST count each key once, and MUST NOT use any part of the payload before
the signature check passes. The digest of an envelope is
`sha256:<hex>` of its payload bytes.

Payload types:

| Payload type | Signed by | Payload schema |
|---|---|---|
| `application/vnd.openbasalt.knowledge.keyring+json` | root keys | [keyring](../schemas/keyring.schema.json) |
| `application/vnd.openbasalt.knowledge.delegation+json` | a publisher key | [delegation](../schemas/delegation.schema.json) |
| `application/vnd.openbasalt.knowledge.entry+json` | a publisher key | [entry](../schemas/entry.schema.json) |
| `application/vnd.openbasalt.knowledge.pack+json` | a publisher key | [pack](../schemas/pack.schema.json) |
| `application/vnd.openbasalt.knowledge.catalog+json` | a publisher key | [catalog](../schemas/catalog.schema.json) |
| `application/vnd.openbasalt.knowledge.discovery+json` | the online key | [discovery](../schemas/discovery.schema.json) |
| `application/vnd.openbasalt.knowledge.search-response+json` | the online key | [search response](../schemas/search-response.schema.json) |
| `application/vnd.openbasalt.knowledge.error+json` | the online key | [error](../schemas/error.schema.json) |

### 2.3 Keyrings, roles and rotation

Each namespace has a keyring: a versioned list of keys with roles.

- `root` keys sign the next version of the keyring. They are kept offline.
- `publisher` keys sign entries, packs, catalogs and delegations. They are
  kept offline or in the publisher's release pipeline.

```json
{
  "schema": "kb.keyring/v0",
  "namespace": "basalt",
  "version": 2,
  "threshold": 1,
  "keys": [
    {"type": "ed25519-public", "keyid": "<32 hex>", "public": "<base64>", "roles": ["root"]},
    {"type": "ed25519-public", "keyid": "<32 hex>", "public": "<base64>", "roles": ["publisher"],
     "not_after": "2028-01-01T00:00:00Z"}
  ],
  "revoked": ["<32 hex>"]
}
```

A client pins one keyring per namespace (shipped with the system or set by
an administrator); trust comes from where the file is. The pinned file's
own root signatures are still checked so a damaged file is refused.

Rotation follows the root of trust, as in TUF: version N+1 is accepted
only if it is for the same namespace, has a higher version, is signed by
`threshold` root keys of version N and by `threshold` root keys of its own,
and keeps every key id version N revoked. A client that pinned any version
can therefore reach the current one by fetching each version in turn.
Keys may carry `not_before` and `not_after`; a key outside its window, or
revoked, verifies nothing. Publisher keys are checked against the current
time, so content signed by a retired key must be signed again.

### 2.4 Online key delegation

Search results are computed per request, so they cannot be signed offline.
A server holds an online key; each namespace's publisher signs a
delegation for it:

```json
{
  "schema": "kb.delegation/v0",
  "namespace": "basalt",
  "key": {"type": "ed25519-public", "keyid": "<32 hex>", "public": "<base64>"},
  "not_before": "2026-10-01T00:00:00Z",
  "not_after": "2026-10-31T00:00:00Z"
}
```

A client MUST refuse a delegation that is not signed by a publisher key of
the namespace, is not valid at the current time, or lasts longer than 90
days. The online key can sign only discovery documents, search responses
and errors. It can never sign entries, packs or catalogs, so a compromised
server can reorder, omit or withhold results, but cannot change what an
entry says or invent one.

## 3. Transport and versions

HTTPS only (a client MAY allow plain HTTP to a loopback address for
tests). Request and response bodies are `application/json`. All paths of
version 0 start with `/kb/v0/`. A server MUST answer a request under
another version prefix (`/kb/v1/`, `/kb/v999/`) with the error
`unsupported_version` listing `supported_versions`.

Version negotiation: the client reads the discovery document, picks the
highest version listed in `versions` that it also speaks, and uses that
prefix. A server that changes the protocol incompatibly adds a new prefix
and keeps the old one for as long as it lists it.

Servers MUST NOT set cookies, MUST NOT require authentication for any
protocol path, and SHOULD send `Referrer-Policy: no-referrer` and
`X-Content-Type-Options: nosniff`.

## 4. Resources

| Method and path | Answer | Signed by | Cache |
|---|---|---|---|
| `GET /.well-known/openbasalt-knowledge` | discovery | online key | `max-age=60` |
| `GET /kb/v0/{ns}/keyring.json` | latest keyring | root keys | public, short |
| `GET /kb/v0/{ns}/keyring/{n}.json` | keyring version n | root keys | public |
| `GET /kb/v0/{ns}/catalog.json` | pack catalog | publisher | public, short |
| `GET /kb/v0/{ns}/packs/{id}-{version}.json` | one pack | publisher | public, long |
| `GET /kb/v0/{ns}/entries/{id}.json` | one entry | publisher | public, short |
| `POST /kb/v0/{ns}/search` | search response | online key | `no-store` |

Every path except search and discovery is a static file of the
publisher's build output, served byte for byte. A mirror can therefore
serve the same tree from any static host, and a client can fetch entries,
the catalog and packs from a mirror with no discovery and no online key.

Static answers SHOULD carry an `ETag` (the digest of the file) and honor
`If-None-Match` with 304.

### 4.1 Discovery

```json
{
  "schema": "kb.discovery/v0",
  "versions": ["0"],
  "issued_at": "2026-10-05T12:00:00Z",
  "namespaces": [
    {"name": "basalt", "languages": ["en", "pt-BR"],
     "bundle": {"version": "2026.10.5", "digest": "sha256:<hex of the catalog payload>"},
     "keyring_version": 1,
     "delegation": {"payloadType": "application/vnd.openbasalt.knowledge.delegation+json", "payload": "<base64>", "signatures": []}}
  ],
  "limits": {"max_request_bytes": 8192, "max_results": 10,
             "rate_limit": {"requests": 60, "seconds": 60, "burst": 20}},
  "privacy": {
    "service": ["no-accounts", "no-cookies", "no-client-addresses-stored", "no-query-logging", "aggregate-counters-only"],
    "hosting": {"declared": true, "provider": "Quave ONE", "access_logs": true, "retention_days": 30,
                "fields": ["ip", "time", "method", "path", "status", "size"], "query_body_logged": false}
  }
}
```

The client verifies each delegation of a namespace it trusts with that
namespace's keyring, then the discovery envelope with the delegated key,
and checks that `issued_at` is within 5 minutes of its clock. The
`privacy` object is signed with the rest of the document and has two
parts (section 7): `service`, the promises of the server process itself,
and `hosting`, the operator's statement about the hosting layer in front
of it.

### 4.2 Search request

`POST /kb/v0/{ns}/search` with a JSON body
([schema](../schemas/search-request.schema.json)). The request is POST so
that no part of the query appears in URLs, proxy logs or browser history.

```json
{
  "schema": "kb.search.request/v0",
  "namespace": "basalt",
  "distro": "basalt",
  "release": "44",
  "arch": "x86_64",
  "intent": "driver.install",
  "component": "nvidia",
  "hardware": [{"bus": "pci", "vendor": "10de", "device": "1b81"}],
  "packages": [{"name": "kernel", "version": "6.17.1-200.fc44"}],
  "errors": ["EKEYREJECTED"],
  "lang": "pt-BR",
  "free_text": {"text": "video stopped after the update", "consent": "question"},
  "limit": 5,
  "nonce": "<16 to 32 random bytes, base64url without padding>"
}
```

| Field | Rule |
|---|---|
| `namespace` | required, must equal `{ns}` in the path |
| `distro`, `release`, `arch` | optional; `/etc/os-release` `ID` and `VERSION_ID`, the machine architecture |
| `intent`, `component` | optional identifiers: lower case, digits, `_`, dot separated (`driver.install`) |
| `hardware` | at most 8; bus `pci` or `usb`, vendor and device as four lower case hex digits |
| `packages` | at most 16; name and version (no spaces) |
| `errors` | at most 8 error codes, no spaces (`EKEYREJECTED`, `http:403`, `selinux:avc-denied`) |
| `lang` | optional language tag (`en`, `pt-BR`) |
| `free_text` | optional; at most 280 characters; `consent` MUST be `question` or `topic` |
| `limit` | 1 to 10 (0 or absent: 5) |
| `nonce` | required, fresh random bytes for every request |

At least one of intent, component, hardware, packages, errors or free
text MUST be present. Unknown fields are an error: a client cannot add a
host name or a machine id by mistake, and a server cannot be asked to
accept one. The formats leave no room for sentences outside `free_text`.

Free text: a client MUST send it only when the person allowed it for this
question (`question`) or for this topic (`topic`), SHOULD remove personal
data it can detect first and show the text before sending, and SHOULD
prefer structured fields. A server
MUST refuse free text without a valid consent value
(`free_text_without_consent`), MUST NOT log or store it, and MAY use it
only to rank results for that request.

### 4.3 Search response

The response is an envelope signed by the online key
([schema](../schemas/search-response.schema.json)):

```json
{
  "schema": "kb.search.response/v0",
  "namespace": "basalt",
  "request_digest": "sha256:<hex of the exact request body bytes>",
  "nonce": "<the request's nonce>",
  "issued_at": "2026-10-05T12:00:01Z",
  "bundle": {"version": "2026.10.5", "digest": "sha256:<catalog payload digest>"},
  "results": [
    {"id": "nvidia-legacy-580", "score": 11.66, "pack": "nvidia-legacy-580",
     "digest": "sha256:<entry payload digest>", "matched": ["text", "intent", "hardware"],
     "entry": {"payloadType": "application/vnd.openbasalt.knowledge.entry+json", "payload": "<base64>", "signatures": []}}
  ],
  "packs": [{"id": "nvidia-legacy-580", "version": "2026.10.5", "digest": "sha256:<pack file digest>"}]
}
```

A client MUST check, before using any result: the online signature and its
delegation; that `request_digest` is the digest of the body it sent and
`nonce` is the nonce it sent (so a response cannot be replayed for another
question); that `issued_at` is within 5 minutes of its clock; and for every
result, that `entry` verifies with a publisher key of the namespace, that
its digest, id and pack equal the result's fields. Human text shown to a
person comes only from the publisher-signed entry, never from the
server's own fields.

`packs` lists packs whose conditions match the query positively
(hardware or packages) or that hold a result. It is a suggestion; the
client decides on the machine (section 6).

### 4.4 Entries

An entry ([schema](../schemas/entry.schema.json); the source format is in
[content.md](content.md)) holds: id, revision, update date, pack, kind
(`guide`, `fix`, `reference`), intents, components, error codes,
keywords, the conditions where it applies (`applies_to`), proposals,
references, license, and one text variant per language (title, summary,
Markdown body and the text of each proposal). Machine fields are English
identifiers; human text is per language.

A proposal is an action of the client's closed action set:

```json
{"id": "enroll-key", "action": "mok.enroll", "risk": "medium",
 "params": {"certificate": "/etc/pki/akmods/certs/public_key.der"}, "requires": ["install-driver"]}
```

Parameters are single values, never commands. A client runs only actions
it implements, through its own validators and the person's confirmation;
a proposal with an unknown action is shown as text and nothing runs for
it. Commands inside the Markdown body are documentation for people and
MUST NOT be executed by a client.

### 4.5 Packs and the catalog

A pack is a signed set of entries for offline use: the `core` pack holds
what every machine of the namespace may need; topic packs hold niche
content (one GPU family, one service). The catalog
([schema](../schemas/catalog.schema.json)) lists every pack with its
version, path, size, the SHA-256 of the pack file, the number of entries,
the machine conditions and a title and description per language.

A client downloads a pack only with the person's permission, then checks
the file's size and digest against the verified catalog, the pack's own
signature, and every entry inside it. Packs are plain data files over
HTTPS; the download carries no query, no account and no machine
identifier, so a mirror learns only that someone fetched that pack.

## 5. Applicability conditions

`applies_to` (on entries and packs) uses these groups; each present group
must hold, and an empty group says nothing:

| Group | Holds when | Unknown when |
|---|---|---|
| `distros` | the `distro` fact is listed | no distro given |
| `releases` | `release` is within `min` and `max` (inclusive, rpm version order) | no release given |
| `arch` | `arch` is listed | no arch given |
| `hardware` | any given device is on the bus, has the vendor and falls in a device range (no ranges: any device of the vendor) | no device given |
| `packages` | a named package's version is in its range | the facts do not name the package |

A group that fails excludes the entry. Unknown groups neither exclude nor
match. Hardware fails when devices are given and none matches, because the
devices a client sends are the ones the question is about. Versions
compare as rpm does (`rpmvercmp`): digit runs numerically, letter runs as
text, `~` before everything, `^` after the base version.

The same rules run on the server (search) and on the client (pack
suggestions from the catalog, computed on the machine without sending
anything).

## 6. Client behavior

A conforming client:

- pins keyrings and follows rotations only through section 2.3;
- refuses unsigned, wrongly signed, stale, replayed or mismatched data,
  and treats an unsigned error as a transport failure;
- sends only the fields the question needs, generates a fresh nonce for
  every request, and sends free text only with consent (section 4.2);
- presents entries as reference data, keeps them away from any
  instruction channel of a language model (delimit them, scan them for
  instructions aimed at assistants), and turns proposals into actions
  only through its closed action set and the person's confirmation;
- asks before downloading a pack, and lets the person see and remove
  installed packs;
- shows the person the server's hosting statement (section 7.2) when it
  asks for permission to search or to download a pack, in plain words:
  whether the host keeps client addresses, for how long, and that the
  question's details are not kept; when the statement is not declared, it
  says that the host may keep the address for an unknown time;
- records what it fetched, when and why, in its own audit log.

## 7. Privacy requirements for servers

A server runs behind a hosting layer (a container platform's ingress, a
load balancer, a CDN) that it does not control. The discovery `privacy`
object keeps the two apart: `service` holds what the server process
promises and enforces itself; `hosting` holds what the operator states
about the layer in front of it. A client shows both to the person.

### 7.1 The service

A conforming server:

- has no accounts and requires no authentication;
- sets no cookies and uses no client fingerprinting;
- does not store client addresses: rate limiting MAY key on the address
  only in memory, through a keyed hash whose key is random and replaced at
  least daily;
- does not log query content: no free text, no field of a search
  request, no entry id from a path; an access log line MAY hold the route
  pattern, the status, the size and the duration;
- keeps only aggregate counters (requests per route, status and
  namespace; empty results; rate limited requests);
- publishes these promises in the discovery `privacy.service` list.

### 7.2 The hosting layer

The operator states what the hosting layer keeps
([schema](../schemas/discovery.schema.json)):

| Field | Meaning |
|---|---|
| `declared` | `false`: the operator states nothing, and clients MUST assume the host may keep client addresses for an unknown time; `true`: the fields below are present |
| `provider` | optional name of the hosting provider |
| `access_logs` | whether the hosting layer keeps access logs |
| `retention_days` | how long they are kept (only with `access_logs: true`) |
| `fields` | what a log line holds, from `ip`, `time`, `method`, `path`, `status`, `size`, `duration`, `host`, `user_agent`, `referer` (only with `access_logs: true`) |
| `query_body_logged` | whether request bodies are kept; search queries travel in the body, so `false` means the question's details are not kept |

The statement is configuration of each deployment, never a default: a
server that was not told what its host does publishes
`{"declared": false}`, not a claim that there are no logs. An operator
MUST NOT declare less than the hosting layer keeps.

What the logged fields reveal: an address with a time tells that a
machine used the service; a path tells which resource was fetched. Search
is a POST to one path per namespace, so its log line holds no part of the
query. A pack, an entry or a keyring is fetched by its path, so a log
line shows which pack or entry was downloaded, like a package mirror's
log shows which package was. Operators who need no record of client
addresses at all choose a host without access logs and declare
`access_logs: false` (see [hosting.md](hosting.md)).

## 8. Rate limits

A server SHOULD limit each client with a token bucket and advertise the
limit in discovery. Every answer of a limited path carries
`RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` and
`RateLimit-Policy` (`<burst>;w=<seconds>`). A limited request gets status
429, the error `rate_limited` with `retry_after`, and a `Retry-After`
header in seconds. Clients SHOULD wait `Retry-After` before retrying.
`/healthz` is not limited and not part of the protocol.

## 9. Errors

Errors are envelopes signed by the online key with this payload
([schema](../schemas/error.schema.json)):

```json
{"schema": "kb.error/v0", "code": "invalid_request", "message": "error codes are identifiers without spaces"}
```

| Code | Status | Meaning |
|---|---|---|
| `invalid_request` | 400 | the body does not follow the request schema, or the namespace differs from the path |
| `free_text_without_consent` | 400 | `free_text` without `consent` `question` or `topic` |
| `payload_too_large` | 413 | body over `max_request_bytes` |
| `unsupported_media_type` | 415 | search body not `application/json` |
| `method_not_allowed` | 405 | search is POST only |
| `unknown_namespace` | 404 | the server does not serve the namespace |
| `not_found` | 404 | no such entry, pack or keyring version |
| `unsupported_version` | 404 | unknown version prefix; `supported_versions` lists the ones served |
| `rate_limited` | 429 | wait `retry_after` seconds |
| `internal` | 500 | server failure |

`message` is English text for developers; clients MUST NOT show it as
content. An error that does not verify (for example one produced by a
proxy) is only a transport failure.

## 10. MCP binding

The same operations are exposed to agents as a Model Context Protocol
server over stdio (`kb mcp`), with read-only tools:

| Tool | Does |
|---|---|
| `knowledge_search` | the structured search of section 4.2; `free_text` requires `free_text_consent` |
| `knowledge_fetch` | one entry by id, in a language |
| `knowledge_catalog` | the namespace's packs |

The MCP server verifies everything as a client does (remote mode) or reads
a verified local build (offline mode). Entry text is returned inside
delimiters and marked as reference data; proposals are returned as action
identifiers and parameters only.

## 11. Security considerations

- A malicious or compromised server can withhold, reorder or omit
  results, and can learn the structured queries it receives. It cannot
  change or invent entries. Clients that need completeness can download
  packs instead of searching.
- A compromised publisher key can sign false entries; the root keys
  revoke it through a keyring rotation, and every client that updates the
  keyring stops trusting it. Root keys should stay offline, with a
  threshold above one once there are several maintainers.
- Entries may quote commands and may contain text an attacker hopes a
  model will follow. The review pipeline checks for it, and clients must
  still treat entries as untrusted data (section 6).
- Structured queries still reveal something (a GPU model, an error code).
  Clients send only what the question needs, and pack downloads let a
  machine work offline without sending any query.
