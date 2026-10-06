# Hosting

A deployment has two parts with different needs:

- Static files (keyrings, catalog, packs, entries): the publisher's build
  output, served byte for byte. Any static host or mirror works; clients
  verify everything.
- Search and discovery: computed per request and signed with the online
  key, so they need a running service holding that key.

## Recommended: kbd as a container on Quave ONE

`kbd` is a small static Go binary (the image is distroless, about 10 MB)
that serves both parts from memory. The recommended deployment is one
container on the Quave ONE container platform.

Image and runtime:

- `Dockerfile` in this repository: static build, `gcr.io/distroless/static`
  base, user 65532, no shell. Run it with a read-only root file system.
- Health check: `GET /healthz` on port 8080 (the image also has
  `kbd health-check` for platforms that run a command).
- Resources: 0.25 CPU and 128 MB of memory are plenty for thousands of
  entries; the index is built in memory at start, in milliseconds.
- Scale out by running more replicas; there is no shared state. Each
  replica has its own in-memory rate limiter.

Configuration by environment (see `cmd/kbd/main.go` for the full list):

| Variable | Value |
|---|---|
| `KBD_FETCH_URL` | the static mirror that holds the signed build (kbd fetches it at start and verifies it before serving) |
| `KBD_NAMESPACES` | `basalt` (comma separated for more) |
| `KBD_DATA` | a small writable volume or tmpfs, for example `/data` (only for the fetched files) |
| `KBD_TRUST_JSON` or `KBD_TRUST` | the pinned keyrings (public) |
| `KBD_DELEGATIONS_JSON` or `KBD_DELEGATIONS` | the delegation of each namespace for the online key (public) |
| `KBD_ONLINE_KEY_JSON` (secret) or `KBD_ONLINE_KEY` | the online private key; the only secret |
| `KBD_RATE`, `KBD_BURST` | per client limit, default 60 per minute, burst 20 |
| `KBD_CLIENT_IP_HEADER` | the header the platform's ingress sets with the client address, for rate limiting only |

Instead of fetching, the build can be mounted read-only at `KBD_DATA`.
A new content release is a restart (or a rolling update) with the new
build; a new online key or delegation is a secret and variable change.

Operational duties:

- Renew the delegation before it expires (at most 90 days; 30 is a good
  rhythm). The publisher signs it offline with `kb delegate`; nothing on
  the server can extend it.
- Rotate the online key on any suspicion; publish a new delegation, and
  the old key stops being accepted when its delegation expires (clients
  check every response).
- Turn off or minimize the ingress access log of the platform for this
  service, or make sure it keeps no client addresses and paths. kbd keeps
  its own promises (no addresses, no query content, aggregate counters
  only), but a proxy in front of it can log what kbd does not. Search is
  a POST, so the query never appears in a URL either way.
- Keep the publisher and root keys off the platform. Only the online key
  lives there; the worst its theft allows is withholding or reordering
  results until the delegation expires.

Static files can be served by the same container (they are part of the
protocol paths) and, for scale and offline mirrors, also from the
distribution's existing package mirror, unchanged.

## Alternative: Cloudflare Workers and R2

The static files on R2 (object storage) behind a custom domain, and a
Worker that answers discovery and search.

- The Worker needs its own implementation of search and signing in
  JavaScript or WebAssembly (the Go server does not run there as is), and
  it must pass the same conformance suite. The online key would be a
  Worker secret.
- The index is loaded from R2 into the Worker on each cold start, or
  precomputed into a compact form; fine for a few thousand entries.
- Cost at list prices at the time of writing (check current pricing):
  Workers Paid at 5 USD per month including 10 million requests; R2 at
  0.015 USD per GB-month of storage with no egress fees and 0.36 USD per
  million read operations. For this data (megabytes) the cost is close to
  the Workers base fee.
- Privacy: Cloudflare terminates TLS and sees every client address and
  request; its logging and analytics settings for the zone decide what is
  kept. Search being a POST keeps the query out of URL logs, but the
  bodies pass through the provider.

## Comparison

| | kbd on Quave ONE | Workers and R2 |
|---|---|---|
| Code | the reference server, conformance tested here | a second implementation to write and keep conformant |
| Cost | one small container | about the Workers base fee |
| Latency | one region, plus any CDN for static files | edge, worldwide |
| Privacy | our process and the platform ingress; ingress logs configurable | the edge provider sees all traffic; zone log settings |
| Secrets | online key as a platform secret | online key as a Worker secret |
| Offline mirrors | static files copy as they are | same |

The container keeps one implementation of the protocol, the one the
conformance suite and the unit tests cover, and keeps the online key and
the request bodies on infrastructure the project controls. Static packs
can still be cached by a CDN or served from the package mirror, since
their integrity does not depend on the host.

## Local and air gapped use

- `kb mcp -bundle DIR -trust trust.json` answers from a verified build
  with no network at all.
- A fleet can run its own `kbd` with the publisher's build and its own
  online key, if the publisher delegates to it, or mirror only the
  static files and use packs (no search).
