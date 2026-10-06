# Prior art, and why a protocol of our own

The goal: an assistant on a person's machine asks, with permission, for
knowledge that fits that machine (one GPU family, one error code, one
release), gets it signed by the people who reviewed it, can turn it only
into steps of its own closed action set, and reveals as little as
possible about the machine while doing so. Several mature open projects
cover parts of this. None covers the combination, so we define a small
open protocol and reuse libraries and ideas where they fit.

Licenses below are as published by each project at the time of writing;
check the current terms before reusing code or content.

## Offline knowledge archives

Kiwix and the ZIM format (openZIM). Kiwix serves whole wikis and
documentation sites offline from single ZIM files with a built-in
full-text index (Xapian). libzim and kiwix-tools are GPL-3.0; the content
keeps its own license (Wikipedia is CC BY-SA).

- Fits: offline use, compact single-file packages.
- Does not fit: no per-article signatures (integrity comes from the
  download channel), no notion of where an article applies (hardware,
  release, packages), no structured query, no machine-readable steps. A
  ZIM file is a library to browse, not answers to apply.

## Search engines and libraries

| Project | License | Notes |
|---|---|---|
| Meilisearch | MIT for the community edition (some enterprise features under another license) | typo tolerant search server; a separate service to run |
| Typesense | GPL-3.0 | search server; GPL network use would bind a modified server |
| Bleve | Apache-2.0 | Go library, BM25 scoring, analyzers for many languages |
| Tantivy | MIT | Rust library, fast, Lucene-like |
| Xapian | GPL-2.0 or later | C++ library, used by Kiwix |

These are search engines: they rank documents. They have nothing to say
about signed content, conditions, privacy of the query or what a client
may do with a result, which is most of this protocol. A knowledge
namespace holds hundreds to a few thousand short entries, which a short
BM25 over pre-filtered entries handles in microseconds, with
deterministic ranking and no dependency. We keep the index internal
(`internal/index`) so it can move to Bleve (the license and language fit)
if namespaces grow into the hundreds of thousands of entries or need
stemming for many languages.

## Community question and answer

Discourse (GPL-2.0) runs Ask Fedora and many distribution forums; Stack
Exchange sites (content CC BY-SA) hold a large share of Linux answers.

- Fits: real problems and real fixes, community review by votes.
- Does not fit: free text written for people, mixed quality, answers that
  go stale, accounts for every interaction, content licenses that do not
  combine with Apache-2.0 data, and no machine-readable conditions or
  steps. Forum threads are good sources for an entry's author, not
  content to ship.

## Manual pages and tldr

man pages ship with every package (licenses vary by project); tldr-pages
(content CC BY 4.0, many clients under MIT) gives short examples per
command.

- Fits: local, offline, authoritative for one command.
- Does not fit: organized by command, not by problem; nothing about
  hardware or which fix applies. An entry should link the man page of the
  commands it uses, as the seed entries do.

## Wikis

ArchWiki (GNU FDL 1.3 or later) is one of the best Linux references, and
distribution wikis (Fedora, Debian, Gentoo) cover their own systems.

- Fits: depth, breadth, maintained by experienced users.
- Does not fit: written for experts and for one distribution, not signed,
  no conditions, and the FDL does not combine with Apache-2.0 content, so
  entries may reference wiki pages but must not copy them.

## Rule based diagnosis services

Red Hat Insights runs rules over data collected from registered systems.
The rule framework, insights-core, is Apache-2.0; the hosted rule content
and the service need a Red Hat subscription, and the client uploads
collected system data to the service for analysis.

- Fits: the closest idea: known problems, conditions on the machine's
  state, recommendations with remediation.
- Does not fit: the analysis happens on the vendor's side over uploaded
  data, which is the opposite of our privacy model (match on the machine,
  send minimized identifiers only, or download a pack and send nothing),
  and the content is not open.

## Hardware based driver suggestions

Ubuntu's `ubuntu-drivers` and AppStream metadata (`<provides><modalias>`,
used by GNOME Software and KDE Discover) suggest packages by matching the
machine's device modalias patterns on the machine.

- Fits: exactly the local matching we want for packs: the catalog's
  conditions are evaluated on the machine, nothing is sent.
- Difference: they map hardware to packages; we map hardware (and
  releases, packages, error codes) to reviewed guidance with steps. Our
  `hardware` condition uses vendor and device id ranges; modalias patterns
  would fit as another condition kind if a namespace needs them.

## Signing and update security

| Project | License | What we take |
|---|---|---|
| The Update Framework (TUF) | specification CC BY 4.0, implementations Apache-2.0 or MIT | root of trust that rotates by threshold signatures of the old and new root keys; short-lived online keys for dynamic data |
| DSSE (Dead Simple Signing Envelope) | Apache-2.0 | the envelope layout and the pre-authentication encoding, so signed bytes never need JSON canonicalization |
| minisign, signify | ISC | Ed25519 as the only algorithm, small key files |
| Sigstore | Apache-2.0 | not used: keyless signing depends on online identity providers and a transparency log; our clients must verify offline from a pinned keyring |
| OpenPGP | standard (RFC 9580) | not used for the protocol (see [protocol.md section 2.1](protocol.md#21-algorithm)); a distribution can still sign its pinned keyring with its OpenPGP release key |

## Agent tool protocols

The Model Context Protocol (MIT) is how agents call tools. We expose
search and fetch as read-only MCP tools (`kb mcp`) so any agent can use
the service, but MCP is a binding, not the protocol: the signed objects
and the privacy rules are the same over HTTPS and over MCP.

## What we built and what we reuse

Built here:

- the protocol: minimized structured queries, applicability conditions,
  signed entries, packs and catalogs, delegated online keys for dynamic
  answers, privacy requirements, error model, conformance suite;
- the content format and pipeline (Markdown with YAML front matter,
  English identifiers, per-language text);
- `kbd` (server), `kb` (tools, client, MCP server), the Go client library.

Reused:

| Component | License | Use |
|---|---|---|
| Go standard library (`crypto/ed25519`, `net/http`, `log/slog`) | BSD-3-Clause | everything the client library needs |
| go.yaml.in/yaml/v3 | MIT and Apache-2.0 | reading front matter in the content tools (not in the client library) |
| santhosh-tekuri/jsonschema v6 | Apache-2.0 | validating payloads against the JSON schemas in the conformance suite |
| DSSE layout, TUF rotation rules, rpm's version comparison algorithm | as above | reimplemented from their specifications |

The client library (`client`, `signing`, `protocol`) depends only on the
Go standard library, so a distribution can vendor it into its assistant
with no third-party code.
