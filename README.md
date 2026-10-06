# OpenBasalt Knowledge

An open protocol and a small service that let an operating system
assistant find reviewed, signed knowledge about the machine it runs on,
with the person's permission and without giving the machine away.

- Distribution neutral: each distribution or project publishes its own
  namespace (`basalt`, `fedora`, others) with its own keys.
- Signed end to end: every entry is signed by its publisher; every search
  answer by a server key the publisher delegated. Clients verify
  everything and refuse anything else. The transport is not trusted.
- Private by design: queries are structured identifiers (intent,
  component, hardware ids, package versions, error codes); free text only
  with consent; no accounts, no cookies, no machine ids, no query logs.
- Content is data: entries propose steps only as identifiers of the
  client's closed action set, which the client validates and the person
  confirms.
- Offline packs: niche topics (one GPU family, one service) come as signed
  packs a machine downloads once, with permission, and uses offline.

Apache-2.0. Status: protocol version 0, draft.

## Documents

| Document | What it covers |
|---|---|
| [docs/protocol.md](docs/protocol.md) | the protocol: signatures, keyrings and rotation, delegation, search, entries, packs, conditions, privacy, rate limits, errors, MCP binding |
| [schemas/](schemas) | JSON schemas of every message |
| [docs/content.md](docs/content.md) | the content format (Markdown with YAML front matter) and the review, build and signing pipeline |
| [docs/conformance.md](docs/conformance.md) | the conformance suite |
| [docs/integration-basalt.md](docs/integration-basalt.md) | how a system assistant uses it: permission, minimized queries, verification, guard, proposals, ledger |
| [docs/hosting.md](docs/hosting.md) | deployment options |
| [docs/prior-art.md](docs/prior-art.md) | related projects and what we reuse |
| [CONTRIBUTING.md](CONTRIBUTING.md) | adding or changing an entry, the review tiers |

## Components

| Path | What |
|---|---|
| `cmd/kbd` | the server: read-only, verifies its data at start, signs dynamic answers, rate limits without storing addresses, logs no queries |
| `cmd/kb` | the tool: keys and keyrings, `validate`, `build`, `verify`, local and remote search, pack download, `conformance`, `mcp` (stdio MCP server) |
| `cmd/kb-review` | the AI review step of the content pipeline (OpenAI compatible or Anthropic APIs) |
| `client`, `signing`, `protocol` | the Go client library; standard library only |
| `conformance` | the conformance suite, usable against any server |
| `content/basalt` | seed content for the `basalt` namespace, in English and Brazilian Portuguese |
| `examples/sample` | a sample build of the seed content, signed with a throwaway key |

## Quick start

Requires Go (the version in `go.mod`).

```sh
make test                       # unit tests with the race detector
make conformance                # build the seed content with throwaway keys, run kbd, run the suite

go build -o bin/ ./cmd/...
bin/kb validate content/basalt
bin/kb search -bundle examples/sample/kb/v0/basalt -trust examples/sample/trust.json \
  -hw pci:10de:1b81 -intent driver.install -lang pt-BR
```

Use it from an agent (offline, from a verified build):

```json
{ "mcpServers": { "knowledge": { "command": "kb",
  "args": ["mcp", "-bundle", "examples/sample/kb/v0/basalt", "-trust", "examples/sample/trust.json"] } } }
```

The sample's key was thrown away after signing: use it to try things, and
never trust it for anything else.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.
