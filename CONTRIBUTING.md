# Contributing

Thank you for helping. Contributions come by pull request only; nothing is
pushed to `main` directly. Every pull request needs the checks below to
pass and a maintainer's approval.

## Adding or changing an entry

1. Read [docs/content.md](docs/content.md) (format and rules) and the
   review rules in [.github/review-prompt.md](.github/review-prompt.md).
2. Create or edit `content/<namespace>/entries/<id>/en.md`, then the
   translations (`pt-BR.md` and others listed in `namespace.yaml`). Machine
   fields go only in `en.md`; translations carry only human text.
3. Check it locally:

   ```sh
   go run ./cmd/kb validate content/basalt
   make sample
   go run ./cmd/kb search -bundle dist/sample/kb/v0/basalt -trust dist/sample/trust.json -hw pci:10de:1b81 -intent driver.install
   ```

   Try queries that should find your entry and queries whose conditions
   should exclude it.
4. Open a pull request and fill in the checklist.

What reviewers look for, in short: facts with sources, conditions as
narrow as the facts, translations that keep every command and value,
proposals only from the namespace's action list with plain parameters,
no text aimed at assistants or models, no personal data, commands that
are safe to copy and a way back for risky steps.

Content is licensed Apache-2.0 like the code. Write it yourself or from
sources whose license allows it; reference wikis and forums, do not copy
them.

## Changing code

```sh
make lint test conformance
```

A change to the protocol updates `docs/protocol.md`, the JSON schemas in
`schemas/` and the conformance suite in the same pull request. The client
library (`client`, `signing`, `protocol`) stays on the Go standard
library.

## Review tiers

Content is reviewed by people and by AI, in two tiers. The AI reads
content strictly as data: entries are placed inside delimiters, nothing in
them is run, and text in them that addresses a model is itself a finding.

Tier 1, every pull request that changes `content/`:

- `cmd/kb-review` with a fast model reviews the changed entries against
  `.github/review-prompt.md` and posts a comment with a verdict per entry
  and the findings (rule, severity, file).
- It sets the commit status `knowledge/ai-review`, which is required. It
  fails on any blocker, and also when the answer cannot be parsed.
- The tool and the rules come from the base branch, never from the pull
  request, so a pull request cannot change its own review.
- A failing AI review can be wrong. Explain in the pull request; a
  maintainer decides, and fixes the rules if they need it.

Tier 2, before a release:

- On a release pull request to `main` (label `release`), on a `release-*`
  tag, or by hand, a stronger model re-reviews every entry changed since
  the last release tag and a consistency overview of each whole namespace
  (contradictions, duplicates, conditions against the catalog).
- The signed build of a release tag runs only after tier 2 passes.

Pull requests from forks: GitHub does not give secrets to workflows of
pull requests from forks, so tier 1 cannot run there by itself. A
maintainer reads the change and adds the `ai-review` label; the
`content-review-fork` workflow then reviews the pull request's files as
data (it builds the tool from the base branch and never builds or runs
anything from the fork) and removes the label. New commits need the label
again.

## For maintainers: setup

Repository secrets (Settings, Secrets and variables, Actions):

| Secret | Used by |
|---|---|
| `OPENAI_API_KEY` | tier 1 and tier 2 with the `openai` provider |
| `ANTHROPIC_API_KEY` | tier 1 and tier 2 with the `anthropic` provider |
| `KB_PUBLISHER_KEY` | the signed build of a release (the content of a `kb keygen` key file); store it in the `release` environment with required reviewers |

Repository variables:

| Variable | Default | Meaning |
|---|---|---|
| `KB_REVIEW_PROVIDER` | `openai` | `openai` (any OpenAI compatible Chat Completions API) or `anthropic` (Messages API) |
| `KB_REVIEW_MODEL_PR` | `gpt-6-luna` | the tier 1 model: fast and inexpensive |
| `KB_REVIEW_MODEL_RELEASE` | none | the tier 2 model: a stronger one. Until it is set, tier 2 fails with a message saying so |
| `KB_REVIEW_BASE_URL` | the provider's API | another OpenAI compatible endpoint, if wanted |

Branch protection for `main`: require pull requests, one approval from a
code owner, the `ci` check and the `knowledge/ai-review` status; no force
pushes. Create the labels `ai-review` and `release`.

Never run the review workflows locally with real keys. To see what the
model would receive, use `go run ./cmd/kb-review -dry-run -changed FILE`.

Keys: root and publisher keys are created offline with `kb keygen` and
never committed (`*.key` is ignored). The public keyrings live in
`keys/<namespace>/keyring-<n>.json`; changing them follows
[docs/protocol.md section 2.3](docs/protocol.md#23-keyrings-roles-and-rotation).

## Conduct

This project follows the OpenBasalt [code of conduct](CODE_OF_CONDUCT.md).
