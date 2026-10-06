# Content format and pipeline

Knowledge is written as files in this repository, reviewed by pull
request, and turned by the pipeline into signed entries, packs and a
catalog (the objects of [protocol.md](protocol.md)).

## Layout

```
content/
  <namespace>/
    namespace.yaml
    entries/
      <entry-id>/
        en.md        English: every machine field and the English text
        pt-BR.md     a translation: human text only
```

One directory per entry; the directory name is the entry id (lower case
letters, digits and hyphens, 2 to 64 characters). `en.md` is required;
every other `<lang>.md` must be a language listed in `namespace.yaml`.

## namespace.yaml

```yaml
namespace: basalt
title: {en: Basalt OS knowledge, pt-BR: Conhecimento do Basalt OS}
description: {en: Guides and fixes for most machines., pt-BR: Guias e correções para a maioria das máquinas.}
languages: [en, pt-BR]
license: Apache-2.0
actions: [selinux.fcontext, unit.restart, journal.vacuum, package.install, mok.enroll]
packs:
  - id: nvidia-legacy-580
    applies_to:
      distros: [basalt, fedora]
      hardware:
        - {bus: pci, vendor: "10de", devices: [{from: "1b00", to: "1bff"}]}
    title: {en: NVIDIA 580 legacy driver, pt-BR: Driver legado NVIDIA 580}
    description: {en: Step by step installation for older GPUs., pt-BR: Instalação passo a passo para placas antigas.}
```

- `actions` is the closed list of action identifiers entries of this
  namespace may propose. It should mirror the action set of the clients
  the namespace serves; a client runs only the actions it implements and
  shows the others as text.
- `packs` declares topic packs. Entries without a `pack` go to the `core`
  pack. Every pack needs a title and description in every language.
- Hex ids are quoted in YAML (`"10de"`, `"1380"`) so they stay strings.

## The English file

```markdown
---
id: secure-boot-module-rejected
revision: 1
updated: "2026-10-05"
kind: fix                     # guide, fix or reference
intents: [diagnose, fix.module]
components: [secure_boot, kernel, akmods]
errors: ["kernel:key-rejected", "EKEYREJECTED"]
keywords: [Secure Boot, Key was rejected by service, MOK]
applies_to:
  distros: [basalt, fedora]
  arch: [x86_64, aarch64]
proposals:
  - id: enroll-key
    action: mok.enroll
    params: {certificate: /etc/pki/akmods/certs/public_key.der}
    risk: medium
  - id: reboot
    action: system.reboot
    params: {reason: key-enrollment}
    risk: low
    requires: [enroll-key]
references:
  - title: Linux kernel documentation, kernel module signing
    url: https://docs.kernel.org/admin-guide/module-signing.html
title: A kernel module fails to load with "Key was rejected by service"
summary: One or two sentences a person reads in a list of results.
proposal_text:
  enroll-key: Prepare the enrollment of this machine's signing key.
  reboot: Restart, then confirm the key on the blue enrollment screen.
---
Markdown body: what it means, how to check, how to fix, how to go back.
```

Field rules:

| Field | Rule |
|---|---|
| `revision` | starts at 1; increase it on every change of meaning |
| `updated` | `YYYY-MM-DD`, quoted |
| `intents`, `components` | identifiers: lower case, digits, `_`, dot separated |
| `errors` | codes without spaces; prefer the tool's own code (`EKEYREJECTED`) or `<source>:<code>` (`http:403`, `selinux:avc-denied`) |
| `keywords` | English search terms people and tools use (model names, messages) |
| `applies_to` | the conditions of [protocol.md section 5](protocol.md#5-applicability-conditions); as narrow as the facts allow |
| `proposals` | `id`, `action` from the namespace list, `params` (single values, no commands), `risk` (`low`, `medium`, `high`), optional `requires` (earlier proposal ids) |
| `references` | https sources for the facts |
| `title` (max 120), `summary` (max 400), `proposal_text` | English human text |

## Translations

A translation file holds only human text: `title`, `summary`,
`proposal_text` (the same proposal ids as the English file) and the body.
Any machine field in a translation is a validation error. This is the
i18n rule of the assistants this content serves: identifiers stay English
and stable, people read their own language. A translation keeps every
command, path, package name and number exactly as in English.

A client shows the variant for the person's language, then the base
language (`pt` for `pt-PT`), then English.

## Writing guidance

- Write for people who are not experts: what is wrong, how to check, what
  the fix does, how to go back. Short sentences.
- Never suggest turning off a protection (SELinux, Secure Boot, the
  firewall) as a fix.
- Commands must be safe to copy: no `curl | sh`, placeholders named
  clearly (`MODULE`), a way back for risky steps.
- No text addressed to an assistant or a model, no hidden text, no
  personal data, no internal host names.
- Public text style: no em or en dashes, no bold, no ellipsis.

## Pipeline

```
pull request ──> ci: kb validate, unit tests, sample build with throwaway keys, conformance
             └─> AI review, tier 1 (fast model) ──> maintainer approval ──> merge to main
release pull request or release tag ──> AI review, tier 2 (stronger model, all changes since the last release
                                        plus the whole namespace's consistency)
release tag ──> signed build (publisher key from the release environment) ──> kb verify ──> artifact ──> publish
```

1. `kb validate content/<ns>` checks every rule above: schema of the front
   matter (unknown fields are errors), ids, identifiers, conditions,
   proposals against the namespace's actions, every language having the
   text of every proposal, references being https.
2. The AI review reads the changed entries as data and applies the rules
   in [`.github/review-prompt.md`](../.github/review-prompt.md) (facts,
   sources, conditions, i18n, actions, prompt injection, personal data,
   command safety). It is a required check; see
   [CONTRIBUTING.md](../CONTRIBUTING.md).
3. `kb build` signs every entry, groups entries into packs, writes the
   catalog and copies the keyrings, then loads its own output with the
   same verification a server uses. Builds are reproducible: with the
   same content, key and `SOURCE_DATE_EPOCH`, the output is byte for byte
   the same.
4. `kb verify` checks a build against a trust file; `kbd` refuses to start
   on anything that does not verify.

Build output layout (the URL layout of [protocol.md](protocol.md), served
as is by any static host):

```
<out>/<ns>/keyring.json
<out>/<ns>/keyring/<n>.json
<out>/<ns>/catalog.json
<out>/<ns>/packs/<id>-<version>.json
<out>/<ns>/entries/<id>.json
```

## Keys

Publisher and root keys are made with `kb keygen` (Ed25519, a JSON file
written with mode 0600) and never enter the repository. The public
keyrings of each namespace live in `keys/<namespace>/keyring-<n>.json`.

```sh
kb keygen -out root.key -pub root.pub
kb keygen -out publisher.key -pub publisher.pub
kb keyring -ns basalt -version 1 -root root.pub -publisher publisher.pub -sign root.key -out keyring-1.json
kb build -content content/basalt -key publisher.key -keyring keyring-1.json -version 2026.10.5 -out dist/kb/v0
kb trust -out trust.json keyring-1.json
kb verify -trust trust.json dist/kb/v0/basalt
```

For a server, make an online key and a delegation (at most 90 days):

```sh
kb keygen -out online.key -pub online.pub
kb delegate -ns basalt -key publisher.key -online online.pub -days 30 -out delegations/basalt.json
```

`scripts/sample-bundle.sh OUT` does all of this with throwaway keys for
tests; [`examples/sample`](../examples/sample) is its output.
