## What this changes

<!-- One or two sentences. For content: which entries, and why. -->

## Content checklist (skip for code only changes)

- [ ] `kb validate content/<namespace>` passes locally.
- [ ] Every fact has a source in `references` (vendor documentation, a manual page, the project's own docs), and I checked it.
- [ ] `applies_to` is as narrow as the facts allow (distro, release, hardware ids, packages), and I tested the conditions with `kb search`.
- [ ] Machine fields are English identifiers; every language file has the same proposals with human text.
- [ ] Proposals use only actions listed in the namespace's `actions`; commands in the body are shown to people, never run by a client.
- [ ] No text addressed to an assistant or a model, no personal data, no internal hosts.
- [ ] Commands are safe to copy: no `curl | sh`, no disabling SELinux or Secure Boot, a way back is described for risky steps.

## Code checklist (skip for content only changes)

- [ ] `make lint test` passes.
- [ ] Protocol changes update `docs/protocol.md`, the JSON schemas and the conformance suite together.

The AI review (tier 1) runs on this pull request and posts its verdict.
A maintainer approval is required in any case.
