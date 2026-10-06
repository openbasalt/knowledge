# Integrating a system assistant (Basalt OS as the example)

This is how an operating system assistant uses OpenBasalt Knowledge. It
is written for the Basalt OS assistant, whose design (a deterministic
guard, typed proposals from a closed action set, confirmation before any
change, an audit ledger) the protocol was shaped around, but the same
steps apply to any assistant. Nothing here changes how the assistant
works offline: local knowledge keeps answering, and the remote service is
an addition the person controls.

## Overview

```
question or system event
  -> local knowledge first (the core index shipped with the system, installed packs)
  -> not enough? ask the person: search remotely for this question / this topic / no
  -> build a minimized query (identifiers only; free text only with consent, scrubbed)
  -> client library: send, verify every signature, nonce, digest and time
  -> guard: entries are untrusted data (scan, delimit, strip, never instructions)
  -> proposals: map action ids to the closed action set, validate, show, confirm
  -> ledger: what was asked (as identifiers), what came back, what the person decided
```

## 1. Permission first

The assistant never searches remotely on its own.

- When local knowledge has no confident answer, the assistant asks, in the
  person's language: "I can look this up in the Basalt OS knowledge
  service. It will send: your GPU model id (10de:1b81), your release (44)
  and the error code EKEYREJECTED. Nothing else. The service keeps none of
  it. The server's host keeps your IP address and the time for 30 days;
  your question's details are not kept. Search?" with three choices: this
  question only, always for this topic, or no.
- The hosting sentence comes from the signed discovery document
  (`privacy.hosting`, protocol section 7.2), not from text built into the
  assistant, so it is right for whichever server is configured. When the
  server declares no access logs the sentence says so; when it declares
  nothing, the assistant says "The server's host may keep your IP address;
  it did not say for how long." The client library's
  `Hosting.KeepsAddresses` and `Hosting.LogsQueryBody` give the facts to
  phrase. A host that keeps request bodies (`query_body_logged: true`)
  keeps the question as well, and the prompt says so.
- "Always for this topic" is stored per topic (the intent and component,
  for example `driver.install` + `nvidia`) and shown in Settings, where the
  person can review and remove each permission, and turn remote search
  off entirely.
- Administrators can set a policy for a fleet: allow, deny, or point the
  client at an internal mirror or server (a namespace's static files can
  be mirrored as they are).
- Detected conditions work the same way: the assistant matches the pack
  catalog locally (the catalog is a small signed file fetched with the
  system's package metadata or once a day, with no query attached). When
  the machine matches a pack it says so and asks before downloading: "There
  is a guide for your GTX 1070 (NVIDIA 580 legacy driver, 22 KB). The
  server's host keeps your IP address for 30 days and can see which guide
  was downloaded. Download it?" A downloaded pack works offline and answers
  locally from then on.
- A permission given under one hosting statement is asked again when the
  statement changes to keep more (logs where there were none, a longer
  retention, more fields, request bodies).

## 2. The minimized query

The query is built from the assistant's own structured findings, not from
the conversation:

| Field | Source |
|---|---|
| `distro`, `release`, `arch` | `/etc/os-release`, the running architecture |
| `intent`, `component` | the decision layer's goal (`diagnose` + `nginx`, `driver.install` + `nvidia`) |
| `hardware` | only the devices the question is about (the GPU for a GPU question), as PCI or USB vendor and device ids |
| `packages` | only the packages involved, with versions |
| `errors` | codes the diagnosers extracted (`EKEYREJECTED`, `selinux:avc-denied`) |
| `lang` | the person's language |
| `free_text` | only if the person allowed it for this question or topic, after the assistant's personal data scrubbing (host names, user names, addresses, anything shaped like a secret), and shown to the person before sending |

Never sent: host names, user names, serial numbers, MAC addresses, disk
ids, IP addresses, file contents, journal lines, or any stable machine
identifier. Each request has a fresh random nonce, so requests cannot be
linked by the protocol itself.

The network path follows the assistant's existing rules: the confined
daemon has no network access, so the search runs from the component that
already may reach the network on the person's behalf (the person's
session, or a small helper with an allowlist entry for the knowledge
server), and the request is visible as leaving the machine.

## 3. Verification

The assistant embeds the Go client library (`client`, `signing`,
`protocol`; standard library only) and ships the pinned keyring of the
`basalt` namespace inside a package signed with the distribution's release
key. The library refuses, and the assistant then answers from local
knowledge only, when:

- a signature is missing or does not verify with the pinned keyring (or a
  rotation it signed);
- the server's online key is not delegated by the namespace's publisher,
  or the delegation expired;
- the response is for another request (nonce or request digest) or its
  time is off by more than 5 minutes;
- a downloaded pack does not match the catalog's size and digest.

Unsigned errors are treated as network failures. The assistant's audit
record names the reason.

## 4. Through the guard

Signed is not the same as safe to follow. Entry text goes through the
assistant's guard exactly like other untrusted content (web pages,
documents):

- scan for text addressed to an assistant, hidden or invisible
  characters, look-alike letters and exfiltration links; a finding is
  shown to the person and the entry is not used for automatic steps;
- clean before any language model sees it: invisible characters removed,
  links replaced by a host marker, the text placed inside delimiters and
  labeled as reference data;
- check any model output that summarizes an entry before it is shown or
  spoken (no commands, links or markup the facts do not hold).

The body's commands are shown to the person as documentation, in their
own block, never run by the assistant.

## 5. Proposals

An entry's proposals are action identifiers with parameters. The
assistant:

1. maps each `action` to its closed action set; an action it does not
   implement becomes a plain text step ("do this yourself") and nothing
   runs for it;
2. runs the action's own validator on the parameters (a path under the
   allowed prefixes, a package from an allowed repository, a size within
   limits); a failing parameter drops the proposal and is recorded;
3. builds a normal proposal from them, marked with the entry as its
   source and always for review (never the automatic path), with the
   exact commands rebuilt from the typed actions, the risk, the undo
   (snapshot before and after), and the human text from the entry in the
   person's language;
4. applies it only after the person's confirmation, like any other
   proposal.

Proposal order follows `requires`. High risk steps (a driver
installation) always show the way back first.

## 6. Ledger

Every remote interaction is recorded in the assistant's audit log, in
English and machine-readable:

| Record | Holds |
|---|---|
| `knowledge.permission` | topic, scope (question, topic, denied), who decided |
| `knowledge.search` | server, namespace, the structured query fields (never free text; only whether free text was sent), the hosting statement shown to the person, result ids and digests, bundle version, verification outcome |
| `knowledge.pack` | pack id, version, digest, size, from where, verification outcome; install or removal |
| `knowledge.proposal` | entry id and revision behind a proposal, the proposal id, what the guard found |

With these records a person or an administrator can see what left the
machine and why each suggestion was made.

## 7. Packs

Installed packs live next to the core index in a read-only data
directory, each with its verified file. At load the assistant checks the
signature again (keys may have rotated) and drops packs that no longer
verify. Removing a pack in Settings deletes its file and is recorded.
Packs never contain executable content, only entries.

## 8. Rollout

1. Read only: verified search and fetch shown as reference text, no
   proposals from remote entries.
2. Packs with local catalog matching and the download permission.
3. Proposals from entries for the actions the assistant already has
   (SELinux labels, unit restarts, journal and cache cleanup), always for
   review.
4. Driver actions (repository enablement, package installation, key
   enrollment, restart) once the assistant implements them with their
   validators and snapshots.
