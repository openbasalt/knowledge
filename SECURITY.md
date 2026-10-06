# Security policy

OpenBasalt Knowledge promises that clients can verify every piece of
knowledge they receive, that a server cannot change what a publisher
signed, and that a query reveals only what the client chose to send. A way
around any of these is a security problem. Please report it privately and
give us time to fix it before it is disclosed.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/openbasalt/knowledge/security/advisories/new>
(the "Report a vulnerability" button under the Security tab). If you
cannot use GitHub, write to security@openbasalt.org.

Do not open a public issue, pull request or discussion for a security
problem.

Please include what you can of: the version or commit, steps to
reproduce, and what an attacker gains (who the attacker is: a malicious
server, a network attacker, a contributor of content, a mirror), and
whether you want to be credited.

We aim to acknowledge a report within 7 days and to agree on a disclosure
date with you, normally within 90 days of the report or when a fix is
released, whichever comes first.

## Scope

In scope:

- signature verification, keyring rotation and delegation in `signing`,
  `protocol` and `client` (a client accepting something it should refuse);
- the server `kbd`: anything that makes it store or log client addresses
  or query content, serve unverified data, or fall over on crafted input;
- the content pipeline: a way for a pull request to change its own
  review, reach secrets, or get content past validation;
- the MCP server: a way for entry content to escape its delimiters.

Content problems (a wrong fact, an unsafe command in an entry) are not
vulnerabilities in the software; report them as ordinary issues, or
privately if publishing the details would put people at risk.

## Supported versions

Until 1.0, only the latest commit on `main` and the latest release receive
security fixes.
