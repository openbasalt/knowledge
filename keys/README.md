# Public keyrings

Each namespace's public keyrings live here as `keys/<namespace>/keyring-<n>.json`
(signed envelopes, see [docs/protocol.md](../docs/protocol.md#23-keyrings-roles-and-rotation)).
They hold public keys only. Private keys are never committed.

The release workflow signs with the publisher key from its secret and the
keyrings in this directory, oldest first. A namespace without a keyring
here cannot be released.
