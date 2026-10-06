# Sample build

The seed content of `content/basalt` built by `scripts/sample-bundle.sh`
with throwaway keys. The private keys were deleted right after signing, so
nobody can sign anything else with them: use this sample to try the tools
and the format, and never pin its keyring for real use.

| Path | What |
|---|---|
| `kb/v0/basalt/` | the build output, laid out as the protocol's URL paths |
| `kb/v0/basalt/packs/nvidia-legacy-580-2026.10.5.json` | the sample pack (one entry, NVIDIA 580 legacy driver guide) |
| `trust.json` | a trust file pinning the sample keyring |
| `delegations/basalt.json` | a delegation for the sample's online key (expired after 30 days; the key is gone, so it only shows the format) |

```sh
go run ./cmd/kb verify -trust examples/sample/trust.json examples/sample/kb/v0/basalt
go run ./cmd/kb search -bundle examples/sample/kb/v0/basalt -trust examples/sample/trust.json -error EKEYREJECTED
```

Regenerate with `SOURCE_DATE_EPOCH=1759622400 KB_VERSION=2026.10.5 scripts/sample-bundle.sh examples/sample`
(new keys each time, so the signatures change).
