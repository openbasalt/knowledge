#!/usr/bin/env bash
# Build the seed content into OUT with throwaway keys, verify it, and
# optionally run the conformance suite against kbd serving it.
#
#   scripts/sample-bundle.sh OUT [--conformance]
#
# The keys live in a temporary directory that is removed on exit: the
# output holds only public material (the keyring, a trust file for it and
# the online key's delegation). A sample bundle is for tests and examples;
# nothing should trust its key.
set -euo pipefail

out=${1:?usage: scripts/sample-bundle.sh OUT [--conformance]}
mode=${2:-}
root=$(cd "$(dirname "$0")/.." && pwd)
keys=$(mktemp -d)
kbd_pid=
cleanup() {
	[ -n "$kbd_pid" ] && kill "$kbd_pid" 2>/dev/null || true
	rm -rf "$keys"
}
trap cleanup EXIT

cd "$root"
go build -o "$keys/bin/" ./cmd/kb ./cmd/kbd
kb="$keys/bin/kb"

"$kb" keygen -out "$keys/root.key" -pub "$keys/root.pub" >/dev/null
"$kb" keygen -out "$keys/publisher.key" -pub "$keys/publisher.pub" >/dev/null
"$kb" keygen -out "$keys/online.key" -pub "$keys/online.pub" >/dev/null
"$kb" keyring -ns basalt -version 1 -root "$keys/root.pub" -publisher "$keys/publisher.pub" \
	-sign "$keys/root.key" -out "$keys/keyring-1.json"

rm -rf "$out"
mkdir -p "$out"
"$kb" validate content/basalt
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)} \
	"$kb" build -content content/basalt -key "$keys/publisher.key" -keyring "$keys/keyring-1.json" \
	-version "${KB_VERSION:-0.0.0}" -out "$out/kb/v0"
"$kb" trust -out "$out/trust.json" "$keys/keyring-1.json"
mkdir -p "$out/delegations"
"$kb" delegate -ns basalt -key "$keys/publisher.key" -online "$keys/online.pub" -days 30 \
	-out "$out/delegations/basalt.json"
"$kb" verify -trust "$out/trust.json" "$out/kb/v0/basalt"

if [ "$mode" = "--conformance" ]; then
	port=${KBD_PORT:-18080}
	# kbd listens on loopback with no proxy in front, so the hosting layer
	# truthfully keeps no access logs here.
	KBD_ADDR="127.0.0.1:$port" KBD_DATA="$out/kb/v0" KBD_TRUST="$out/trust.json" \
		KBD_ONLINE_KEY="$keys/online.key" KBD_DELEGATIONS="$out/delegations" \
		KBD_HOSTING_ACCESS_LOGS=false KBD_HOSTING_QUERY_BODY_LOGGED=false \
		KBD_RATE=6000 KBD_BURST=1000 KBD_LOG_LEVEL=warn "$keys/bin/kbd" &
	kbd_pid=$!
	for _ in $(seq 50); do
		KBD_ADDR="127.0.0.1:$port" "$keys/bin/kbd" health-check && break
		sleep 0.1
	done
	"$kb" conformance -url "http://127.0.0.1:$port" -trust "$out/trust.json"
fi
