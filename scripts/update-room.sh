#!/usr/bin/env bash
# Builds room.wasm, publishes it as the active project version, relocks the LLM key to it.
# Seller rows are locked to one build, so each listing must be stored again after this.
# ROOM_WASM_URL skips the upload: use it when FastFS is down, with a URL OutLayer's workers can fetch.
# ROOM_WASM_HOST=walrus stores it on Walrus testnet for 50 days, past the end of judging.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
export PATH="$HOME/.local/bin:$PATH"
export DARKROOM_CONTRACT=deals.$NEAR_ACCOUNT_ID
PROJECT=$NEAR_ACCOUNT_ID/room
retry() { for attempt in 1 2 3 4; do "$@" && return 0; sleep $((attempt * 5)); done; return 1; }

enclave/room/build.sh >/dev/null
WASM=enclave/room/target/wasm32-wasip2/release/room.wasm
HASH=$(sha256sum "$WASM" | cut -d' ' -f1)
URL=${ROOM_WASM_URL:-}
if [ "${ROOM_WASM_HOST:-}" = walrus ]; then
  BLOB=$(curl -sS -m 90 -X PUT "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=50&permanent=true" --upload-file "$WASM" | python3 -I -c "import sys,json;d=json.load(sys.stdin);print(d['newlyCreated']['blobObject']['blobId'] if 'newlyCreated' in d else d['alreadyCertified']['blobId'])")
  URL=https://aggregator.walrus-testnet.walrus.space/v1/blobs/$BLOB
  sleep 10
fi
[ -n "$URL" ] || URL=$(outlayer upload "$WASM" 2>&1 | grep -oE 'https://[^ ]+\.wasm' | head -1)
for attempt in 1 2 3 4 5 6 7 8; do [ "$(curl -sSL -m 60 "$URL" | sha256sum | cut -d" " -f1)" = "$HASH" ] && break; [ "$attempt" = 8 ] && { echo "URL does not serve this build: $URL"; exit 1; }; sleep 15; done
sleep 5
retry outlayer deploy room "$URL" --hash "$HASH"
sleep 5
retry outlayer secrets set "{\"LLM_API_KEY\":\"$LLM_API_KEY\"}" --profile llm --project "$PROJECT" --access allow-all --build "$HASH" --via "$DARKROOM_CONTRACT,$NEAR_ACCOUNT_ID"
if [ -f .darkroom.env ]; then sed -i "s/^DARKROOM_WASM_HASH=.*/DARKROOM_WASM_HASH=$HASH/" .darkroom.env; fi
# Older versions stay callable until removed.
tmp=$(mktemp -d)
printf 'network = "testnet"\n\n[project]\nname = "room"\nowner = "%s"\n' "$NEAR_ACCOUNT_ID" > "$tmp/outlayer.toml"
versions=$(bun -e "import {view} from './cli/near';for (const v of await view('outlayer.testnet','list_versions',{project_id:'$PROJECT'})) if (!v.is_active) console.log(v.wasm_hash)")
for version in $versions; do (cd "$tmp" && retry outlayer versions remove "$version"); done
rm -rf "$tmp"
echo "$HASH"
