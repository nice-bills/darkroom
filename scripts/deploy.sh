#!/usr/bin/env bash
# Deploys the real stack on testnet. Needs .env, near-cli, cargo-near, `outlayer login testnet`
# and a funded payment key (`usdc.fakes.testnet` has a public mint).
# The contract is pinned to the enclave's public key, read from a real run.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
: "${DARKROOM_LLM_URL:?}" "${DARKROOM_LLM_MODEL:?}" "${LLM_API_KEY:?}" "${DARKROOM_RPC_URL:?}"
export PATH="$(dirname "$(rustup which --toolchain stable rustc)"):$HOME/.local/bin:$PATH"

ROOT=$NEAR_ACCOUNT_ID
CONTRACT=room.$ROOT
TOKEN=tusdc.$ROOT
PROJECT=$ROOT/room
API=https://testnet-api.outlayer.ai
PAYMENT_KEY=$(outlayer keys show 1 2>/dev/null | grep -oE "$ROOT:1:[A-Za-z0-9+/=]+" | head -1)

key() { (umask 077; printf '{"account_id":"%s","public_key":"%s","private_key":"%s"}' "$1" "$NEAR_PUBLIC_KEY" "$NEAR_PRIVATE_KEY" > ~/.near-credentials/testnet/"$1".json); }
exists() { curl -sS -m 20 "$DARKROOM_RPC_URL" -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$1\"}}" | grep -q '"amount"'; }
create() { key "$1"; exists "$1" || near account create-account fund-myself "$1" "$2" use-manually-provided-public-key "$NEAR_PUBLIC_KEY" sign-as "$ROOT" network-config testnet sign-with-legacy-keychain send >/dev/null 2>&1; }
deploy() { near contract deploy "$1" use-file "$2" with-init-call new json-args "$3" prepaid-gas '100 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-legacy-keychain send >/dev/null 2>&1; }

for dir in contracts/test-token contracts/darkroom decoy; do (cd "$dir" && cargo near build non-reproducible-wasm --no-abi >/dev/null 2>&1); done

if ! exists "$TOKEN"; then create "$TOKEN" '1.6 NEAR'; deploy "$TOKEN" contracts/test-token/target/near/test_token.wasm '{}'; fi
if ! exists "decoy.$ROOT"; then create "decoy.$ROOT" '1.3 NEAR'; deploy "decoy.$ROOT" decoy/target/near/decoy_vault.wasm "{\"owner\":\"$ROOT\"}"; fi

HASH=$(scripts/update-room.sh | tail -1)
sleep 3
ENCLAVE_KEY=$(curl -sS -m 90 -X POST "$API/call/$PROJECT" -H "X-Payment-Key: $PAYMENT_KEY" -H 'Content-Type: application/json' -d '{"input":{"op":"public_key"}}' | python3 -I -c "import sys,json;print(json.load(sys.stdin)['output']['public_key'])")
echo "enclave key $ENCLAVE_KEY"

if exists "$CONTRACT"; then near account delete-account "$CONTRACT" beneficiary "$ROOT" network-config testnet sign-with-legacy-keychain send >/dev/null 2>&1; sleep 3; fi
create "$CONTRACT" '2.4 NEAR'
deploy "$CONTRACT" contracts/darkroom/target/near/darkroom.wasm \
  "{\"outlayer\":\"outlayer.testnet\",\"project_id\":\"$PROJECT\",\"token\":\"$TOKEN\",\"enclave_key\":\"$ENCLAVE_KEY\"}"
near contract call-function as-transaction "$TOKEN" storage_deposit json-args "{\"account_id\":\"$CONTRACT\"}" prepaid-gas '30 Tgas' attached-deposit '0.00125 NEAR' sign-as "$ROOT" network-config testnet sign-with-legacy-keychain send >/dev/null 2>&1

cat > .darkroom.env <<EOF
DARKROOM_CONTRACT=$CONTRACT
DARKROOM_TOKEN=$TOKEN
DARKROOM_PROJECT=$PROJECT
DARKROOM_WASM_HASH=$HASH
DARKROOM_RELAYER=$ROOT
OUTLAYER_API=$API
OUTLAYER_REGISTER=worker.outlayer.testnet
OUTLAYER_PAYMENT_KEY=$PAYMENT_KEY
NEAR_RPC=$DARKROOM_RPC_URL
EOF
chmod 600 .darkroom.env
echo "deployed. wasm $HASH"
echo "Every published version stays callable: remove any older one. Before real use, delete the full-access keys on $CONTRACT and on the project owner."
