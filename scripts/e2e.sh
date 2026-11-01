#!/usr/bin/env bash
# The whole product on testnet, real worker and real model: list, escrow, agents negotiate in the
# TEE, the signed verdict settles on chain, the secret is released, and the run is verified.
# Needs a deployed stack (.darkroom.env), .env, a logged-in outlayer and a buyer account.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; source .darkroom.env; set +a
export PATH="$HOME/.local/bin:$PATH"
SELLER=$NEAR_ACCOUNT_ID
BUYER=${1:-buyer.$NEAR_ACCOUNT_ID}
BUDGET=${2:-50}
darkroom() { bun cli/darkroom.ts "$@"; }
tokens() { bun -e "import {view} from './cli/near';console.log(Number(await view('$DARKROOM_TOKEN','ft_balance_of',{account_id:'$1'}))/1e6)"; }

near contract call-function as-transaction "$DARKROOM_TOKEN" mint json-args '{"amount":"100000000"}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' sign-as "$BUYER" network-config testnet sign-with-legacy-keychain send >/dev/null 2>&1
sleep 2
echo "== seller lists the decoy exploit. It is encrypted on this machine, never sent in the clear."
darkroom seller list --as "$SELLER" --title "Security finding" --private-title "Critical fund-draining exploit in your vault, with reproduction steps" --target "$BUYER" --secret-file decoy/exploit.md --reserve 2 --max-rooms 1
sleep 3
LISTING=$(( $(bun -e "import {view} from './cli/near';console.log(await view('$DARKROOM_CONTRACT','listing_count',{}))") - 1 ))

echo "== before: buyer $(tokens "$BUYER"), seller $(tokens "$SELLER")"
echo "== buyer sends an agent in with a hard budget of $BUDGET USDC. The buyer does not see the secret."
# DOOR=chain runs the room from the contract by yield/resume, with no relayer.
OUT=$(darkroom buyer open --as "$BUYER" --listing "$LISTING" --budget "$BUDGET" --protects 50000 ${DOOR:+--door "$DOOR"})
echo "$OUT"
sleep 4
echo "== after: buyer $(tokens "$BUYER"), seller $(tokens "$SELLER"), escrow $(tokens "$DARKROOM_CONTRACT")"
case "$OUT" in *"no deal"*) echo "== no deal: the budget is back and the buyer learned nothing"; exit 0 ;; esac

echo "== payment settled, so the secret is released to the buyer's key:"
darkroom buyer fetch --as "$BUYER" --listing "$LISTING" ${DOOR:+--door "$DOOR"}
if [ "${DOOR:-}" = chain ]; then
  echo "== the contract asked OutLayer for exactly this wasm:"
  WASM=enclave/room/target/wasm32-wasip2/release/room.wasm
  # The hosted relay has no local build to compare with.
  [ -f "$WASM" ] || exit 0
  darkroom verify --tx "$(echo "$OUT" | grep -oE 'open_room tx [A-Za-z0-9]+' | cut -d' ' -f3)" --signer "$BUYER" --wasm "$WASM"
  exit 0
fi
echo "== the TDX quote commits to this wasm, input and output:"
darkroom verify --call "$(echo "$OUT" | grep -oE 'room run [0-9a-f-]+' | cut -d' ' -f3)"
