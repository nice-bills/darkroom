#!/usr/bin/env bash
# Private settlement on testnet, real worker and model: NEAR records a deal with no price and no
# payee, the buyer pays through Gloam on Tempo, and the room confirms it from two RPCs before it
# reveals. The seller does nothing after listing.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; source .darkroom.env; set +a
export PATH="$HOME/.local/bin:$PATH"
SELLER=$NEAR_ACCOUNT_ID
BUYER=${1:-buyer.$NEAR_ACCOUNT_ID}
LIMIT=${2:-50}
# A real payment on Tempo, to an address that is not this room's.
OTHER_TX=0x1bde22fef2e62d78fc7e8eee17009f787d341c2bae31b2d567977da0cf342a53
darkroom() { bun cli/darkroom.ts "$@"; }
refused() { local out; if out=$("$@" 2>&1); then echo "FAIL: should have been refused"; exit 1; else echo "refused: $(echo "$out" | tail -1)"; fi; }

echo "== seller lists privately. The payee seed goes in the encrypted row."
darkroom seller list --as "$SELLER" --title "Security finding" --private-title "Critical fund-draining exploit in your vault, with reproduction steps" --target "$BUYER" --secret-file decoy/exploit.md --reserve 2 --bond 1 --max-rooms 1 --private
sleep 3
LISTING=$(( $(bun -e "import {view} from './cli/near';console.log(await view('$DARKROOM_CONTRACT','listing_count',{}))") - 1 ))

near contract call-function as-transaction "$DARKROOM_TOKEN" mint json-args '{"amount":"100000000"}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' sign-as "$BUYER" network-config testnet sign-with-legacy-keychain send >/dev/null 2>&1
sleep 2
echo "== buyer's agent goes in. Its limit of $LIMIT USDC is sealed to the room. Only a fixed bond moves."
# DOOR=chain runs every step from the contract, with no relayer.
OUT=$(darkroom buyer open --as "$BUYER" --listing "$LISTING" --budget "$LIMIT" --protects 50000 ${DOOR:+--door "$DOOR"})
echo "$OUT"
case "$OUT" in *"no deal"*) echo "== no deal: nothing was ever paid"; exit 0 ;; esac
sleep 3
echo "== what NEAR recorded:"
bun -e "import {view} from './cli/near';const r=await view('$DARKROOM_CONTRACT','get_room',{listing_id:$LISTING,buyer:'$BUYER'});console.log(JSON.stringify({status:r.status,bond:r.cap,protected_value:r.protected_value,mandate:r.mandate.slice(0,32)+'…'}))"

echo "== attack: fetch without paying"
refused darkroom buyer fetch --as "$BUYER" --listing "$LISTING"
echo "== attack: fetch with someone else's payment"
refused darkroom buyer fetch --as "$BUYER" --listing "$LISTING" --tx "$OTHER_TX"
echo "== buyer pays through Gloam: shields, splits off the price, cashes out to this room's one-time address"
darkroom buyer pay --as "$BUYER" --listing "$LISTING" ${DOOR:+--door "$DOOR"}
sleep 3
echo "== the seller did nothing, and the money is already theirs:"
darkroom seller paid --listing "$LISTING" --buyer "$BUYER"
echo "== the room saw the payment on Tempo, so the secret is released:"
darkroom buyer fetch --as "$BUYER" --listing "$LISTING" ${DOOR:+--door "$DOOR"}
sleep 3
echo "== the room signed that it saw the payment, so the bond came back: $(bun -e "import {view} from './cli/near';console.log((await view('$DARKROOM_CONTRACT','get_room',{listing_id:$LISTING,buyer:'$BUYER'})).bond_done)")"
[ "${DOOR:-}" = chain ] && exit 0
echo "== the TDX quote commits to this wasm, input and output:"
darkroom verify --call "$(echo "$OUT" | grep -oE 'room run [0-9a-f-]+' | tail -1 | cut -d' ' -f3)"
