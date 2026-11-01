#!/usr/bin/env bash
# Real on-chain settlement against a mock OutLayer. Proves escrow, NEP-141 flows and the callback,
# not the TEE. Needs a funded testnet account in .env and contract wasm built.
set -euo pipefail
cd "$(dirname "$0")/.."
source .env
ROOT=$NEAR_ACCOUNT_ID
near=~/.local/bin/near
W=target/near
TOKEN=tusdc.$ROOT MOCK=mock.$ROOT ESCROW=escrow.$ROOT BUYER=buyer.$ROOT SELLER=seller.$ROOT LATE=late-$(date +%s).$ROOT
COMMITMENT=$(printf 'ab%.0s' {1..32})
ENCLAVE_KEY=$(printf 'cd%.0s' {1..32})

fail() { echo "FAIL: $*"; exit 1; }
key() { umask 077; printf '{"account_id":"%s","public_key":"%s","private_key":"%s"}' "$1" "$NEAR_PUBLIC_KEY" "$NEAR_PRIVATE_KEY" > ~/.near-credentials/testnet/"$1".json; }
exists() { curl -sS -m 20 https://test.rpc.fastnear.com -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$1\"}}" | grep -q '"amount"'; }
create() {
  key "$1"
  $near account create-account fund-myself "$1" "$2" use-manually-provided-public-key "$NEAR_PUBLIC_KEY" sign-as "$ROOT" network-config testnet sign-with-legacy-keychain send >/dev/null 2>&1
}
deploy() { # account wasm init-json
  local out; out=$($near contract deploy "$1" use-file "$2" with-init-call new json-args "$3" prepaid-gas '100 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-legacy-keychain send 2>&1) || { echo "$out" | tail -8; fail "deploy $1"; }
}
call() { # signer contract method json deposit
  local out
  for attempt in 1 2 3 4; do
    if out=$($near contract call-function as-transaction "$2" "$3" json-args "$4" prepaid-gas '200 Tgas' attached-deposit "$5" sign-as "$1" network-config testnet sign-with-legacy-keychain send 2>&1); then return 0; fi
    case "$out" in *"rate limit"*|*"nonce"*) sleep $((attempt * 5)) ;; *) break ;; esac
  done
  echo "$out" | tail -12; fail "call $3"
}
view() { $near contract call-function as-read-only "$1" "$2" json-args "$3" network-config testnet now 2>/dev/null | tr -d ' \n'; }
balance() { view "$TOKEN" ft_balance_of "{\"account_id\":\"$1\"}" | tr -d '"'; }
expect() { [ "$2" = "$3" ] && echo "ok: $1" || fail "$1: got $2, want $3"; }
wait_status() { # listing want
  for _ in 1 2 3 4 5 6 7 8 9 10; do s=$(view "$ESCROW" get_room "{\"listing_id\":$1,\"buyer\":\"$BUYER\"}"); echo "$s" | grep -q "$2" && return 0; sleep 2; done
  fail "listing $1: $s"
}
open_msg() { printf '{\\"listing_id\\":%s,\\"buyer_pubkey\\":\\"%s\\",\\"protected_value\\":50000}' "$1" "$(printf 'ab%.0s' {1..32})"; }
fund_room() { # listing amount
  call "$BUYER" "$TOKEN" ft_transfer_call "{\"receiver_id\":\"$ESCROW\",\"amount\":\"$2\",\"msg\":\"$(open_msg "$1")\"}" '1 yoctoNEAR'
}
run_room() { # listing output-json
  call "$BUYER" "$MOCK" set_next_output "{\"output\":$2}" '0 NEAR'
  call "$BUYER" "$ESCROW" open_room "{\"listing_id\":$1}" '0.1 NEAR'
}

# The token, buyer and seller come from deploy.sh. Balances are compared as deltas.
for a in "$MOCK" "$ESCROW" "$LATE"; do
  key "$a"
  if exists "$a"; then $near account delete-account "$a" beneficiary "$ROOT" network-config testnet sign-with-legacy-keychain send >/dev/null 2>&1; fi
done
create "$MOCK" '1.34 NEAR'; create "$ESCROW" '2.6 NEAR'; create "$LATE" '0.24 NEAR'
deploy "$MOCK" contracts/mock-outlayer/$W/mock_outlayer.wasm '{}'
deploy "$ESCROW" contracts/darkroom/$W/darkroom.wasm "{\"outlayer\":\"$MOCK\",\"project_id\":\"mock/room\",\"token\":\"$TOKEN\",\"enclave_key\":\"$ENCLAVE_KEY\"}"

call "$BUYER" "$TOKEN" mint '{"amount":"100000000"}' '0 NEAR'
sleep 2
for a in "$ESCROW"; do call "$BUYER" "$TOKEN" storage_deposit "{\"account_id\":\"$a\"}" '0.00125 NEAR'; done
for t in deal nodeal timeout tampered unpaid; do call "$( [ $t = unpaid ] && echo "$LATE" || echo "$SELLER")" "$ESCROW" list "{\"profile\":\"p\",\"title\":\"$t\",\"max_rooms\":1,\"commitment\":\"$COMMITMENT\",\"target\":null,\"private_settlement\":false,\"bond\":\"0\"}" '0.01 NEAR'; done

BUYER0=$(balance "$BUYER"); SELLER0=$(balance "$SELLER")
fund_room 0 20000000; sleep 2
expect "buyer escrowed 20" "$(balance "$BUYER")" $((BUYER0 - 20000000))
run_room 0 '{"deal":true,"price":5000000,"ct_ref":"0-b","ct_hash":"h"}'
wait_status 0 Deal
sleep 3
expect "seller paid 5" "$(balance "$SELLER")" $((SELLER0 + 5000000))
expect "buyer got change, net cost 5" "$(balance "$BUYER")" $((BUYER0 - 5000000))
before=$(view "$MOCK" runs '{}')
call "$BUYER" "$ESCROW" reveal '{"listing_id":0}' '0.1 NEAR'
expect "reveal started a run" "$(view "$MOCK" runs '{}')" $((before + 1))
BUYER1=$(balance "$BUYER")

fund_room 1 20000000
run_room 1 '{"deal":false,"price":0,"ct_ref":"","ct_hash":""}'
wait_status 1 NoDeal; sleep 3
expect "no deal refunds in full" "$(balance "$BUYER")" "$BUYER1"
refused=$($near contract call-function as-transaction "$ESCROW" reveal json-args '{"listing_id":1}' prepaid-gas '300 Tgas' attached-deposit '0.1 NEAR' sign-as "$BUYER" network-config testnet sign-with-legacy-keychain send 2>&1 || true)
case "$refused" in *"No deal to reveal"*) echo "ok: reveal refused after no deal" ;; *) fail "reveal after no deal" ;; esac

fund_room 2 20000000
run_room 2 null
wait_status 2 NoDeal; sleep 3
expect "timed-out run refunds in full" "$(balance "$BUYER")" "$BUYER1"

fund_room 3 20000000
run_room 3 '{"deal":true,"price":7000000,"ct_ref":"r","ct_hash":"h"}'
wait_status 3 NoDeal; sleep 3
expect "off-bucket price refunds in full" "$(balance "$BUYER")" "$BUYER1"

fund_room 4 20000000
run_room 4 '{"deal":true,"price":5000000,"ct_ref":"4-b","ct_hash":"h"}'
wait_status 4 Deal; sleep 4
expect "payout to unregistered seller stays owed" "$(view "$ESCROW" get_owed "{\"account\":\"$LATE\"}" | tr -d '"')" 5000000
call "$BUYER" "$TOKEN" storage_deposit "{\"account_id\":\"$LATE\"}" '0.00125 NEAR'
call "$LATE" "$ESCROW" claim '{}' '0 NEAR'; sleep 3
expect "claim pays the seller" "$(balance "$LATE")" 5000000

for a in "$MOCK" "$ESCROW" "$LATE"; do $near account delete-account "$a" beneficiary "$ROOT" network-config testnet sign-with-legacy-keychain send >/dev/null 2>&1; done
echo "ALL SETTLEMENT CHECKS PASSED"
