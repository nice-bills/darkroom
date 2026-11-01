#!/usr/bin/env bash
# Turns the service's environment into the files the CLIs and scripts read.
set -euo pipefail
: "${NEAR_ACCOUNT_ID:?}" "${NEAR_PUBLIC_KEY:?}" "${NEAR_PRIVATE_KEY:?}" "${OUTLAYER_CREDENTIALS_B64:?}" "${NEAR_CONFIG_B64:?}" "${OUTLAYER_PAYMENT_KEY:?}"
umask 077
mkdir -p ~/.near-credentials/testnet ~/.outlayer/testnet ~/.config/near-cli
for account in "$NEAR_ACCOUNT_ID" "buyer.$NEAR_ACCOUNT_ID" "seller.$NEAR_ACCOUNT_ID"; do
  printf '{"account_id":"%s","public_key":"%s","private_key":"%s"}' "$account" "$NEAR_PUBLIC_KEY" "$NEAR_PRIVATE_KEY" > ~/.near-credentials/testnet/"$account".json
done
printf testnet > ~/.outlayer/default-network
base64 -d <<< "$OUTLAYER_CREDENTIALS_B64" > ~/.outlayer/testnet/credentials.json
# The config names the keychain by absolute path, from the machine that wrote it.
base64 -d <<< "$NEAR_CONFIG_B64" | sed "s#^credentials_home_dir = .*#credentials_home_dir = \"$HOME/.near-credentials\"#" > ~/.config/near-cli/config.toml
# The scripts source these. Values are already in the environment, so both files can stay empty.
: > .env
: > .darkroom.env
exec bun relay/server.ts
