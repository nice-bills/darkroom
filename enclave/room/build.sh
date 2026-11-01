#!/usr/bin/env bash
# Generates the manifest, then builds. Contract id and LLM host end up in the wasm hash.
set -euo pipefail
cd "$(dirname "$0")"
: "${DARKROOM_CONTRACT:?}" "${DARKROOM_LLM_URL:?}" "${DARKROOM_LLM_MODEL:?}" "${DARKROOM_RPC_URL:?}" "${DARKROOM_RPC_URL_2:?}"
export DARKROOM_VAULT_RPC=${DARKROOM_VAULT_RPC:-https://rpc.moderato.tempo.xyz}
export DARKROOM_VAULT_RPC_2=${DARKROOM_VAULT_RPC_2:-https://tempo-moderato-testnet.drpc.org}
export DARKROOM_VAULT_POOL=${DARKROOM_VAULT_POOL:-0x841DC046Ea3CC842BA3A855731472c6Eb0F2d5eb}
export DARKROOM_VAULT_ASSET=${DARKROOM_VAULT_ASSET:-0x20c0000000000000000000000000000000000000}
host=$(echo "$DARKROOM_LLM_URL" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')
rpc_host=$(echo "$DARKROOM_RPC_URL" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')
rpc_host_2=$(echo "$DARKROOM_RPC_URL_2" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')
# The worker admits contract calls and HTTPS, never a direct one. Who may actually read a secret
# is decided by the secret row, which names the contract and the relayer.
vault_host=$(echo "$DARKROOM_VAULT_RPC" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')
vault_host_2=$(echo "$DARKROOM_VAULT_RPC_2" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')
sed -e "s/__VAULT_RPC_HOST_2__/$vault_host_2/" -e "s/__VAULT_RPC_HOST__/$vault_host/" -e "s/__LLM_HOST__/$host/" -e "s/__RPC_HOST__/$rpc_host/" -e "s/__RPC_HOST_2__/$rpc_host_2/" manifest.template.json > manifest.json
# Pinned, with paths remapped, so anyone can rebuild the same sha256 from the same source.
TOOLCHAIN=1.98.1
export PATH="$(dirname "$(rustup which --toolchain "$TOOLCHAIN" rustc)"):$PATH"
# The compiled wasm depends on the source path, so every build happens at one fixed path.
BUILD=/tmp/darkroom-build
rm -rf "$BUILD"
mkdir -p "$BUILD/enclave/room" "$BUILD/enclave/core"
cp -r ../../agents "$BUILD/"
cp -r ../core/src ../core/Cargo.toml ../core/gloam-fixture.json "$BUILD/enclave/core/"
cp -r src Cargo.toml Cargo.lock manifest.json "$BUILD/enclave/room/"
export RUSTFLAGS="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$(rustc --print sysroot)=/rust"
(cd "$BUILD/enclave/room" && cargo build --locked --target wasm32-wasip2 --release)
mkdir -p target/wasm32-wasip2/release
cp "$BUILD/enclave/room/target/wasm32-wasip2/release/room.wasm" target/wasm32-wasip2/release/room.wasm
sha256sum target/wasm32-wasip2/release/room.wasm
