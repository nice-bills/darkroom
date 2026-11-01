# Spike notes

Checked 2026-10-30 against app.outlayer.ai/docs, the `out-layer/outlayer` source and testnet RPC.

## Latest

The on-chain door was never down. Our contract and probes omitted `max_memory_mb`, and workers ignore a request that omits a limit (OutLayer issue 31). With it, OutLayer's probe answered in 11 seconds and `DOOR=chain scripts/e2e.sh` ran the whole flow. The notes below that blame the door are wrong on that point and stay as history.

Full flow works on testnet through the signed path: `scripts/e2e.sh`. See the README's Status table. Everything below is the history of how it got there.

Found in the real worker and fixed:

- `wasi-http-client` writes a body in one `blocking-write-and-flush`. The worker's wasmtime 28 traps above 4,096 bytes, and hides the cause. Prompts crossed that by round 2. The room now has its own sender that writes in chunks, after sending the request, because a large body otherwise blocks forever. The harness pins wasmtime 28 and uses a 6 KB secret, so it fails if this returns.
- Workers cannot fetch from `files.catbox.moe` or the dead `test.fastfs.io`.
- The docs' task hash formula is out of date. `verify --call` uses the worker's real one.

## Status at the spike stage

| Spike | Local | Testnet |
| --- | --- | --- |
| 1. Enclave calls an OpenAI-compatible endpoint | Pass: `room.wasm` under wasmtime with a mock LLM; deal, no-deal and unknown-field input | Not run, needs account |
| 2. Contract calls `outlayer.testnet`, gets callback | Unit tests pass, wasm builds | Not run, needs account. Exact callback payload unknown until then |
| 3. Seller secret readable only by the room | Design below | Not run, needs account |

### Testnet run, 2026-10-30 (blocked)

Throwaway `darkroom-nb.testnet`, contract `contract.darkroom-nb.testnet`, project `darkroom-nb.testnet/room`, wasm `b6de98b2…5466`.

Worked: contract deploy; `outlayer upload`; project deploy (with `--hash`); secret stored with build lock and `--via` rule; `open_room` reached OutLayer with `predecessor_id` set to the contract; callback ran both times.

Not reached: the room never executed. Tx `C7awQ1h7zhmgCwX1fbTQybeoy9kmjeGa2k5Jd1mVunwK`: no worker resumed the yield, OutLayer logged `Execution promise failed: Failed`, charged 0.001 NEAR and refunded 0.199.

Likely cause, not proven: `test.fastfs.io` answers 502 at every path, including `/`, so the worker cannot fetch the wasm. The testnet downloader shows 84 failed of 116 tasks. The executor's uptime also stays under a minute, so a worker problem is not ruled out.

Learned for escrow: after a timed-out run our callback sees promise success with value `null`, not `Err`. Settlement must treat anything but a valid verdict as no deal and refund. The success payload is still unobserved.

### Real deployment, 2026-10-31

Deployed `tusdc`, `decoy` and `room` under `darkroom-nb.testnet`, project version `17c79424…56ee`, LLM key stored locked to that build and contract. `seller list` stored the decoy row and listed it. `buyer open` escrowed 50, started the run and got a full refund after about 2 minutes as `NoDeal`.

That timing looks like a yield timeout with the room never run, likely FastFS, unproven. No sign the room executed. Downloader failures rose from 84 to 88.

`seller list --as` must be the account `outlayer login` used, since that account owns the secret row.

### First real TEE run, 2026-10-31

The room has run in a real OutLayer worker, over the HTTPS door, in test project `darkroom-nb.testnet/room-h2`. That build is the production code with `callers` changed to HTTPS-only.

| Step | Call id | Result |
| --- | --- | --- |
| Negotiate, with Claude Haiku 5.5 | `e5e4dda8-d41c-4c3e-ae88-92914c1bedd4` | Deal at 2 USDC in 6 seconds |
| Reveal | `c0a93e46-af99-4c9c-854c-3d249d45c119` | Published to public storage, decrypted locally, exact match |
| HTTPS call to production `room` | `a098b033-b167-46b9-818f-491bdc85c022` | Refused by the `callers` gate, nothing executed |

`darkroom verify --call <id>` recomputes the task hash and it matches the one inside the TDX quote (version 4, type 0x81) for both runs. This covers the real keystore, sealing, storage, secrets and egress to the allowed host. Intel's signature on the quote is not checked locally.

The docs' task hash formula is out of date. The worker also hashes caller, project, secrets ref, timestamp and attached USD (`worker/src/tdx_attestation.rs`).

### What was wrong

Two separate faults, both at OutLayer's end:

1. **Wasm hosting.** The worker fetches wasm over HTTPS, and could not fetch from `test.fastfs.io` (Cloudflare 502, dead origin, not on FastNEAR's status page) or `files.catbox.moe` (`Failed to send request`). `d.uguu.se` works.
2. **The on-chain door is down.** `request_execution` times out at about 2 minutes for every project, including OutLayer's own cached `connectors.outlayer.testnet/connector-probe` (tx `59RxhKyLXXmNgcC1RbmNUd3QSFjuoeeT19UvXfCTX673`), which works over HTTPS. Neardata is current, and the cause is unknown.

So contract to OutLayer yield/resume has still never completed. Settlement is proven against a mock, and the room against a real worker, but not joined.

`usdc.fakes.testnet` has a public `mint`, which funds testnet payment keys for free.

### Second run and harness, 2026-10-31

Reproducible build `37647e09…cd43` is the active version. `verify` passed on tx `BRtKysbMvFsjFbUnm2QSjwBjZxf5Ton7d2iUroGfS3w5` and failed on the wrong wasm. The run timed out again: `Execution promise failed: Failed`, 0.099 NEAR refunded.

The harness ran the real wasm with a real model over TLS: deal at 2 USDC in 8 seconds, then reveal and decrypt. Negotiation used about 2.6 million instructions of a 10 billion limit.

Not proven by any of this: the worker's real host, keystore key derivation, the `callers` refusal, or the egress allowlist.

### Local build after that run

`room.wasm` is now `4248fa20…88b0` with sealing and `reveal`, not uploaded. Unit tests: contract 13, room 6. The deployed contract and project are still the older spike build.

Host calls (`encrypt`, `decrypt`, `mac`, `set_raw`, `get_raw`, `set_worker`) cannot run under plain wasmtime, and `wasi-test-runner` does not cover them. `negotiate` on a deal and all of `reveal` can only be tested on OutLayer.

## Changes to the brief

1. **`darkroom.testnet` is taken.** It exists with one full-access key and 1 NEAR. Use a name we control.
2. **Seller secret goes in as an OutLayer secret, not through encryption keys.** Encryption keys are symmetric and never leave the keystore, so the seller's CLI cannot encrypt to them. Input data is public on chain. The route that works offline is an ECIES secret, encrypted to the keystore public key, then delivered as an env var through `secrets_ref`. Pin it with the access condition `And[WasmHash(build), Predecessor{Whitelist[contract]}]`.
3. **Pin callers in the manifest.** Without it anyone can call `request_execution` on the project directly, pass their own input and get a deal without escrow. `"callers": {"contract": {"only": [<contract>]}}` is enforced by the worker before any secret is decrypted. Every published version stays callable, so remove any version without this block.
4. **Pin the LLM endpoint at compile time.** `ai-example` takes the endpoint from input. Copying that would let the buyer send the secret to their own server. The URL is a build-time env var, so it stays provider-neutral but is covered by the wasm sha256. `capabilities.network` allowlists the host, and is enforced only when `connector_id` is set.
5. **The LLM provider sees the secret.** A generic OpenAI-compatible API is outside the TEE. Only an attested private-inference endpoint keeps the confidentiality claim, so the demo needs NEAR AI Cloud. Q-000 offers $10 in credits for joining NEAR Builders. Any other provider must be labelled as a dev stand-in.
6. **Ciphertext delivery.** `set_worker(key, ct, Some(false))` writes public storage, readable at `/public/storage/get`. It is public, which is fine for ciphertext sealed to the buyer's key.

## Facts verified

- Testnet USDC: `3e2210e1184b45b64c8a434c0a7e7b23cc04ea7eb7a6c3c32520d03d4afcb8af` (Circle docs; `ft_metadata` answers on testnet).
- `outlayer.testnet` is live: 5927 executions in `get_stats`. API base for testnet is `https://testnet-api.outlayer.ai`.
- `on_execution_response` returns the room's JSON stdout as the callback value, and `null` on failure.
- Workers fetch wasm by direct HTTPS unless cached. Other jobs can pass while FastFS is down.
- The keyless Pollinations endpoint allows one reply per 45 seconds per IP. It cannot serve the room.
- Contracts must be built with `cargo near build`. Plain `cargo build` trapped on init.
- `room.wasm` calls the Anthropic Messages API or an OpenAI-compatible API, chosen by the compiled-in URL.
- Submissions open 2026-11-01. Team size value is `1`.

## Doc conflicts to settle on testnet

- Failed runs: the pricing page says not refunded, the integration page says charged for resources used and the rest refunded.
- Limits: max instructions is 100B on one page, 500B on another. Encryption keys are 5 or 3.

## Local run

`wasi-http-client` sends chunked request bodies, so a mock LLM must accept them. Check a real endpoint does too.
