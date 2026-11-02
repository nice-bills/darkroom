# Darkroom

A market for secrets on NEAR. A seller's secret goes into an attested enclave. A buyer sends an AI agent in with a hard budget. The agents negotiate. On a deal, payment settles and the secret is released to the buyer. On no deal, the budget is refunded and the buyer's human learns only "no deal".

Built for NEAR HACKATHON 2026.

## The problem

Information is hard to sell. A buyer cannot value it without seeing it, and after seeing it has no reason to pay. This is Arrow's information paradox (1962). "NDAI Agreements" (Stephenson, Miller et al., 2025, arXiv:2502.07924) proposes agents in a TEE as the fix.

The demo: a whitehat sells an exploit for a deliberately buggy vault to the protocol that owns it. Without this, the whitehat must reveal the bug and hope to be paid.

## How it works

```
seller CLI -- ECIES to OutLayer keystore --> secret row, locked to one build, one contract, one relayer
           -- list(title, commitment)    --> escrow contract, public sha256(salt || secret)
buyer CLI  -- ft_transfer_call(budget)   --> escrow contract, then start_room
relayer    -- HTTPS call                 --> OutLayer TEE worker runs room.wasm

room.wasm  : reads the listing and room from the chain, never from its input
             checks the room is Running and the secret matches the commitment
             spends this room's one negotiation
             seller agent <-> buyer agent, up to 3 rounds. Rust decides the outcome
             deal: seal the secret to the project
             signs {deal, price, ct_ref, ct_hash} with a key that exists only inside runs

anyone     -- settle_signed(verdict, sig) --> contract checks ed25519 against the pinned enclave key
             deal: pay seller, refund the rest, record ct_ref and ct_hash
             no deal: full refund
             no answer: anyone can call refund_stale after about 6 minutes

relayer    -- reveal --> second TEE run. Reads the deal and the buyer's key from the chain,
                         re-encrypts to that key and publishes the ciphertext
buyer CLI  -- fetches and decrypts locally
```

The relayer cannot change a verdict, reuse one, run a room twice, swap in another secret, or get a reveal without a recorded deal. If it does nothing, the budget comes back through `refund_stale`. Every step also has a contract door that needs no relayer, including a private deal's terms and reveal. A relayer does see a public deal's verdict first, so it could read the price and let the room go stale. A private verdict has no price.

Payment comes first, reveal second. If the room sealed to the buyer before settlement, a failed settlement would leave the buyer with a decryptable secret and a refund. `reveal` can be retried.

The contract also has a yield/resume door (`open_room`), where it calls OutLayer directly and the callback settles. It needs no relayer. The scripts use the relayer by default, and `DOOR=chain` uses this door, for both public and private rooms.

## NEAR technology used

- **OutLayer TEE (Intel TDX)**: runs the room. Secret rows locked by wasm hash and caller, an ed25519 signing key that exists only inside runs, a room key in the author row, project-wide worker storage, manifest `callers` and `capabilities.network`, public storage, TDX attestation.
- **NEAR contract with `ed25519_verify`**: settles from a signature only the enclave can make, with no operator step. See Known limitations for who holds keys on testnet.
- **OutLayer yield/resume**: `request_execution` from the contract, with the callback settling. Works end to end on testnet with no relayer, for public and private rooms.
- **NEP-141 escrow**: `ft_on_transfer` funds a room, `ft_transfer` settles it.
- **NEAR AI Cloud**: the model endpoint, when run with an attested model. `darkroom verify-model` checks its Intel and NVIDIA evidence. Not yet run in the room: see Known limitations.
- **Gloam** (not NEAR tech, runs on Tempo testnet): pays private deals. The buyer shields, then cashes out through Gloam's relay to a one-time address. NEAR stays the state machine and the enclave stays the judge. See [docs/gloam-design.md](docs/gloam-design.md).
- **NEAR Intents dry quotes**: `intents/quote.ts` shows the cross-chain payment path. Mainnet only, not executed.

## Repository

| Path | What |
| --- | --- |
| `contracts/darkroom` | Listings, NEP-141 escrow, OutLayer calls, settlement, reveal |
| `contracts/test-token` | Free-mint NEP-141 so no faucet is needed. Worth nothing |
| `contracts/mock-outlayer` | Stands in for OutLayer in settlement tests. Proves nothing about the TEE |
| `enclave/core` | Negotiation and sealing, free of WASI so tests and the bench run the same code |
| `enclave/room` | The wasm: binds `core` to OutLayer and HTTP |
| `enclave/harness` | Runs the real wasm on the worker's wasmtime version against OutLayer's published interfaces |
| `agents/` | Seller and buyer prompts and the valuation rubric, compiled into the wasm |
| `cli/` | `seller list`, `paid`, `forfeit`, `buyer open`, `pay`, `reclaim`, `fetch`, `cancel`, `refund`, `status`, `verify`, `verify-model`. `gloam.ts` makes the Gloam payments and runs under Node |
| `decoy/` | Deliberately vulnerable vault. `exploit.md` is the demo secret, `attacker/` proves it |
| `redteam/` | Leak benchmark |
| `tools/verify-quote` | Checks a TDX quote against Intel's root with `dcap-qvl` |
| `intents/` | Dry-run quote |
| `relay/` | One public endpoint that runs a real room and streams each step, with a daily cap |
| `scripts/` | `attacks.ts`, `e2e.sh`, `e2e-private.sh`, `deploy.sh`, `update-room.sh`, `settlement-check.sh` |

## Status

| Claim | Evidence |
| --- | --- |
| **The whole product works on testnet** | `scripts/e2e.sh`: escrow, agents in a real TDX worker, signed settlement, exact secret delivered, quote verified. See [docs/spikes.md](docs/spikes.md) |
| **Private settlement works on testnet** | `scripts/e2e-private.sh`: NEAR recorded a deal with price 0. The worker refused a reveal with no payment and with another transaction's payment. The buyer cashed out through Gloam's relay, the seller's one-time address held the price with no seller action, and the room released the exact secret and signed the bond back |
| NEAR does not see a private room's limit | The limit and value at risk are sealed to a room key the enclave signs, and bound to that room. NEAR shows a fixed bond, `protected_value` 0 and ciphertext. The limit stays out of the closing sum and only filters it, so the price does not trace it |
| Walking away from a price costs a bond | A private room holds a public bond. The price is released only after the chain records the deal. The bond returns when the room sees the payment, through a signature or the contract callback. A seller claims it in two steps after about an hour, and a paid buyer can still show payment during the grace period. The two-step `forfeit` is unit-tested. The one-step version ran live on an earlier build |
| A private payment cannot be faked | A cash out is final on arrival, so neither side can undo it. The room reads the receipt from two RPCs. Tests and the harness refuse underpayment, another address, another room's payment, another token, a failed transaction and a lying RPC |
| The planned model is really in a TEE | `darkroom verify-model --model z-ai/glm-5.3-flash`: gateway and model quotes verify against Intel, bound to a fresh nonce, and NVIDIA's service accepts the GPU evidence. The check refuses `z-ai/glm-5.3`, a third-party route. The room does not run this model yet |
| The relayer cannot cheat | `scripts/attacks.ts`: 15 attacks refused on the current deployment, with real transactions and worker calls. They include a forged signature, a real signature moved or edited, replay on a settled room, reveal without a deal, a second run, lying about the cap, forged bond claims and storage griefing |
| A finding reaches only its owner | A listing can name its one allowed buyer, and the real claim stays in the encrypted row. The contract refused a non-target buyer and returned the funds |
| A silent relayer cannot trap funds | `refund_stale` returned four stuck budgets on testnet |
| Hostile data does not buy itself | [docs/redteam.md](docs/redteam.md) |
| The run really happened in a TEE | `darkroom verify --call`: the quote commits to the wasm, input and output, Intel's signature chain verifies, TCB is `UpToDate`, and the worker build is on OutLayer's on-chain approved list |
| One lying RPC cannot fake a deal | The room reads two independent RPCs and refuses if they differ |
| Direct calls are refused | The manifest denies `direct`. HTTPS callers can start the wasm, and only this build started by the contract or the relayer can read a secret row. That rule is enforced by OutLayer |
| Anyone can rebuild the same wasm | `enclave/room/build.sh` from a clean clone gives the deployed sha256 `62c93637…76188`, with `DARKROOM_CONTRACT=deals.darkroom-nb.testnet`, `DARKROOM_LLM_URL=https://api.anthropic.com/v1/messages`, `DARKROOM_LLM_MODEL=claude-haiku-5-5` and the two RPC URLs in `.env.example`. The contract uses a non-reproducible build, so its deployed code cannot be checked this way |
| The demo secret is real | `decoy/attacker` drained 0.5 NEAR on testnet with no deposit |
| No relayer needed | `DOOR=chain scripts/e2e.sh` and `DOOR=chain scripts/e2e-private.sh`: the contract starts the room, the callback settles, and terms and reveal run from the contract. A private deal completed this way, with the bond returned by the callback. A request that omits a limit is ignored by workers and times out (OutLayer issue 31) |
| Tempo reads have two sources | The room reads Tempo's RPC and dRPC and refuses if they differ. A lying source is refused in the harness |

## Run it

Prerequisites: Rust with `wasm32-wasip2` and `rust-src`, `cargo-near`, `near` (near-cli-rs), `outlayer`, `bun`.

### No account needed

Do this:

```bash
(cd enclave/core && cargo test)
(cd contracts/darkroom && cargo test)
(cd cli && bun install && bun test)
(cd redteam && cargo run --release -- --mock)
bun cli/darkroom.ts verify-model --model z-ai/glm-5.3-flash
```

`verify-model` needs `tools/verify-quote` built first.

See: all tests pass, `ok` lines for Intel and NVIDIA, and the bench prints `HARD RULES HELD` with a measured `bits_per_room` under the 3.17 ceiling.

Results and the attack this found are in [docs/redteam.md](docs/redteam.md). On Claude Haiku 5.5, with the prompts as built, 0 of 5 injections in worthless data bought it, and a real finding sold in 3 of 3 bench rooms. The two runs before the last small rule change sold 6 of 6.

Do this, for the same bench against the model set in `.env` (about 50 calls):

```bash
(set -a; source .env; set +a; cd redteam && cargo run --release)
```

See: `results-live.json`, or `INCONCLUSIVE` if runs never reached a model.

### The real wasm, outside OutLayer

```bash
cd enclave/room
DARKROOM_CONTRACT=room.testnet DARKROOM_LLM_URL=http://127.0.0.1:18099/v1/chat/completions DARKROOM_RPC_URL=http://127.0.0.1:18099/rpc DARKROOM_RPC_URL_2=http://127.0.0.1:18099/rpc2 DARKROOM_VAULT_RPC=http://127.0.0.1:18099/vault DARKROOM_VAULT_RPC_2=http://127.0.0.1:18099/vault2 DARKROOM_LLM_MODEL=mock ./build.sh
cd ../harness && cargo run --release -- ../room/target/wasm32-wasip2/release/room.wasm
```

See: `HARNESS PASSED`. It uses the worker's wasmtime version and a 6 KB secret, and attacks the room: a room that is not running, a swapped secret, a fake reveal, a second run, and private reveals with no payment, too little, the wrong address or a lying RPC. It proves nothing about a TEE.

### Settlement on testnet

Put a funded testnet account in `.env` (see `.env.example`), then:

```bash
./scripts/settlement-check.sh
```

See: `ALL SETTLEMENT CHECKS PASSED`. This is real chain settlement against the mock OutLayer: escrow, deal, change, no-deal refund, timed-out run, off-bucket price, payout to an unregistered seller.

### Full flow on testnet

`usdc.fakes.testnet` has a public `mint`, which funds an OutLayer payment key for free. `test.fastfs.io` was down when this was written, so `ROOM_WASM_HOST=walrus` stores the wasm on Walrus testnet for 50 days, and workers fetch it from there.

Set `DARKROOM_LLM_URL`, `DARKROOM_LLM_MODEL`, `DARKROOM_RPC_URL` and `LLM_API_KEY` in `.env` (Anthropic or OpenAI-compatible, chosen by URL), run `outlayer login testnet`, create and top up a payment key, then:

```bash
ROOM_WASM_HOST=walrus ./scripts/deploy.sh
./scripts/e2e.sh
DOOR=chain ./scripts/e2e.sh
```

See: balances before and after, `deal at N USDC`, the exploit text, and `ok` lines for the quote, Intel's signature and the approved worker list. Build `tools/verify-quote` first. Or `no deal: any escrow is refunded`: agents are real, so some rooms end that way. Run it again for a new listing.

Single steps are `bun cli/darkroom.ts` with no arguments.

### Private settlement on testnet

Same setup, plus Node 24. Tempo's testnet faucet funds the payments.

```bash
(cd cli && bun install)
./scripts/e2e-private.sh
```

See: a `Deal` with price `0`, a bond and no limit on NEAR, two `refused:` lines, the one-time address holding the price, the exploit text, and the bond back. Or `no deal: any escrow is refunded`. Run it again for a new listing. Paying takes about 4 minutes locally, and more on a small server. `buyer pay` resumes if it stops. `DOOR=chain` runs it with no relayer, at 0.1 NEAR per run.

### Live attacks

After a deal through the relayer, with the `settle_signed` tx it printed:

```bash
set -a; source .env; source .darkroom.env; set +a
bun scripts/attacks.ts <settle_signed tx>
```

See: `ok` per attack, then `ALL ATTACKS REFUSED`. No model runs.

### Relay

```bash
set -a; source .env; source .darkroom.env; set +a
bun relay/server.ts
curl -N -X POST localhost:8787/run -d '{"flow":"private"}'
```

Or run the same relay from the `Dockerfile`. It needs only testnet keys. The model key stays sealed in OutLayer.

See: each step as it happens. `flow` is `private`, `escrow` or `chain`. One run at a time, a one-minute gap, three runs per client a day, and `RELAY_DAILY_LIMIT` runs a day in all (20 by default). The stream shows the demo's price and limit, and the decoy secret. It is a demo, so do not run it with a real one.

### Cross-chain quote

```bash
bun intents/quote.ts 20
```

See: the cost of funding 20 USDC from Arbitrum, labelled as a dry run.

## Security design

1. **Only a fixed schema leaves the room.** `{deal, price, ct_ref, ct_hash, sig}`, enforced in Rust and again in the contract.
2. **Rust decides, agents only propose.** A hijacked agent cannot exceed the cap, undercut the reserve, or set a price outside the buckets.
3. **The input names a room and nothing else.** Cap, title, buyer key and deal status all come from the chain, so a lying relayer changes nothing.
4. **Settlement needs the enclave's signature.** It covers the contract, listing, buyer and whole verdict, so it cannot be changed or moved. The key exists only inside runs of this project for this caller.
5. **One negotiation per room,** spent inside the enclave before any model runs. A second run could read a second price.
6. **The listing commits to the secret,** so a run cannot pair one listing's price with another's secret.
7. **Reveal needs a recorded deal,** read from the chain, and only ever seals to the buyer's on-chain key.
8. **Budget cap twice.** The escrow amount, then the room.
9. **Price buckets.** 1, 2, 5, 10, 20, 50, 100, 200 USDC, enforced in the room and the contract.
10. **The endpoints are compiled in.** A caller-chosen endpoint would receive the secret. The manifest allowlists those hosts, and direct calls are refused.
11. **The seller's row opens only for one build,** started by the contract or the relayer.
12. **The data is fenced.** It sits in a fence with a random tag per run, and the prompts treat it as data. Notes are cut to one line, so they cannot forge a transcript entry. The title and notes are outside the fence. This reduces injection and does not end it: Rust limits are what hold.
13. **`max_rooms` per listing** bounds sybil buyers.
14. **Buyers send only numbers.** A free-text field let a buyer order the agents to encode the secret in the price. See [docs/redteam.md](docs/redteam.md).
15. **Targeted disclosure.** A listing can name its one allowed buyer, so an exploit cannot be sold to an attacker, and the public title says nothing an attacker could use.
16. **No secret kept on no deal.** The only record is the spent-run mark. A deal the relayer never settles leaves its sealed record in storage, unreadable without a recorded deal.
17. **A private payment needs nothing from the seller.** A private Gloam note can be spent back by its payer, and a payee who opens it can take the money and block a reveal. So the buyer cashes out to a one-time address for this room, derived from a seed in the row. A cash out is final, and the room reads it from two RPCs.
18. **The payee seed is sealed with the secret,** so a paid seller cannot delete their row and strand the buyer.
19. **The price leaves the room only after the chain records the deal,** at a fixed size. Buyers shield a fixed 200 USDC, because the shield is a public token transfer.
20. **One door per room.** The contract records `relay` or `chain`, and the room refuses the other, so a room negotiates once.
21. **Either door can reveal.** Deals are sealed under a room key and kept in project-wide storage, and a buyer can run terms and reveal from the contract, so a silent relayer strands nobody. The payment hash goes in sealed to the room.
22. **A paid buyer beats a forfeit.** A claim on the bond opens a grace period, and showing payment during it wins. `buyer pay` refuses to start near the end of the window.
23. **A payment resumes.** Each step is written down before money moves and checked against the chain on a rerun. `buyer reclaim` cashes out what was left of the shielded amount.

## Known limitations

- **Covert channel.** A price and deal bit can carry at most log2(9) = 3.17 bits per room. `redteam` measures that bound on colluding agents. Timing is not counted: the run time is visible and depends on rounds and retries. Total leak per listing is at most `max_rooms` x 3.17 bits plus timing. It is bounded, not zero. A short secret can be leaked this way if an agent cooperates.
- **The model provider sees the secret** unless it runs in an attested TEE. Any other endpoint is a dev stand-in and voids the confidentiality claim. The demo model, Claude Haiku 5.5 through the Anthropic API, is such a stand-in: Anthropic sees the secret. Use only decoy secrets with it. `z-ai/glm-5.3-flash` on NEAR AI Cloud passes `verify-model` but needs an API key we do not have yet, so no run has used it. The check covers the endpoint, not each reply. Agents in the room also read the secret by design.
- **Trust moves, it does not vanish.** You trust Intel TDX, OutLayer's worker registry and keystore, and that the two RPC endpoints the room reads are not lying together.
- **The project owner is trusted.** The signing key is bound to the project, and whoever publishes a version decides what it signs. The room key lives in the author row, so the owner holds it and a new version could read sealed deals, including unpaid ones. For real use, the keys must be generated and locked so no person holds them. On testnet one throwaway key holds the project and the contract, and the hosted relay holds it too.
- **Older versions stay published.** Testnet has several inactive project versions. Secret rows are locked to one build, so they cannot read rows. Remove them before real use.
- **The relayer sees which rooms run and when,** and can delay or drop a run. A buyer can then use the contract door, at 0.1 NEAR per run. It cannot see the secret or the negotiation. A buyer who is also the relayer can drop a verdict and learn the deal bit for free.
- **Agent outcomes vary.** A real finding can still end in no deal, and models occasionally decline to price an exploit, though retries and the buyer prompt reduce that. A room shows no reason, by design. The bench prints every reply, so diagnose there.
- **A deal can leave the seller paid and the buyer waiting** if every reveal run fails. `reveal` retries, and the sealed copy persists, but delivery depends on OutLayer being up.
- **The midpoint rule can be gamed.** When talks stall, a seller gains by asking high and a buyer by bidding low. No bargaining rule avoids this entirely (Myerson-Satterthwaite). The cap, reserve and zero-bid exit limit the harm. An ask counts only up to four times the bid, a bid counts only up to the ask, a later zero or refusal withdraws a bid, and if the midpoint misses the reserve by one bucket the deal closes at the ask. If the seller's agent stops answering, a standing bid can still close.
- **Reading an attestation needs a payment key.** OutLayer gates that route, so `verify --call` needs a testnet key.
- **The wasm is on Walrus testnet,** because `test.fastfs.io` is still down. It is paid for 50 epochs, about 50 days, which outlasts judging. Testnet storage is not a promise for real use, so republish before then. Each new build needs a new upload.
- **Escrow settlement is public.** Who paid whom, and the price bucket, are on chain. A relayer also sees a public verdict before it settles, and could let the room go stale to get a free look at the price.
- **Private settlement has a bond, not escrow.** A buyer can learn the price and not pay. That leaks the deal bit and bucket for that room and costs the bond, which must stay below the seller's reserve. An outage that outlasts the window and grace period can cost an honest buyer the bond.
- **What private hides, and what it does not.** NEAR shows no price, payee or limit. It does show who listed, who bought, the target and that a deal happened, and the target names the vulnerable protocol. On Tempo the cash out shows the amount and the one-time address, and a watcher who matches timing could guess the price. The shield comes from the buyer's own address, for a fixed 200 USDC. Payments use Gloam's relay and fall back to a direct send, which shows that address. On mainnet the pools keep a 0.25% cash-out fee, which `buyer pay` does not add yet.
- **Only `listing_count` orders listings.** Two sellers listing at once can read the same id in the CLI. The chain is correct, and the printed id may not be.
- **Private settlement crosses chains with no bridge.** The room needs two Tempo sources to agree, so if dRPC or Tempo's RPC is down, the reveal waits and can be retried.
- **Gloam is beta and on Tempo uses development proving keys.** Its external audit is still planned. This is not a partnership.
- **NEAR Intents is not executed.** Quote only, no testnet exists.
- **No storage deposits** for listings and rooms, and no fee model. The contract account pays, so a public demo must keep it topped up. Testnet only.

## Related work

`discordwell/ndai-hackathon` (TrustKit) implements enclave negotiation, sealed exploits and escrow on Base and Ethereum Sepolia. Its settlement relies on an operator key submitting the outcome and a seller accept step. Darkroom's contract has neither: only a signature from inside the enclave, or the OutLayer callback, settles. On testnet one key still owns the contract and project. `enricobottazzi/ndai_zone_awareness` (arXiv:2603.19011) studies how LLMs weigh attestation evidence. Darkroom's rules are enforced outside the model.

## Libraries, templates and AI use

Model: Claude Haiku 5.5 by default in tests. Rust: near-sdk, near-contract-standards, outlayer SDK, wasi, wasmtime, serde, serde_json, sha2, hkdf, chacha20poly1305, x25519-dalek, ed25519-dalek, base64, hex, hmac, getrandom, ureq, dcap-qvl, k256, sha3, tokio, anyhow. TypeScript: @noble/ciphers, @noble/curves, @noble/hashes, @gloamtrade/sdk, snarkjs, viem. Tools: cargo-near, near-cli-rs, outlayer-cli, Bun, Node.

The room started from OutLayer's `ai-example`. The manifest pattern follows OutLayer's `caller-gate-probe`. Most code in this repository was written with Claude Code.

## License

MIT
