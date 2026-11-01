# Is Darkroom worth winning?

Checked 2026-10-30. Search was not exhaustive.

## Update, 2026-10-31

Winning cannot be known in advance. Evidence now: the whole product working on testnet, in a real TDX worker, with real settlement, live attacks refused, a found and closed exfiltration attack, and a reproducible build. Remaining weakness: the demo model is not attested, so the privacy claim needs an attested model for the track that judges it.

Rule Q-012 needs a video when judges cannot open a hosted demo, and the X demo post is a required submission field. Not recording means not submitting, unless the post carries screenshots and a hosted demo stays up.

## Update, 2026-11-01

Private settlement through Gloam works on testnet, which TrustKit does not have. Yield/resume now runs end to end on testnet. The planned NEAR AI model passes Intel and NVIDIA checks, but no run has used it, so the privacy claim stays open until a key arrives.

## Verdict

Keep going, with a narrower claim. The event is good value (13 tracks, three paid places each, no token buy-in, team keeps rights). The idea survives, but "nobody has shipped atomic disclosure-for-payment settlement" is not safe to say.

Gate: the room must run in a TEE on testnet. Passed on 2026-10-31 through the signed path. Yield/resume is still unproven.

## Closest prior art

`discordwell/ndai-hackathon` (TrustKit), MIT, 2 stars, last pushed 2026-06-19, Base and Ethereum Sepolia, Nitro and TDX.

It already has: two agents negotiating in an enclave, escrow with a budget cap, sealed exploits with re-encryption to the buyer, and on-chain delivery hashes. Its demo story is an exploit sale, the same as ours. A judge who searches will find it, and its scope is far wider than ours.

`enricobottazzi/ndai_zone_awareness` is an experiment framework behind arXiv:2603.19011, not a product. That paper measures how LLMs weigh attestation evidence, so "negotiation chat experiments" in the brief undersells it.

## What is actually different

TrustKit settles through trust in a person's key:

- An `operator` EOA submits the outcome. The contract stores the attestation as a hash and does not check it against the outcome.
- The seller then calls `acceptDeal`, a second step.
- It runs on an operator's own AWS instance.

Darkroom's contract has no operator key and no accept step. Only the OutLayer callback can settle, in the same promise chain as the run, on a shared TEE network, and the wasm hash pins who may call and where data may go.

Claim we can defend: "settlement with no operator key and no seller accept step", from a signature only the enclave can make. Trust moves to OutLayer's worker registry and TDX; it does not disappear. Say that too.

Other gap worth testing: arXiv:2603.19011 finds LLMs cannot reliably verify safety. Our design does not depend on an LLM judging its environment. The hash and caller rules are enforced outside the model.

## Hole found in our own design

The brief has the room seal the secret to the buyer and store the ciphertext before the callback runs. If that callback then ends in no-deal, for example the run outlasts the yield window after writing, the buyer holds a decryptable secret and gets a full refund. That breaks the core promise.

Fix, built locally: payment first, then reveal.

1. On a deal the room seals the secret under an OutLayer encryption key with `caller: "predecessor"`, stores it, and returns `ct_ref` and `ct_hash`. The buyer cannot open this.
2. The callback settles and records `Status::Deal`.
3. The buyer calls the contract's `reveal`. It requires `Status::Deal` and starts a second run, which checks `ct_hash`, opens the stored copy and re-encrypts to `buyer_pubkey`, published under `reveal:<ct_ref>`.
4. `reveal` can be retried, so a failed run costs a retry and not the secret.

A sealed copy is needed, not a re-read of the secret row: the seller could delete the row after being paid.

At this stage the room did not check the chain itself. It does now.

The room does not check the chain itself. It relies on the manifest admitting only the contract, so that contract must stay locked:

- The `only` rule admits the account that called OutLayer, including a direct call signed with the contract account's own key. Whoever holds that key can start a reveal for free. Delete the contract's full-access keys before any real use. Today it uses the throwaway key, which is acceptable only for spikes.
- Worst case left: the seller is paid and every reveal run fails. Bounded by retries, but not zero. State it under known limitations.

## Scope consequence

Depth on one claim beats breadth against TrustKit. The red-team leak benchmark and a one-command judge flow matter more than `intents/` or the auction.
