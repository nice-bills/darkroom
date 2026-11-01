# Core checklist

Core first, then UI and UX, then the demo.

## Done

- [x] Listing, NEP-141 escrow, settlement, refunds, stale refund, failed payout recovery
- [x] Two-agent negotiation with caps, reserve, price buckets, midpoint close
- [x] Room runs in a real TDX worker
- [x] Enclave-signed settlement, relayer trusted with nothing
- [x] Payment first, then reveal, exact secret delivered
- [x] Chain reads from two RPCs, one negotiation per room, secret commitment
- [x] Red-team bench, offline and live, and live attacks on the deployed system
- [x] Full attestation check: quote binding, Intel signature, approved worker list
- [x] Reproducible build
- [x] Decoy vault with a proven exploit
- [x] Intents dry quote
- [x] Targeted disclosure: one allowed buyer, private claim
- [x] CLI and one-command `scripts/e2e.sh`

## Open before UI

- [ ] Attested model. Needed for the privacy claim. See below.
- [ ] Permanent wasm URL. Temporary hosts expire, and FastFS is down. A GitHub release works once the repo is public.
- [ ] Final freeze: delete the full-access keys on the contract and project owner, so the "no operator" claim is true on the deployment. Irreversible, so do this last.
- [ ] Yield/resume against a real worker, if OutLayer's on-chain door comes back.

## Model options

No free attested API was found among 11 providers listed at confidentialinference.net on 2026-10-31. All are pay-as-you-go.

1. NEAR AI Cloud with the hackathon's free $10 from joining NEAR Builders (rule Q-000). No payment, one wallet connect, far more than this project needs.
2. Keep Claude Haiku 5.5, labelled a stand-in. Works today, but weakens the privacy track.
