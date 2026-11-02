# Demo script and X post draft

Goal: one complete moment in under 90 seconds. Show a real terminal, no slides.

## Video

1. (0-10s) On screen: "How do you sell a secret? Show it and they don't need to pay. Hide it and they won't."
2. (10-25s) Seller terminal. `darkroom seller list --as seller.testnet --title "Critical drain in the decoy vault" --secret-file decoy/exploit.md --reserve 5`. Say: the secret is encrypted on this machine, and only one exact build, called by the contract or the relayer, can read it.
3. (25-50s) Buyer terminal. `darkroom buyer open --as buyer.testnet --listing 0 --budget 50 --protects 50000`. Say: my agent goes in with a hard 50 USDC cap. It reads the exploit. I don't. Show `deal at N USDC`, then the seller's token balance going up.
4. (50-65s) `darkroom buyer fetch --as buyer.testnet --listing 0`. The exploit text appears. Say: payment settled first, then the secret was released to my key.
5. (65-80s) Run a second listing with worthless data. Show `no deal: any escrow is refunded, and you learned nothing else`.
6. (80-90s) `darkroom verify ...` showing the `ok` lines. Say: only a signature from inside the enclave can settle. There is no operator key in the contract's settlement path.

Use real runs only. Agents are real, so some rooms end in no deal: rerun `scripts/e2e.sh` for a new listing.

## X post draft

You can't sell a secret: show it and nobody needs to pay, hide it and nobody will.

Darkroom fixes that. My AI agent reads an exploit inside a TEE with a hard budget. If it buys, payment settles and I get the secret. If not, I get a refund and learn nothing.

NEAR's role: OutLayer runs the agents in an attested enclave, and a NEAR contract settles the NEP-141 escrow from a signature only that enclave can make, with no operator key.

Built at NEAR HACKATHON. @NEARProtocol #NEARHackathon

Demo and repo: <link>
What would you sell in a room like this?
