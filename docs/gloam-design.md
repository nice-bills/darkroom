# Private settlement with Gloam

Checked 2026-11-01 against the Gloam docs and `@gloamtrade/sdk` 0.4.5 source. Built, and run on testnet by `scripts/e2e-private.sh`.

## What it fixes

NEAR settlement shows who paid whom and the price bucket. For a disclosure market that alone leaks: a protocol paying a security researcher is a signal to attackers. Gloam hides the amount and the payee.

Gloam is not on NEAR. NEAR stays the state machine and the source of truth, the enclave stays the judge, and Gloam is the money.

## Two traps in the obvious design

The obvious design is: buyer pays privately, shows a receipt, room reveals. It gives secrets away.

1. **A receipt does not show who got paid.** From Gloam's docs: "The payer picks the payment note's key, so both sides can make the same proof." A buyer can pay themselves.
2. **A payment is not final until swept.** Until the payee moves it, "the payer could still spend it back". A buyer could pay, get the secret, then take the money back.

## The flow

1. The seller's row also holds their Gloam receive key. Only the room reads it.
2. On a deal the room seals its keys and the price with the secret, signs a verdict with price 0, and seals the real price and the seller's receive tag to the buyer's key at a fixed size. The chain records a deal and learns no price.
3. The buyer shields a fixed amount, pays that tag through Gloam's relay from a new address, and posts the sealed ticket to the contract.
4. The seller's CLI sweeps the payment into a fresh note whose secret is derived from a sweep key, the payment's nullifier and the room's `ct_ref`. The buyer cannot compute that secret.
5. Anyone can run the reveal. The room checks all of the following before it seals the secret to the buyer:
   - the ticket opens with the seller's receive key, so the payment really went to this seller
   - the asset and amount meet the deal
   - the note commitment is bound to the secret, and the note is in the vault
   - its nullifier is spent
   - the vault holds the commitment only the seller's key could derive for this room, so the seller swept it and the buyer did not spend it back

## Failure cases

| Who misbehaves | Result |
| --- | --- |
| Buyer pays themselves | Ticket does not open with the seller's key. No reveal |
| Buyer spends the payment back first | The derived commitment is missing. No reveal, and the seller lost nothing |
| Seller never sweeps | The seller is unpaid and the buyer gets no secret, then spends the payment back. Nobody is cheated |
| Seller sweeps and goes quiet | The ticket is on chain and the keys are sealed, so the reveal needs nothing more from the seller |
| Relayer lies | Same protections as today |
| Buyer reuses one payment for two rooms | The sweep note includes the room, and a note is swept once. The second reveal fails |
| Seller deletes their row after the sweep | The keys are sealed with the secret, so reveal does not need the row |
| Buyer learns the price and does not pay | Nothing is released. The buyer learned the deal bit and bucket, bounded per room, and loses a bond after the pay window |
| Seller stalls to take the bond | The bond stays below the reserve, so sweeping always earns more |

## What the room needs

P-256 ECDH, HKDF and AES-GCM to open a ticket, Poseidon on bn254 to recompute note values, and EVM reads from two independent RPCs on Tempo. All are ordinary Rust. The room never generates a proof: only the buyer and seller do, with the SDK.

## Limits to state plainly

- Gloam is beta, reviewed internally, with an external audit still planned.
- Tempo and Robinhood testnets use development proving keys. Base and Ethereum Sepolia use the final ones.
- The relay hides who sent a payment or sweep, at the cost of depending on it. The shield is never relayed, so it is a fixed amount.
- Moving funds from a NEAR account to Gloam is through Intents, which is mainnet only, so it is a dry quote here.
- This is not a partnership. Gloam's post says any reward is undecided.
