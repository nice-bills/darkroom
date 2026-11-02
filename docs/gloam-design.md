# Private settlement with Gloam

Checked 2026-11-01 against the Gloam docs and `@gloamtrade/sdk` 0.4.5 source. Built, and run on testnet by `scripts/e2e-private.sh`.

## What it fixes

Escrow on NEAR shows who paid whom and the price bucket. For a disclosure market that alone leaks: a protocol paying a security researcher is a signal to attackers. Gloam moves the payment off NEAR.

Gloam is not on NEAR. NEAR stays the state machine, the enclave stays the judge, and Gloam is the money.

## Why not a private note

The first build paid with a private Gloam note, and the seller swept it. An independent audit broke it:

1. The payer picks a note's key, so a payer can spend it back until the payee moves it.
2. A payee who opens the note can sweep it anywhere. The room cannot tell that from the buyer spending it back. So a seller could keep the money, block the reveal and take the bond.

Keeping a private note safe needs the room to make the sweep proof itself, which does not fit in a run today.

## The flow

1. The seller's row holds a payee seed. Each room's address derives from it, so no two rooms share one.
2. On a deal the room signs a verdict with price 0. The chain records a deal and learns no price.
3. After the chain records the deal, the `terms` run seals the price and the room's address to the buyer at a fixed size. A verdict seen early by a relayer shows no price.
4. The buyer shields a fixed 200 USDC, splits off the exact price as a private note, and cashes it out to the address through Gloam's relay. The cash out is final on arrival.
5. The buyer runs the reveal through a relayer or the contract, with the transaction hash sealed to the room, so NEAR shows no link. The room reads the receipt from two RPCs, confirms the address received the price in the right token, and seals the secret to the buyer. The bond returns through a signed receipt or the contract callback.

## Failure cases

| Who misbehaves | Result |
| --- | --- |
| Buyer pays someone else, or too little | The receipt does not match. No reveal |
| Buyer reuses a payment | Each room has its own address, so another room's payment does not match |
| Buyer takes the money back | A cash out cannot be undone |
| Buyer learns the price and walks | Nothing is released. The buyer learned the deal bit and bucket, and loses the bond after the window |
| Seller goes quiet | Nothing needed: the money is theirs on arrival |
| Relayer goes quiet, or is the seller | The buyer runs terms and reveal from the contract |
| Seller claims the bond while a buyer is paying | The claim opens a grace period, and showing payment wins |
| Seller deletes their row | The seed and secret are sealed with the deal |
| One RPC lies | The two sources disagree. No reveal |

## What the room needs

secp256k1 and keccak to derive addresses, and JSON-RPC reads from two independent Tempo sources. The room never generates a proof. The buyer does, with the SDK.

## Limits to state plainly

- A cash out is public: the amount and the one-time address appear on Tempo. Nothing links them to NEAR except timing, and a watcher matching timing could guess the price.
- Gloam is beta, reviewed internally, with an external audit still planned.
- Tempo and Robinhood testnets use development proving keys. Base and Ethereum Sepolia use the final ones.
- Mainnet pools keep a 0.25% cash-out fee. `buyer pay` does not add it yet, so a mainnet buyer would underpay.
- Moving funds from a NEAR account to Gloam is through Intents, which is mainnet only, so it is a dry quote here.
- This is not a partnership. Gloam's post says any reward is undecided.
