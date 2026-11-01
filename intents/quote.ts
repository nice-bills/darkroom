#!/usr/bin/env bun
// MAINNET-ONLY DRY QUOTE. Nothing is executed and no funds move. It shows what paying a Darkroom
// budget from Arbitrum USDC would cost. NEAR Intents has no testnet, so the escrow does not use it.
const USDC_ARBITRUM = "nep141:arb-0xaf88d065e77c8cc2239327c5edb3a432268e5831.omft.near";
const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
// Sample addresses: a dry quote only prices the route.
const REFUND_TO = "0x0000000000000000000000000000000000000001";
const RECIPIENT = "darkroom.near";

const budgetUsdc = Number(process.argv[2] ?? 20);
const response = await fetch("https://1click.chaindefuser.com/v0/quote", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    dry: true,
    swapType: "EXACT_OUTPUT",
    slippageTolerance: 100,
    originAsset: USDC_ARBITRUM,
    depositType: "ORIGIN_CHAIN",
    destinationAsset: USDC_NEAR,
    amount: String(budgetUsdc * 1_000_000),
    refundTo: REFUND_TO,
    refundType: "ORIGIN_CHAIN",
    recipient: RECIPIENT,
    recipientType: "DESTINATION_CHAIN",
    deadline: new Date(Date.now() + 3_600_000).toISOString(),
  }),
});
const body = await response.json();
if (!response.ok) throw new Error(`quote failed: ${JSON.stringify(body)}`);
const { amountInFormatted, amountOutFormatted, timeEstimate } = body.quote;
console.log(`DRY RUN, mainnet quote, not executed:`);
console.log(`pay ${amountInFormatted} USDC on Arbitrum, escrow receives ${amountOutFormatted} USDC on NEAR, about ${timeEstimate}s`);
