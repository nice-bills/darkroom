import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";

// The Rust test `payee_key_matches_the_cli` holds the same vector, so the two cannot drift.
test("payee derivation matches the room", () => {
  const key = createHash("sha256").update("darkroom-payee").update(Buffer.alloc(32, 7)).update("7-buyer.testnet").digest("hex");
  expect(privateKeyToAccount(`0x${key}`).address.toLowerCase()).toBe("0x73092dd8c4f754c228860b37fd963cd933820fe1");
});
