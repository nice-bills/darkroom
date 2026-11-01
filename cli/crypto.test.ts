import { expect, test } from "bun:test";
import { hexToBytes } from "@noble/hashes/utils";
import { openDelivery } from "./crypto";

const seal = hexToBytes((await Bun.file(`${import.meta.dir}/seal-vector.txt`).text()).trim());
const buyerSecret = "09".repeat(32);

test("opens what the enclave sealed", () => {
  expect(new TextDecoder().decode(openDelivery(buyerSecret, seal))).toBe("exploit");
});

test("the wrong key cannot open it", () => {
  expect(() => openDelivery("08".repeat(32), seal)).toThrow();
});
