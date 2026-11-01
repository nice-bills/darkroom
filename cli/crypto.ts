// Mirrors seal_to_buyer in enclave/core: ephemeral_pub || ChaCha20-Poly1305 ciphertext.
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";

const INFO = utf8ToBytes("darkroom-reveal-v1");

/// Refuses a room key the enclave did not sign, so a relayer cannot read a sealed limit.
export function checkRoomKey(contract: string, keys: { mandate_key: string; mandate_sig: string }, enclaveKey: string) {
  const message = utf8ToBytes(`darkroom-mandate-v1|${contract}|${keys.mandate_key}`);
  if (!ed25519.verify(hexToBytes(keys.mandate_sig), message, hexToBytes(enclaveKey))) {
    throw new Error("Room key is not signed by the enclave");
  }
  return keys.mandate_key;
}

export function newBuyerKey() {
  const secret = x25519.utils.randomPrivateKey();
  return { secret: bytesToHex(secret), pubkey: bytesToHex(x25519.getPublicKey(secret)) };
}

/// Mirrors `open_mandate` in enclave/core: the limit and value at risk as little-endian u64s, then
/// the room's hash, so a sealed limit cannot be replayed into another room.
export function sealMandate(roomKeyHex: string, capMicro: bigint, protectedValue: bigint, ctRef: string): string {
  const numbers = new DataView(new ArrayBuffer(48));
  numbers.setBigUint64(0, capMicro, true);
  numbers.setBigUint64(8, protectedValue, true);
  new Uint8Array(numbers.buffer).set(sha256(utf8ToBytes(ctRef)), 16);
  const secret = x25519.utils.randomPrivateKey();
  const shared = x25519.getSharedSecret(secret, hexToBytes(roomKeyHex));
  const key = hkdf(sha256, shared, undefined, INFO, 32);
  const sealed = chacha20poly1305(key, new Uint8Array(12)).encrypt(new Uint8Array(numbers.buffer));
  return bytesToHex(new Uint8Array([...x25519.getPublicKey(secret), ...sealed]));
}

export function openDelivery(secretHex: string, sealed: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(hexToBytes(secretHex), sealed.slice(0, 32));
  const key = hkdf(sha256, shared, undefined, INFO, 32);
  return chacha20poly1305(key, new Uint8Array(12)).decrypt(sealed.slice(32));
}
