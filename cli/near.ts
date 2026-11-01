// Views go straight to RPC. Transactions shell out to near-cli so keys stay in its keychain.
import { spawnSync } from "node:child_process";

export const RPC = process.env.NEAR_RPC ?? "https://test.rpc.fastnear.com";

export async function rpc(method: string, params: unknown) {
  const response = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = (await response.json()) as { result?: any; error?: unknown };
  if (!body.result || body.result.error) throw new Error(JSON.stringify(body.error ?? body.result?.error));
  return body.result;
}

export async function view(contract: string, method: string, args: object) {
  const result = await rpc("query", {
    request_type: "call_function",
    finality: "final",
    account_id: contract,
    method_name: method,
    args_base64: btoa(JSON.stringify(args)),
  });
  return JSON.parse(new TextDecoder().decode(new Uint8Array(result.result)));
}

export function call(signer: string, contract: string, method: string, args: object, deposit: string) {
  const result = spawnSync(
    "near",
    ["contract", "call-function", "as-transaction", contract, method, "json-args", JSON.stringify(args),
     "prepaid-gas", "300 Tgas", "attached-deposit", deposit, "sign-as", signer,
     "network-config", "testnet", "sign-with-legacy-keychain", "send"],
    { encoding: "utf8" },
  );
  const output = result.stdout + result.stderr;
  if (result.status !== 0) throw new Error(`${method} failed:\n${output.slice(-600)}`);
  return output;
}
