// Each run spends model credits and testnet funds, so a public URL needs hard limits.
export const COOLDOWN_MS = 60_000;
export const PER_CLIENT_DAILY = 3;

export type Flow = "private" | "escrow" | "chain";
export const FLOWS: Record<Flow, string[]> = {
  private: ["scripts/e2e-private.sh"],
  escrow: ["scripts/e2e.sh"],
  chain: ["scripts/e2e.sh"],
};

export interface State {
  busy: boolean;
  day: string;
  runs: number;
  lastEnd: number;
  clients: Map<string, number>;
}

export function admit(state: State, now: number, dailyLimit: number, client: string): string | null {
  const day = new Date(now).toISOString().slice(0, 10);
  if (state.day !== day) {
    state.day = day;
    state.runs = 0;
    state.clients.clear();
  }
  if (state.busy) return "A room is already running";
  if (now - state.lastEnd < COOLDOWN_MS) return "Try again in a minute";
  if (state.runs >= dailyLimit) return "Today's demo runs are used up";
  if ((state.clients.get(client) ?? 0) >= PER_CLIENT_DAILY) return "You have used today's runs";
  return null;
}

/// Defense in depth: the scripts print no keys, but this output is public.
export function redact(line: string, secrets: string[]) {
  return secrets.reduce((text, secret) => text.replaceAll(secret, "[redacted]"), line);
}
