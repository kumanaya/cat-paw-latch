/**
 * Linux owner-presence seam. No credential bytes cross this interface.
 *
 * Without Hello/Touch ID, presence is: the graphical session is unlocked,
 * plus an interactive confirmation (zenity/kdialog when present; otherwise
 * the Electron app injects a prompt). A locked session always fails closed.
 */
import { spawnSync } from "node:child_process";
import type { Intent } from "@domo/protocol";
import type { PolicyDelegate } from "./policyEngine.js";
import {
  PresencePolicy,
  type PresenceGate,
  type PresenceReason,
} from "./windowsPresence.js";

export type PresencePrompt = (reason: PresenceReason) => Promise<boolean>;

function sessionLocked(): boolean {
  const session = process.env.XDG_SESSION_ID;
  if (!session) return false; // no session id: do not invent a lock; prompt still required
  try {
    const result = spawnSync("loginctl", ["show-session", session, "-p", "LockedHint", "--value"], {
      encoding: "utf8",
      timeout: 3_000,
    });
    if (result.status !== 0) return false;
    return (result.stdout ?? "").trim().toLowerCase() === "yes";
  } catch {
    return false;
  }
}

function defaultCliPrompt(reason: PresenceReason): boolean {
  const text = reason === "vault"
    ? "Unlock Plow Latch vault?"
    : "Approve this Plow Latch action?";
  for (const [bin, args] of [
    ["zenity", ["--question", "--title=Plow Latch", `--text=${text}`]],
    ["kdialog", ["--yesno", text, "--title", "Plow Latch"]],
  ] as const) {
    try {
      const result = spawnSync(bin, args, { timeout: 120_000 });
      if (result.error) continue;
      if (result.status === 0) return true;
      if (result.status === 1) return false;
    } catch {
      /* try next */
    }
  }
  // No dialog tool: fail closed rather than silently unlock.
  return false;
}

/**
 * Valid until the session locks or the app clears it. Deliberately not a
 * cache of a vault key.
 */
export class LinuxPresenceGate implements PresenceGate {
  private unlocked = false;
  constructor(
    private readonly prompt: PresencePrompt = async (reason) => defaultCliPrompt(reason),
    private readonly platform: NodeJS.Platform = process.platform,
    private readonly locked: () => boolean = sessionLocked,
  ) {}

  async verify(reason: PresenceReason): Promise<boolean> {
    if (this.platform !== "linux") return true;
    if (this.locked()) {
      this.unlocked = false;
      return false;
    }
    if (this.unlocked) return true;
    try {
      this.unlocked = await this.prompt(reason);
      return this.unlocked;
    } catch {
      return false;
    }
  }

  lock(): void {
    this.unlocked = false;
  }
}

/** Same adapter shape as Windows: approval UI first, then presence. */
export function linuxPresencePolicy(inner: PolicyDelegate, gate: PresenceGate): PresencePolicy {
  return new PresencePolicy(inner, gate);
}

/** Sensitive intents that require presence on Linux (mirrors Windows). */
export function linuxSensitive(intent: Intent): boolean {
  return intent.capabilities.some((c) =>
    c.kind === "process.exec" || c.kind === "fs.read" || c.kind === "fs.write" ||
    c.kind === "network" || c.kind === "browser" || c.kind === "credential",
  );
}
