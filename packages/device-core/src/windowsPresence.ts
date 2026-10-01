/** Windows owner-presence seam.  No credential bytes cross this interface. */
import { createRequire } from "node:module";
import type { Intent } from "@domo/protocol";
import type { IntentDecision, PolicyDelegate } from "./policyEngine.js";

export type PresenceReason = "vault" | "approval";
export interface PresenceGate { verify(reason: PresenceReason): Promise<boolean>; lock(): void; }

export interface NativeHello {
  checkAvailability(): Promise<string>;
  requestConsent(reason: string): Promise<boolean>;
  requestPassword(reason: string): Promise<boolean>;
}

function nativeHello(): NativeHello | null {
  try { return createRequire(import.meta.url)("@domo/native-hello") as NativeHello | null; }
  catch { return null; }
}

export class AllowPresence implements PresenceGate {
  async verify(): Promise<boolean> { return true; }
  lock(): void {}
}

/** Valid until Windows locks; it is deliberately not a cache of a vault key. */
export class WindowsPresenceGate implements PresenceGate {
  private unlocked = false;
  constructor(
    private readonly adapter: NativeHello | null = nativeHello(),
    private readonly platform: NodeJS.Platform = process.platform,
  ) {}
  async verify(reason: PresenceReason): Promise<boolean> {
    if (this.platform !== "win32" || this.unlocked) return true;
    const native = this.adapter;
    if (!native) return false;
    try {
      const text = reason === "vault" ? "Unlock Plow Latch vault" : "Approve this Plow Latch action";
      // Two paths, and they are NOT the same prompt. `requestConsent` is
      // `UserConsentVerifier` — the Windows Hello face/fingerprint check — and
      // it needs biometric hardware, so on a desktop with no camera or reader
      // `checkAvailability` answers `device-not-present` and it can never run.
      // `requestPassword` is `CredUIPromptForWindowsCredentials`, a PASSWORD
      // dialog: it collects a password and LogonUser checks it. On an account
      // that has a PIN but no password it has nothing to verify and offers to
      // create one — which is the "create an account" prompt, and a real
      // complaint about this path. Removing it does not fix that: it just
      // denies every sensitive action on hardware where Hello cannot run.
      const available = await native.checkAvailability();
      this.unlocked = available === "available"
        ? await native.requestConsent(text)
        : await native.requestPassword(text);
      return this.unlocked;
    } catch { return false; }
  }
  lock(): void { this.unlocked = false; }
}

/** Policy adapter: the approval UI decides first; a Windows owner then proves
 * presence before a sensitive allow can become a grant. */
export class PresencePolicy implements PolicyDelegate {
  constructor(private readonly inner: PolicyDelegate, private readonly gate: PresenceGate) {}
  async decideIntent(intent: Intent): Promise<IntentDecision> {
    const result = await this.inner.decideIntent(intent);
    const decision = typeof result === "string" ? result : result.decision;
    if ((decision === "allow_once" || decision === "always_allow") && sensitive(intent)) {
      if (!(await this.gate.verify("approval"))) return { decision: "deny", source: "presence" };
    }
    return result;
  }
  mayGrantFromStoredRule(intent: Intent): boolean | Promise<boolean> {
    return this.inner.mayGrantFromStoredRule?.(intent) ?? true;
  }
  decisionRecorded(intentId: string): void | Promise<void> { return this.inner.decisionRecorded?.(intentId); }
}

function sensitive(intent: Intent): boolean {
  return intent.capabilities.some((c) =>
    c.kind === "process.exec" || c.kind === "fs.read" || c.kind === "fs.write" ||
    c.kind === "network" || c.kind === "browser" || c.kind === "credential",
  );
}
