/**
 * Policy — twin of DomoDeviceCore/PolicyEngine.swift. Applies stored
 * always-allow rules before ever consulting the delegate. Rules match on
 * (agent, device, exact normalized capability set) — never on goal text.
 */
import fs from "node:fs";
import path from "node:path";
import { lockdownSecretFile } from "./fileLockdown.js";
import {
  AlwaysAllowRule,
  Decision,
  Grant,
  Intent,
  intentRuleKey,
  makeAlwaysAllowRule,
  makeGrant,
} from "@domo/protocol";

/**
 * A delegate's intent decision. It may return a bare Decision (source defaults
 * to "prompt") or annotate HOW it decided — so the audit log can distinguish
 * e.g. an auto-approve from a human answer from a policy deny. Known sources:
 * "prompt" (generic), "ask" (human dialog), "approve" (auto-approve),
 * "adversarial" (adversarial-agent review), "policy" (auto-deny). Rule matches
 * are labeled "rule" by the engine itself.
 */
export type IntentDecision = Decision | { decision: Decision; source?: string };

/** A stored rule which remains visible to its owner but can never answer an
 * intent.  Windows migrates pre-presence-gate sensitive rules into this state
 * instead of silently retaining an unsafe standing approval. */
export type ListedAlwaysAllowRule = AlwaysAllowRule & {
  disabled?: true;
  disabledReason?: "windows_sensitive_capability" | "linux_sensitive_capability";
};

/** Whoever answers approval questions: app UI, headless script… */
export interface PolicyDelegate {
  decideIntent(intent: Intent): Promise<IntentDecision>;
  /**
   * May a stored always-allow rule answer this intent on its own?
   *
   * A rule is a decision the human made once and cached, and the engine
   * short-circuits to it before this delegate is ever asked. A delegate may
   * veto that replay when the current global policy must decide every request.
   *
   * Optional: a delegate that does not implement it keeps the plain behaviour.
   * Answering false does not deny — it sends the intent down the normal path,
   * where the delegate decides as it would have the first time.
   */
  mayGrantFromStoredRule?(intent: Intent): boolean | Promise<boolean>;
  /**
   * The decision for this intent is now in the audit log. A delegate that
   * kept its own record of the question while it was open may let go of it
   * here, and not before: between an answer and its audit line the record is
   * the only durable account of what the human said.
   *
   * Optional. Called once per decided intent, after the audit append, and
   * awaited so a delegate's cleanup finishes before the intent runs.
   */
  decisionRecorded?(intentId: string): void | Promise<void>;
}

export class PolicyEngine {
  private rules = new Map<string, AlwaysAllowRule>();
  private disabled = new Map<string, ListedAlwaysAllowRule>();
  private migrated = new Map<string, ListedAlwaysAllowRule>();

  constructor(
    private readonly rulesFile: string,
    private readonly platform: NodeJS.Platform = process.platform,
  ) {
    try {
      const stored = JSON.parse(fs.readFileSync(rulesFile, "utf8")) as ListedAlwaysAllowRule[];
      let changed = false;
      for (const rule of stored) {
        if (rule.disabled) {
          this.disabled.set(rule.ruleKey, rule);
        } else if (
          (this.platform === "win32" || this.platform === "linux") &&
          !ruleEligibleCapabilities(rule.capabilities, this.platform)
        ) {
          const disabled: ListedAlwaysAllowRule = {
            ...rule,
            disabled: true,
            disabledReason: this.platform === "linux" ? "linux_sensitive_capability" : "windows_sensitive_capability",
          };
          this.disabled.set(rule.ruleKey, disabled);
          this.migrated.set(rule.ruleKey, disabled);
          changed = true;
        } else {
          this.rules.set(rule.ruleKey, rule);
        }
      }
      // Mark the migration durably before the app can advertise any capability.
      // A later restart therefore cannot turn a failed audit write into a rule
      // replay, and the owner sees the disabled rule in the Rules screen.
      if (changed) this.persist();
    } catch {
      /* no rules yet */
    }
  }

  allRules(): ListedAlwaysAllowRule[] {
    return [...this.rules.values(), ...this.disabled.values()]
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  /** Rules migrated during this process start.  DeviceAgent records these once
   * in the audit log; old disabled records are deliberately not re-audited on
   * every app launch. */
  migratedDisabledRules(): ListedAlwaysAllowRule[] {
    return [...this.migrated.values()];
  }

  removeRule(key: string): void {
    this.rules.delete(key);
    this.disabled.delete(key);
    this.persist();
  }

  removeAllRules(): void {
    this.rules.clear();
    this.disabled.clear();
    this.persist();
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.rulesFile), { recursive: true });
    fs.writeFileSync(this.rulesFile, JSON.stringify([...this.rules.values(), ...this.disabled.values()], null, 2) + "\n");
    // Standing grants: owner-only ACL on Windows, like any secret.
    lockdownSecretFile(this.rulesFile);
  }

  async decide(intent: Intent, delegate: PolicyDelegate): Promise<Grant> {
    const key = intentRuleKey(intent);
    const eligible = ruleEligible(intent, this.platform);
    if (eligible && this.rules.has(key) && (await mayGrantFromStoredRule(intent, delegate))) {
      return makeGrant(intent, "always_allow", "rule");
    }
    const result = await delegate.decideIntent(intent);
    const decision = typeof result === "string" ? result : result.decision;
    const source = typeof result === "string" ? "prompt" : (result.source ?? "prompt");
    if (decision === "always_allow" && eligible) {
      this.rules.set(key, makeAlwaysAllowRule(intent));
      this.persist();
    }
    return makeGrant(intent, decision, source);
  }
}

/**
 * An Apple-event intent is a mutation with no idempotence guarantee — a
 * byte-identical `make new address` repeated duplicates owner data. So it is
 * never answered by a stored rule and never stored as one: an `always_allow`
 * answer still grants THIS run, it just isn't cached. Checked on both sides
 * so a rule persisted by an older build cannot replay either.
 *
 * An AppleScript intent is the same mutation by another road (and runs
 * outside the sandbox besides), so the exact same script against the exact
 * same app is decided fresh every time too.
 */
function ruleEligible(intent: Intent, platform: NodeJS.Platform): boolean {
  const exceptional = intent.capabilities.some(
    (c) => (c.kind === "apple_events" && c.allowed === true) || c.kind === "applescript",
  );
  if (exceptional) return false;
  // On Windows an Always rule must never bypass the local-presence gate for
  // work that can change, execute, exfiltrate, or release owner data.
  return ruleEligibleCapabilities(intent.capabilities, platform);
}

function ruleEligibleCapabilities(
  capabilities: AlwaysAllowRule["capabilities"],
  platform: NodeJS.Platform,
): boolean {
  // Windows lacks a presence gate that Always-Allow could safely skip;
  // Linux has no polkit presence gate yet. On both, sensitive caps must
  // re-prompt every time.
  if (platform !== "win32" && platform !== "linux") return true;
  return !capabilities.some((c) =>
    c.kind === "process.exec" || c.kind === "fs.write" || c.kind === "network" ||
    c.kind === "credential" || c.kind === "browser" || c.kind === "fs.read",
  );
}

/**
 * Ask the delegate whether a cached rule may still answer for itself.
 *
 * FAILS CLOSED on a throwing guard: a veto that errors must not read as
 * permission, or the bypass this exists to close comes back the moment the
 * guard is the thing that broke. Closed here means "ask properly", not "deny" —
 * the intent goes down the normal decision path.
 */
async function mayGrantFromStoredRule(intent: Intent, delegate: PolicyDelegate): Promise<boolean> {
  if (!delegate.mayGrantFromStoredRule) return true;
  try {
    return await delegate.mayGrantFromStoredRule(intent);
  } catch {
    return false;
  }
}

/** Scripted decisions — what makes automated testing possible without a UI. */
export interface HeadlessPolicyConfig {
  intent: "allow_once" | "always_allow" | "deny";
  denyKinds?: string[];
}

export class HeadlessPolicy implements PolicyDelegate {
  constructor(public readonly config: HeadlessPolicyConfig) {}

  async decideIntent(intent: Intent): Promise<Decision> {
    if (this.config.denyKinds?.some((kind) => intent.capabilities.some((c) => c.kind === kind))) {
      return "deny";
    }
    const d = this.config.intent;
    return d === "allow_once" || d === "always_allow" || d === "deny" ? d : "deny";
  }
}
