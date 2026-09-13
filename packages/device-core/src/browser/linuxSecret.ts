/**
 * The Linux Secret Service provider for the vault master key (`KLIN1`).
 *
 * Linux has no single Keychain: the Secret Service (GNOME Keyring, KWallet
 * with the Secret Service bridge) is the shared API, and `secret-tool`
 * (libsecret) is its command-line face — present wherever libsecret is
 * installed, with no headers or compiler needed. Items are addressed by
 * attributes (`service`, `account`), exactly the shape the SecItem and
 * Credential Manager providers use, so the per-vault unique-account rule
 * carries over unchanged.
 *
 * Honest limits, kept visible:
 * - There may be no daemon at all (headless box, SSH session, CI). Then
 *   `probe` answers "unavailable" and the key store falls through to
 *   safeStorage (which on Linux is the same Secret Service and fails the
 *   same way) and finally the 0600 key file — the same floor as everywhere.
 * - These calls are synchronous subprocesses. Vault key reads/writes happen
 *   at unlock and setup, never on the call-budget path, which is why the
 *   existing file/SecItem reads get to be synchronous too (README-ts.md).
 *   Every spawn carries a timeout so a wedged daemon cannot pin the process.
 * - A locked collection can raise an unlock prompt on the owner's screen.
 *   That only happens for a vault the owner is opening — the same condition
 *   under which this app raises consent dialogs (DESIGN.md §6a).
 */
import { spawnSync } from "node:child_process";

export interface LinuxSecret {
  get(service: string, account: string): string | null;
  set(service: string, account: string, value: string): void;
  probe(service: string): "ok" | "unavailable";
}

const TIMEOUT_MS = 10_000;

function run(args: string[], input?: string): { status: number | null; stdout: string; error?: Error } {
  try {
    const result = spawnSync("secret-tool", args, {
      input,
      encoding: "utf8",
      timeout: TIMEOUT_MS,
    });
    if (result.error) return { status: null, stdout: "", error: result.error };
    return { status: result.status, stdout: result.stdout ?? "" };
  } catch (error) {
    return { status: null, stdout: "", error: error instanceof Error ? error : new Error(String(error)) };
  }
}

function secretError(what: string, status: number | null, stderrHint?: string): Error {
  const err = new Error(`secret-tool ${what} failed (status ${status ?? "unknown"})${stderrHint ? `: ${stderrHint}` : ""}`);
  (err as { code?: string }).code = "SECRET_TOOL_FAILED";
  return err;
}

export function linuxSecret(): LinuxSecret {
  return {
    get(service: string, account: string): string | null {
      const result = run(["lookup", "service", service, "account", account]);
      if (result.error) throw secretError("lookup", result.status);
      // `lookup` exits 1 when nothing matches — a missing item, never a throw.
      if (result.status === 1) return null;
      if (result.status !== 0) throw secretError("lookup", result.status);
      const value = result.stdout.replace(/\n$/, "");
      return value === "" ? null : value;
    },
    set(service: string, account: string, value: string): void {
      const result = run(
        ["store", "--label", `Plow Latch vault (${account})`, "service", service, "account", account],
        value,
      );
      if (result.error) throw secretError("store", result.status);
      if (result.status !== 0) throw secretError("store", result.status);
    },
    probe(service: string): "ok" | "unavailable" {
      // A search that matches nothing still proves the daemon answered:
      // only a process that never ran (no binary, no bus, timeout) is down.
      const result = run(["search", "service", service]);
      if (result.error) return "unavailable";
      return result.status === 0 || result.status === 1 ? "ok" : "unavailable";
    },
  };
}

/**
 * Whether the Secret Service provider may be CHOSEN for a new key. Linux
 * only, and only when a daemon answers — a headless run must land on the
 * key file, never on a store call that would raise or hang. Same override
 * switch as the other providers, for tests and diagnostics.
 */
export function linuxSecretEligible(): boolean {
  const forced = process.env.DOMO_VAULT_KEY_PROVIDER;
  if (forced) return forced === "linuxsecret";
  if (process.platform !== "linux") return false;
  try {
    return linuxSecret().probe("co.plow.vault") === "ok";
  } catch {
    return false;
  }
}
