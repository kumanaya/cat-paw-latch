/**
 * Where the vault's one master key lives.
 *
 * The vault keeps its items in an encrypted local file (vaultStore.ts); this
 * is the key that file is useless without, rooted in the OS secret store.
 * Four providers, because each environment has a best available home:
 *
 *   1. `secitem`     — a generic password in the data-protection Keychain via
 *                      @domo/native-keychain, under our own access group. The
 *                      packaged, signed macOS app uses this: the access group
 *                      (not the bundle id) is what the item is keyed to, so the
 *                      app can be renamed or re-identified without orphaning keys.
 *   2. `wincred`     — a generic credential in Windows Credential Manager via
 *                      @domo/native-wincred, under `service/account`. The
 *                      packaged Windows app uses this. Same shape as SecItem:
 *                      a unique per-vault account minted at first write.
 *   3. `safestorage` — Electron's safeStorage under the frozen identity in
 *                      vaultKeychain.ts (DPAPI on Windows, Secret Service on
 *                      Linux, Keychain on macOS). What `just app` uses: the
 *                      stock Electron binary carries no entitlement, so SecItem
 *                      with a group refuses it, and safeStorage (whose Keychain
 *                      item is ACL-bound to the binary) is the strongest thing
 *                      left on macOS.
 *   4. `file`        — the key itself in a 0600 file. Tests and any run with
 *                      neither Electron nor the addon. Same posture as
 *                      vaultSecretStore's fallback, for the same reason:
 *                      outside the app there is nothing better to offer.
 *
 * The provider is chosen once, at writeKey, and recorded in the blob on disk;
 * reading obeys the blob, so a vault written under one provider is never
 * silently re-read through another. "Empty" (no blob) and "locked" (a blob we
 * cannot open) stay distinct facts — see vaultSecretStore.ts for the incident
 * that rule comes from.
 *
 * Key material in memory — what can be wiped and what cannot:
 *
 * - The key is never cached: LocalVault and BrokerCore re-read it per call
 *   (localVault.ts), so its lifetime is one operation plus the GC tail.
 * - Wipable: Buffers this code owns outright. Migration wipes its dead
 *   intermediates (masterKeys' internal, the derived halves per attempt, the
 *   user key once filed, org keys and the private DER once rewrapped) via
 *   wipeKeyMaterial — never a splitKey half, which aliases the caller's key.
 * - Unwipable: every hex string the key crosses. native.get, decryptString
 *   and the file read all hand back strings, and strings are immutable — the
 *   hex lives until GC. Same for the legacy account password in migration.
 * - Residual: the GC tail above, plus locked memory (no mlock from JS).
 *   Holding the key in locked memory with a workstation-lock wipe is the
 *   native-hello phase's job, where an addon can own the bytes end to end.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { writeFileDurable } from "../durableFile.js";
import { safeStorage } from "./vaultSecretStore.js";
import { vaultStoreIdentity } from "./vaultKeychain.js";
import { linuxSecret, linuxSecretEligible } from "./linuxSecret.js";

// ─────────────────────────────────────────────────────────────────────────────
// DO NOT CHANGE THESE STRINGS. They are what every SecItem-stored vault key is
// filed under. They are deliberately NOT the bundle id, the product name, or
// anything else that gets renamed — that decoupling is the entire lesson of
// VAULT_STORE_IDENTITY in vaultKeychain.ts, applied here from day one instead
// of after an outage. The access group's team prefix is required by macOS and
// pins the item to our signing identity, not to any one app id.
// ─────────────────────────────────────────────────────────────────────────────
export const VAULT_KEY_SERVICE = "co.plow.vault";
export const VAULT_KEY_ACCESS_GROUP = "3559PD337Z.co.plow.vault";

/** Key length: enc half + mac half, exactly as vaultItems.splitKey expects. */
export const VAULT_KEY_BYTES = 64;

const FILE_NAME = "vault-key.enc";

// Blob markers. KSEC1/KWIN1 carry no key material — the key is in the OS
// secret store and the blob only records which account name it is filed under.
const M_SECITEM = "KSEC1";
const M_WINCREED = "KWIN1";
const M_LINUX_SECRET = "KLIN1";
const M_SAFESTORAGE = "KENC1";
const M_FILE = "KRAW1";

export type VaultKeyState =
  | { status: "empty" }
  | { status: "locked"; reason: "no-storage" | "undecryptable" }
  | { status: "ok" };

interface NativeKeychain {
  get(service: string, account: string, group: string): string | null;
  set(service: string, account: string, group: string, value: string): void;
  probe(service: string, group: string): "ok" | "missing-entitlement" | "unavailable";
}

interface NativeWinCred {
  get(service: string, account: string): string | null;
  set(service: string, account: string, value: string): void;
  probe(service: string): "ok" | "unavailable";
}

/** The macOS addon when it is built and we are on a Mac, else null. */
function nativeKeychain(): NativeKeychain | null {
  try {
    const require_ = createRequire(import.meta.url);
    return require_("@domo/native-keychain") as NativeKeychain | null;
  } catch {
    return null;
  }
}

/** The Windows addon when it is built and we are on Windows, else null. */
function nativeWinCred(): NativeWinCred | null {
  try {
    const require_ = createRequire(import.meta.url);
    return require_("@domo/native-wincred") as NativeWinCred | null;
  } catch {
    return null;
  }
}

/**
 * Whether the SecItem provider may be CHOSEN for a new key. Only the packaged,
 * signed macOS app: it is the one process whose entitlement makes the access
 * group real. `just app` (stock Electron, unpackaged) deliberately lands on
 * safeStorage, and a test process must never write into the developer's real
 * login Keychain — hermeticity is the same rule as DOMO_HOME.
 * DOMO_VAULT_KEY_PROVIDER overrides for tests and diagnostics.
 */
function secItemEligible(): boolean {
  const forced = process.env.DOMO_VAULT_KEY_PROVIDER;
  if (forced) return forced === "secitem";
  if (process.platform !== "darwin") return false;
  try {
    const require_ = createRequire(import.meta.url);
    const electron = require_("electron") as { app?: { isPackaged?: boolean } };
    return electron?.app?.isPackaged === true;
  } catch {
    return false;
  }
}

/**
 * Whether the Credential Manager provider may be CHOSEN for a new key.
 * Only the packaged Windows app: an unpackaged dev run shares the user's
 * credential store with nothing at stake and must not mint durable secrets
 * there — it lands on safeStorage (DPAPI) instead. Same override switch.
 */
function winCredEligible(): boolean {
  const forced = process.env.DOMO_VAULT_KEY_PROVIDER;
  if (forced) return forced === "wincred";
  if (process.platform !== "win32") return false;
  try {
    const require_ = createRequire(import.meta.url);
    const electron = require_("electron") as { app?: { isPackaged?: boolean } };
    return electron?.app?.isPackaged === true;
  } catch {
    return false;
  }
}

export class VaultKeyStore {
  private readonly file: string;
  private readonly account: string;

  constructor(
    dir: string,
    /** Per-instance Keychain account, so two checkouts never share a key.
     * Defaults to the same branch-suffixed identity safeStorage uses. */
    account: string = vaultStoreIdentity(process.env.DOMO_BRANCH),
  ) {
    this.file = path.join(dir, FILE_NAME);
    this.account = account;
  }

  state(): VaultKeyState {
    if (!fs.existsSync(this.file)) return { status: "empty" };
    return this.readKey() !== null
      ? { status: "ok" }
      : { status: "locked", reason: this.lockedReason() };
  }

  /** Why a blob that exists will not open — for the vault screen's wording. */
  private lockedReason(): "no-storage" | "undecryptable" {
    const marker = this.marker();
    if (marker === M_SECITEM && !nativeKeychain()) return "no-storage";
    if (marker === M_WINCREED && !nativeWinCred()) return "no-storage";
    if (marker === M_LINUX_SECRET) {
      try {
        return linuxSecret().probe(VAULT_KEY_SERVICE) === "ok" ? "undecryptable" : "no-storage";
      } catch {
        return "no-storage";
      }
    }
    if (marker === M_SAFESTORAGE && !safeStorage()) return "no-storage";
    return "undecryptable";
  }

  private marker(): string {
    try {
      const fd = fs.openSync(this.file, "r");
      try {
        const head = Buffer.alloc(5);
        fs.readSync(fd, head, 0, 5, 0);
        return head.toString("utf8");
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      return "";
    }
  }

  /** The key, or null when there is none we can open (empty and locked alike —
   * callers that need to tell the difference ask `state`). */
  readKey(): Buffer | null {
    let raw: Buffer;
    try {
      raw = fs.readFileSync(this.file);
    } catch {
      return null;
    }
    const marker = raw.subarray(0, 5).toString("utf8");
    const body = raw.subarray(5);
    try {
      if (marker === M_SECITEM) {
        const native = nativeKeychain();
        if (!native) return null;
        // The blob RECORDS which Keychain account holds this vault's key —
        // never recomputed, because two vaults (two DOMO_HOMEs) on one Mac
        // must not resolve to one item and clobber each other.
        const meta = JSON.parse(body.toString("utf8")) as { account?: string };
        const hex = native.get(VAULT_KEY_SERVICE, meta.account ?? this.account, VAULT_KEY_ACCESS_GROUP);
        return hex ? this.checked(Buffer.from(hex, "hex")) : null;
      }
      if (marker === M_WINCREED) {
        const native = nativeWinCred();
        if (!native) return null;
        // Same record-the-account rule as SecItem: two DOMO_HOMEs on one
        // Windows user must not resolve to one credential.
        const meta = JSON.parse(body.toString("utf8")) as { account?: string };
        const hex = native.get(VAULT_KEY_SERVICE, meta.account ?? this.account);
        return hex ? this.checked(Buffer.from(hex, "hex")) : null;
      }
      if (marker === M_LINUX_SECRET) {
        if (process.platform !== "linux") return null;
        // Same record-the-account rule: attributes address the item.
        const meta = JSON.parse(body.toString("utf8")) as { account?: string };
        try {
          const hex = linuxSecret().get(VAULT_KEY_SERVICE, meta.account ?? this.account);
          return hex ? this.checked(Buffer.from(hex, "hex")) : null;
        } catch {
          return null;
        }
      }
      if (marker === M_SAFESTORAGE) {
        const s = safeStorage();
        if (!s) return null;
        return this.checked(Buffer.from(s.decryptString(body), "hex"));
      }
      if (marker === M_FILE) {
        return this.checked(Buffer.from(body.toString("utf8").trim(), "hex"));
      }
    } catch {
      return null;
    }
    return null;
  }

  private checked(key: Buffer): Buffer | null {
    return key.length === VAULT_KEY_BYTES ? key : null;
  }

  /**
   * File the key under the best provider this environment has. OS secret
   * store first, blob second: a crash in between leaves an orphaned secret
   * (harmless, overwritten by the retry), never a blob pointing at a key
   * that was never stored.
   */
  writeKey(key: Buffer): void {
    if (key.length !== VAULT_KEY_BYTES) {
      throw new Error(`a vault key is ${VAULT_KEY_BYTES} bytes, not ${key.length}`);
    }
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const hex = key.toString("hex");

    const native = secItemEligible() ? nativeKeychain() : null;
    if (native && native.probe(VAULT_KEY_SERVICE, VAULT_KEY_ACCESS_GROUP) === "ok") {
      // A UNIQUE account per vault, minted at first write and recorded in the
      // blob. The instance identity alone is not enough: DOMO_HOME is honored
      // everywhere, so two packaged homes on one Mac would share one item and
      // the second key write would silently orphan the first vault.
      const account = `${this.account} ${crypto.randomUUID()}`;
      native.set(VAULT_KEY_SERVICE, account, VAULT_KEY_ACCESS_GROUP, hex);
      this.writeBlob(M_SECITEM, Buffer.from(JSON.stringify({ account })));
      return;
    }
    const wincred = winCredEligible() ? nativeWinCred() : null;
    if (wincred && wincred.probe(VAULT_KEY_SERVICE) === "ok") {
      // Same unique-account rule as SecItem: two packaged homes on one
      // Windows user must not share one credential.
      const account = `${this.account} ${crypto.randomUUID()}`;
      wincred.set(VAULT_KEY_SERVICE, account, hex);
      this.writeBlob(M_WINCREED, Buffer.from(JSON.stringify({ account })));
      return;
    }
    const linsec = linuxSecretEligible() ? linuxSecret() : null;
    if (linsec && linsec.probe(VAULT_KEY_SERVICE) === "ok") {
      // Same unique-account rule: two homes on one Linux user must not
      // share one Secret Service item.
      const account = `${this.account} ${crypto.randomUUID()}`;
      linsec.set(VAULT_KEY_SERVICE, account, hex);
      this.writeBlob(M_LINUX_SECRET, Buffer.from(JSON.stringify({ account })));
      return;
    }
    const s = safeStorage();
    if (s) {
      this.writeBlob(M_SAFESTORAGE, s.encryptString(hex));
      return;
    }
    this.writeBlob(M_FILE, Buffer.from(hex, "utf8"));
  }

  /** Mint and file a fresh key. Refuses when one exists in ANY state: a locked
   * blob is an existing vault we cannot open, and writing over it would orphan
   * every item encrypted under it. */
  createKey(): Buffer {
    if (fs.existsSync(this.file)) {
      throw new Error("this vault already has a key; refusing to replace it");
    }
    const key = crypto.randomBytes(VAULT_KEY_BYTES);
    this.writeKey(key);
    return key;
  }

  private writeBlob(marker: string, body: Buffer): void {
    // Durable, not merely atomic: migration's recovery logic assumes the key
    // blob is on disk before the item file — see durableFile.ts.
    writeFileDurable(this.file, Buffer.concat([Buffer.from(marker, "utf8"), body]));
  }
}
