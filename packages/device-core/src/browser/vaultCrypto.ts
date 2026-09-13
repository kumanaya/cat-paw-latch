/**
 * The vault's crypto primitives: Bitwarden's EncString format and the KDF that
 * unwraps a legacy account's key.
 *
 * The Bitwarden SERVER is gone, but this format is the live one — every field
 * of every item in the local store is an EncString (type 2: AES-256-CBC then
 * HMAC-SHA256), which is what made migration a verbatim copy. The KDF half
 * (`masterKeys`) exists for migration alone: it turns the old account's
 * password into the keys that unwrap its user key. Nothing here does I/O.
 */
import crypto from "node:crypto";

export const KDF_ITERATIONS = 600_000;

export const pbkdf2 = (pw: crypto.BinaryLike, salt: crypto.BinaryLike, iters: number, len: number) =>
  crypto.pbkdf2Sync(pw, salt, iters, len, "sha256");

/** HKDF-Expand (RFC 5869), single block — all a 32-byte key needs. */
export function hkdfExpand(prk: Buffer, info: string, len: number): Buffer {
  const h = crypto.createHmac("sha256", prk);
  h.update(Buffer.concat([Buffer.from(info, "utf8"), Buffer.from([1])]));
  return h.digest().subarray(0, len);
}

/** The keys a legacy account's password derives: the stretched halves are
 * what unwrap that account's user key. (The old server-auth hash — a
 * 1-iteration PBKDF2 of the password — died with the server; nothing here
 * authenticates to anything.) */
export function masterKeys(email: string, password: string) {
  const masterKey = pbkdf2(password, email.toLowerCase(), KDF_ITERATIONS, 32);
  try {
    return {
      stretchedEnc: hkdfExpand(masterKey, "enc", 32),
      stretchedMac: hkdfExpand(masterKey, "mac", 32),
    };
  } finally {
    // Dead the moment the halves exist — see the memory map in
    // vaultKeyStore.ts for what can and cannot be wiped.
    wipeKeyMaterial(masterKey);
  }
}

/**
 * Zero key material that will never be read again. Buffers only: the hex
 * strings key material crosses (native.get, decryptString, file reads) are
 * immutable and unwipable — they live until GC. Never wipe a splitKey half:
 * halves are subarrays aliasing the caller's key, so wiping one destroys a
 * key still in use. Wipe only buffers this scope owns outright.
 */
export function wipeKeyMaterial(...buffers: Buffer[]): void {
  for (const b of buffers) b.fill(0);
}

/** Bitwarden EncString type 2: AES-256-CBC then HMAC-SHA256. */
export function encString(plain: Buffer, encKey: Buffer, macKey: Buffer): string {  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", encKey, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const mac = crypto.createHmac("sha256", macKey).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
}

export function decString(enc: string, encKey: Buffer, macKey: Buffer): Buffer {
  const dot = enc.indexOf(".");
  if (enc.slice(0, dot) !== "2") throw new Error(`unexpected EncString type ${enc.slice(0, dot)}`);
  const [ivB64, ctB64, macB64] = enc.slice(dot + 1).split("|");
  const iv = Buffer.from(ivB64, "base64");
  const ct = Buffer.from(ctB64, "base64");
  const expect = crypto.createHmac("sha256", macKey).update(Buffer.concat([iv, ct])).digest();
  if (!crypto.timingSafeEqual(expect, Buffer.from(macB64, "base64"))) {
    throw new Error("EncString failed its integrity check");
  }
  const d = crypto.createDecipheriv("aes-256-cbc", encKey, iv);
  return Buffer.concat([d.update(ct), d.final()]);
}

/** Salt bytes for passphrase stretching (KPHR1). */
export const PASSPHRASE_SALT_BYTES = 16;

/** A user passphrase stretched to a 32-byte wrapping key (KPHR1). Same
 *  600k-iteration PBKDF2-SHA256 the legacy migration trusts. The passphrase
 *  string itself is unwipable — the caller wipes what it can (see the memory
 *  map in vaultKeyStore.ts) and the stretched output is wiped by its owner. */
export function stretchPassphrase(passphrase: string, salt: Buffer): Buffer {
  if (salt.length !== PASSPHRASE_SALT_BYTES) throw new Error(`passphrase salt is ${salt.length} bytes, not ${PASSPHRASE_SALT_BYTES}`);
  return pbkdf2(passphrase, salt, KDF_ITERATIONS, 32);
}

/** A wrapped vault key: AES-256-GCM under a 32-byte wrapping key (a
 *  stretched passphrase, or a session-held wrapping key). All base64. */
export interface WrappedVaultKey {
  salt: string;
  iv: string;
  ct: string;
}

/** Wrap the 64-byte master key. Throws on a wrong-sized key or wrapping key
 *  rather than truncating either. */
export function wrapVaultKey(key: Buffer, wrapKey: Buffer, salt: Buffer): WrappedVaultKey {
  if (key.length !== 64) throw new Error(`a vault key is 64 bytes, not ${key.length}`);
  if (wrapKey.length !== 32) throw new Error(`a wrapping key is 32 bytes, not ${wrapKey.length}`);
  if (salt.length !== PASSPHRASE_SALT_BYTES) throw new Error(`passphrase salt is ${salt.length} bytes, not ${PASSPHRASE_SALT_BYTES}`);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", wrapKey, iv);
  const ct = Buffer.concat([cipher.update(key), cipher.final(), cipher.getAuthTag()]);
  return { salt: salt.toString("base64"), iv: iv.toString("base64"), ct: ct.toString("base64") };
}

/** Unwrap. Throws (never null) on a wrong passphrase, a wrong wrapping key,
 *  or a tampered blob — AES-GCM authentication fails closed. */
export function unwrapVaultKey(wrapped: WrappedVaultKey, wrapKey: Buffer): Buffer {
  if (wrapKey.length !== 32) throw new Error(`a wrapping key is 32 bytes, not ${wrapKey.length}`);
  const salt = Buffer.from(wrapped.salt, "base64");
  const iv = Buffer.from(wrapped.iv, "base64");
  const raw = Buffer.from(wrapped.ct, "base64");
  if (salt.length !== PASSPHRASE_SALT_BYTES) throw new Error("wrapped blob has a bad salt");
  if (iv.length !== 12 || raw.length < 16 + 64) throw new Error("wrapped blob has a bad shape");
  const ct = raw.subarray(0, raw.length - 16);
  const tag = raw.subarray(raw.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", wrapKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
