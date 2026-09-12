/**
 * Secret-file ACL lockdown, Windows only.
 *
 * chmod 0600 is advisory on NTFS: without this, a secret file inherits its
 * parent's DACL (SYSTEM, Administrators, and whoever else the profile
 * grants). lockdownSecretFile replaces it with a single owner-only ACE and
 * marks it protected (no inheritance) via @domo/native-fs — the file
 * analogue of what Credential Manager gives the vault key by default.
 *
 * No-op off Windows. On Windows without the built addon it warns once and
 * keeps the inherited ACL: the floor (profile-dir inheritance) is the
 * pre-existing posture, so this layer hardens rather than gates — unlike
 * the Windows sandbox, where the alternative is running arbitrary commands
 * uncaged. The packaged app always carries the addon (afterPackWin refuses
 * a pack without it), so production always enforces. A real ACL failure
 * with the addon present throws: a secret written loose must be visible,
 * never silent.
 */
import { createRequire } from "node:module";

interface NativeFs {
  /** Replace the DACL with one owner-only ACE; returns the SID granted. */
  lockdownFile(path: string): string;
  /** SDDL of owner+group+DACL, for tests. */
  readFileSddl(path: string): string;
}

function nativeFs(): NativeFs | null {
  try {
    const require_ = createRequire(import.meta.url);
    return require_("@domo/native-fs") as NativeFs | null;
  } catch {
    return null;
  }
}

let warnedUnavailable = false;

/**
 * Lock a secret file down to its owner. Returns the SID granted, or null
 * where lockdown does not apply (off Windows) or the addon is absent
 * (warned once).
 */
export function lockdownSecretFile(file: string): string | null {
  if (process.platform !== "win32") return null;
  const addon = nativeFs();
  if (!addon) {
    if (!warnedUnavailable) {
      warnedUnavailable = true;
      console.log("[secret-file] native ACL lockdown unavailable; secret files keep their inherited ACL");
    }
    return null;
  }
  return addon.lockdownFile(file);
}

/** The file's SDDL, for tests. Null where the addon is absent. */
export function readSecretFileSddl(file: string): string | null {
  if (process.platform !== "win32") return null;
  try {
    return nativeFs()?.readFileSddl(file) ?? null;
  } catch {
    return null;
  }
}
