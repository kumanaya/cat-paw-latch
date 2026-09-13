/**
 * Which Linux gate governs a path — the map behind a diagnosis on linux.
 *
 * Linux has no TCC and no Controlled Folder Access. What refuses an approved
 * operation is ordinary DAC (mode bits / ACL), the immutable attribute, or a
 * system location no desktop switch grants (`/etc`, `/usr`, `/boot`, …).
 *
 * Pure: a path and the owner's home in, a permission out. XDG user dirs are
 * the shared HostPermission names (Desktop/Documents/Downloads).
 */
import fs from "node:fs";
import path from "node:path";
import { isLexicallyWithin } from "@domo/protocol";
import { HostPermission } from "./guardedPaths.js";

const under = (p: string, prefix: string): boolean => isLexicallyWithin(p, prefix);

/**
 * The guarded folder that governs `path`, or null when none does. Arguments
 * are expected canonical.
 */
export function linuxGuardedPrefix(target: string, ownerHome: string): HostPermission | null {
  const home = ownerHome.endsWith("/") ? ownerHome.slice(0, -1) : ownerHome;
  if (home.length === 0) return null;
  const rows: [string, HostPermission][] = [
    [`${home}/Desktop`, "files_desktop"],
    [`${home}/Documents`, "files_documents"],
    [`${home}/Downloads`, "files_downloads"],
  ];
  // XDG user-dirs.dirs overrides when present.
  try {
    const cfg = fs.readFileSync(path.join(home, ".config/user-dirs.dirs"), "utf8");
    const map: Record<string, HostPermission> = {
      XDG_DESKTOP_DIR: "files_desktop",
      XDG_DOCUMENTS_DIR: "files_documents",
      XDG_DOWNLOAD_DIR: "files_downloads",
    };
    for (const line of cfg.split("\n")) {
      const m = /^(XDG_(?:DESKTOP|DOCUMENTS|DOWNLOAD)_DIR)="([^"]+)"/.exec(line.trim());
      if (!m) continue;
      const perm = map[m[1]!];
      if (!perm) continue;
      const resolved = m[2]!.replace("$HOME", home).replace(/^~/, home);
      rows.push([resolved, perm]);
    }
  } catch {
    /* no user-dirs file */
  }
  let best: { length: number; permission: HostPermission } | null = null;
  for (const [prefix, permission] of rows) {
    if (under(target, prefix) && (best === null || prefix.length > best.length)) {
      best = { length: prefix.length, permission };
    }
  }
  return best?.permission ?? null;
}

/**
 * Whether `path` is under a Linux system location no ordinary user grant
 * flips: /etc, /usr, /boot, /sys, /proc, /dev, /run, /var/lib. SIP analog.
 */
export function linuxSystemProtected(target: string): boolean {
  const roots = ["/etc", "/usr", "/boot", "/sys", "/proc", "/dev", "/run", "/var/lib", "/var/log"];
  return roots.some((root) => under(target, root));
}
