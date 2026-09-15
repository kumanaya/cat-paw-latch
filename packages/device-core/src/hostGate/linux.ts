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
import fsp from "node:fs/promises";
import path from "node:path";
import { isLexicallyWithin } from "@domo/protocol";
import { FullDiskProbeResult } from "./fullDiskAccess.js";
import { HostPermission } from "./guardedPaths.js";

const under = (p: string, prefix: string): boolean => isLexicallyWithin(p, prefix);

const XDG_KEYS = {
  XDG_DESKTOP_DIR: "files_desktop",
  XDG_DOCUMENTS_DIR: "files_documents",
  XDG_DOWNLOAD_DIR: "files_downloads",
} as const;

/** Default Desktop / Documents / Downloads, then any `user-dirs.dirs` overrides. */
export function linuxUserFolderRows(ownerHome: string): [string, HostPermission][] {
  const home = ownerHome.endsWith("/") ? ownerHome.slice(0, -1) : ownerHome;
  const rows: [string, HostPermission][] = [
    [path.join(home, "Desktop"), "files_desktop"],
    [path.join(home, "Documents"), "files_documents"],
    [path.join(home, "Downloads"), "files_downloads"],
  ];
  try {
    const cfg = fs.readFileSync(path.join(home, ".config/user-dirs.dirs"), "utf8");
    for (const line of cfg.split("\n")) {
      const m = /^(XDG_(?:DESKTOP|DOCUMENTS|DOWNLOAD)_DIR)="([^"]+)"/.exec(line.trim());
      if (!m) continue;
      const perm = XDG_KEYS[m[1] as keyof typeof XDG_KEYS];
      if (!perm) continue;
      const resolved = m[2]!.replace("$HOME", home).replace(/^~/, home);
      rows.push([resolved, perm]);
    }
  } catch {
    /* no user-dirs file */
  }
  return rows;
}

/** The three folders the FDA-equivalent probe lists, honoring user-dirs.dirs. */
export function linuxUserFolderPaths(ownerHome: string): string[] {
  const home = ownerHome.endsWith("/") ? ownerHome.slice(0, -1) : ownerHome;
  const dirs: Record<"files_desktop" | "files_documents" | "files_downloads", string> = {
    files_desktop: path.join(home, "Desktop"),
    files_documents: path.join(home, "Documents"),
    files_downloads: path.join(home, "Downloads"),
  };
  for (const [folder, perm] of linuxUserFolderRows(ownerHome)) {
    if (perm === "files_desktop" || perm === "files_documents" || perm === "files_downloads") {
      dirs[perm] = folder;
    }
  }
  return [dirs.files_desktop, dirs.files_documents, dirs.files_downloads];
}

/**
 * The guarded folder that governs `path`, or null when none does. Arguments
 * are expected canonical.
 */
export function linuxGuardedPrefix(target: string, ownerHome: string): HostPermission | null {
  const home = ownerHome.endsWith("/") ? ownerHome.slice(0, -1) : ownerHome;
  if (home.length === 0) return null;
  const rows = linuxUserFolderRows(home);
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

/** One guarded folder's outcome for the standing inventory. */
export interface LinuxFolderProbe {
  path: string;
  outcome: "ok" | "ENOENT" | "EACCES" | "EPERM" | string;
}

/**
 * The standing folder-access snapshot for the inventory's Full Disk Access
 * row on Linux. Same shape as `probeFullDiskAccessDetail`, deliberately:
 * the inventory, the Settings pane and `plow_device_status` read one row.
 *
 * `granted` only if every folder that exists lists. ENOENT is skipped — a
 * missing XDG dir proves nothing. System paths (`/etc`, `/usr`, …) stay
 * ungated and are not in this list.
 */
export async function probeLinuxFolderAccessDetail(
  ownerHome: string,
): Promise<{ granted: boolean; results: FullDiskProbeResult[] }> {
  const results: FullDiskProbeResult[] = (await probeLinuxFolderAccess(ownerHome)).map((r) => ({
    path: r.path,
    outcome: r.outcome,
  }));
  const considered = results.filter((r) => r.outcome !== "ENOENT");
  const granted = considered.length > 0 && considered.every((r) => r.outcome === "ok");
  return { granted, results };
}

/**
 * What the app itself can list right now, one fresh read per XDG user folder.
 * `readdir` (not open) is the probe: these are folders, and a listing is what
 * trips a read gate on one.
 */
export async function probeLinuxFolderAccess(ownerHome: string): Promise<LinuxFolderProbe[]> {
  const results: LinuxFolderProbe[] = [];
  for (const folder of linuxUserFolderPaths(ownerHome)) {
    try {
      await fsp.readdir(folder);
      results.push({ path: folder, outcome: "ok" });
    } catch (error: unknown) {
      const code = (error as { code?: unknown })?.code;
      results.push({ path: folder, outcome: typeof code === "string" ? code : "error" });
    }
  }
  return results;
}
