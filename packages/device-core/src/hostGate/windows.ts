/**
 * Which Windows gate governs a path — the map behind a diagnosis on win32.
 *
 * Windows has no TCC: there is no per-app privacy switch for the filesystem
 * and no dialog parked on first access. What refuses an approved operation
 * here is one of three things, and the kernel's answer for all of them is
 * the same EPERM/EACCES:
 *
 * - Controlled Folder Access (Windows Security > Ransomware protection):
 *   writes to the user's Desktop, Documents and Pictures by an app that is
 *   not allowlisted. Reads are not gated — CFA is a write gate.
 * - Ordinary ACLs: ownership and ACEs, including the read-only attribute.
 * - The system locations (`%windir%`, `%ProgramFiles%`): writable only
 *   elevated, the SIP analog — no switch grants it.
 *
 * Pure: a path and the owner's profile dir in, a permission out. Nothing
 * touches the disk, so every row is testable against a fixture profile.
 * Windows paths compare case-insensitively, so both sides fold first.
 *
 * The permission names are the SHARED HostPermission set (guardedPaths.ts),
 * not new Windows-only ones: a guarded Desktop is a guarded Desktop on both
 * systems, and the agent-facing cause (`os_permission`, diagnose.ts) plus
 * the owner's sentence are what differ per platform — not the folder.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { isLexicallyWithin } from "@domo/protocol";
import { FullDiskProbeResult } from "./fullDiskAccess.js";
import { HostPermission } from "./guardedPaths.js";

/** Lowercase + forward slashes: the form every comparison below uses. */
function fold(p: string): string {
  return p.replace(/\\/g, "/").toLowerCase();
}

const under = (p: string, prefix: string): boolean =>
  isLexicallyWithin(fold(p), fold(prefix));

/**
 * The guarded folder that governs `path`, or null when none does. Both
 * arguments are expected canonical; the caller already resolved the path it
 * is asking about, because a link's target is what the kernel judged.
 *
 * OneDrive-redirected folders (`...\OneDrive\Desktop`) are rows of their
 * own: they are where the files really are once backup is on, and the
 * lexical prefix would otherwise miss them entirely.
 */
export function windowsGuardedPrefix(path: string, userProfile: string): HostPermission | null {
  const profile = userProfile.endsWith("/") || userProfile.endsWith("\\")
    ? userProfile.slice(0, -1)
    : userProfile;
  if (profile.length === 0) return null;
  const rows: readonly [string, HostPermission][] = [
    [`${profile}/Desktop`, "files_desktop"],
    [`${profile}/OneDrive/Desktop`, "files_desktop"],
    [`${profile}/Documents`, "files_documents"],
    [`${profile}/OneDrive/Documents`, "files_documents"],
    [`${profile}/Downloads`, "files_downloads"],
    [`${profile}/OneDrive/Downloads`, "files_downloads"],
  ];
  let best: { length: number; permission: HostPermission } | null = null;
  for (const [prefix, permission] of rows) {
    if (under(path, prefix) && (best === null || prefix.length > best.length)) {
      best = { length: prefix.length, permission };
    }
  }
  return best?.permission ?? null;
}

/**
 * Whether `path` is under a Windows system location no switch grants:
 * `%windir%` and both Program Files trees. The SIP analog — a refusal here
 * is not a permission the owner can flip. Canonical path in.
 */
export function windowsSystemProtected(path: string): boolean {
  const windir = process.env.SystemRoot ?? process.env.windir ?? "C:\\Windows";
  const roots = [
    windir,
    process.env.ProgramFiles ?? "C:\\Program Files",
    process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)",
    process.env.ProgramData ?? "C:\\ProgramData",
  ];
  return roots.some((root) => under(path, root));
}

/** One guarded folder's outcome for the standing inventory. */
export interface WindowsFolderProbe {
  path: string;
  outcome: "ok" | "ENOENT" | "EACCES" | "EPERM" | string;
}

/**
 * The standing folder-access snapshot for the inventory's Full Disk Access
 * row on Windows. Same shape as `probeFullDiskAccessDetail`, deliberately:
 * the inventory, the Settings pane and `plow_device_status` read one row.
 *
 * What "granted" means here is narrower than on macOS and says so: every
 * guarded folder that EXISTS lists. Controlled Folder Access gates writes,
 * not reads, so this row cannot prove a write will land — only the attempt
 * proves that, and the diagnosis owns it. A missing folder (OneDrive not
 * backing it up) proves nothing and is skipped.
 */
export async function probeWindowsFolderAccessDetail(
  userProfile: string = process.env.USERPROFILE ?? "",
): Promise<{ granted: boolean; results: FullDiskProbeResult[] }> {
  const results: FullDiskProbeResult[] = (await probeWindowsFolderAccess(userProfile)).map((r) => ({
    path: r.path,
    outcome: r.outcome,
  }));
  const considered = results.filter((r) => r.outcome !== "ENOENT");
  const granted = considered.length > 0 && considered.every((r) => r.outcome === "ok");
  return { granted, results };
}

/**
 * What the app itself can list right now, one fresh read per guarded folder.
 * `readdir` (not open) is the probe: these are folders, and a listing is what
 * trips a read gate on one. ENOENT proves nothing — OneDrive may simply not
 * back that folder up — and is skipped downstream; a refusal is the story.
 */
export async function probeWindowsFolderAccess(
  userProfile: string = process.env.USERPROFILE ?? "",
): Promise<WindowsFolderProbe[]> {
  const folders = ["Desktop", "Documents", "Downloads", "Pictures", "OneDrive/Desktop", "OneDrive/Documents"].map(
    (f) => path.join(userProfile, f),
  );
  const results: WindowsFolderProbe[] = [];
  for (const folder of folders) {
    try {
      await fs.readdir(folder);
      results.push({ path: folder, outcome: "ok" });
    } catch (error: unknown) {
      const code = (error as { code?: unknown })?.code;
      results.push({ path: folder, outcome: typeof code === "string" ? code : "error" });
    }
  }
  return results;
}
