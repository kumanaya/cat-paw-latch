/** Private, non-shell protocol from Executor to winsandbox_launcher.exe. */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

export interface WindowsLaunchConfig {
  readonly workspace: string;
  readonly cwd: string;
  /** Absolute executable path followed by its arguments; never shell text. */
  readonly argv: readonly string[];
  readonly network: boolean;
  /**
   * Trusted executable/runtime trees the AppContainer may read and execute.
   * These are never capability paths and must be supplied by Latch itself.
   * The launcher grants them read/execute only; all mutable state stays in
   * `workspace`.
   */
  readonly runtimeRoots?: readonly string[];
  /** Complete child environment, not a merge with the Electron process. */
  readonly env: Readonly<Record<string, string>>;
}

export class WindowsLaunchConfigError extends Error {}

interface NativeFs {
  lockdownFile(file: string): string;
}

function nativeFs(): NativeFs | null {
  try {
    return createRequire(import.meta.url)("@domo/native-fs") as NativeFs | null;
  } catch {
    return null;
  }
}

function encode(value: string): string {
  if (value.includes("\0") || value.includes("\r") || value.includes("\n")) {
    throw new WindowsLaunchConfigError("launcher configuration contains an invalid control character");
  }
  return Buffer.from(value, "utf8").toString("base64");
}

/**
 * Line framing is intentionally narrow and binary-safe: every agent-provided
 * value is base64, and the native helper accepts only the fixed labels below.
 * It never sees a shell command line constructed from these values.
 */
export function serializeWindowsLaunchConfig(config: WindowsLaunchConfig): Buffer {
  if (config.argv.length === 0) throw new WindowsLaunchConfigError("launcher configuration needs an executable");
  const lines = [
    "PLOW-LATCH-APPCONTAINER-1",
    `network ${config.network ? "1" : "0"}`,
    `workspace ${encode(config.workspace)}`,
    `cwd ${encode(config.cwd)}`,
    `application ${encode(config.argv[0])}`,
  ];
  for (const arg of config.argv.slice(1)) lines.push(`arg ${encode(arg)}`);
  for (const root of [...(config.runtimeRoots ?? [])].sort()) lines.push(`runtime ${encode(root)}`);
  for (const [key, value] of Object.entries(config.env).sort(([a], [b]) => a.localeCompare(b))) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new WindowsLaunchConfigError("launcher environment key is invalid");
    lines.push(`env ${encode(key)} ${encode(value)}`);
  }
  return Buffer.from(lines.join("\n") + "\n", "ascii");
}

/**
 * Write a per-run config that only the current owner may read. This is a hard
 * gate on Windows: a provider token is a secret, and inherited NTFS ACLs are
 * not a safe substitute for the native owner-only DACL.
 */
export function writeWindowsLaunchConfig(scratch: string, config: WindowsLaunchConfig): string {
  if (process.platform !== "win32") throw new WindowsLaunchConfigError("Windows launcher config requested off Windows");
  const addon = nativeFs();
  if (!addon) throw new WindowsLaunchConfigError("native Windows ACL addon is unavailable; refusing to write launcher config");
  const file = path.join(scratch, `.appcontainer-${crypto.randomUUID()}.config`);
  try {
    fs.writeFileSync(file, serializeWindowsLaunchConfig(config), { flag: "wx", mode: 0o600 });
    addon.lockdownFile(file);
    return file;
  } catch (error) {
    try { fs.rmSync(file, { force: true }); } catch {}
    throw error;
  }
}
