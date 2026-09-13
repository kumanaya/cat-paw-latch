/** Private, non-shell protocol from Executor to linuxsandbox_launcher. */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface LinuxLaunchConfig {
  readonly workspace: string;
  readonly cwd: string;
  /** Absolute executable path followed by its arguments; never shell text. */
  readonly argv: readonly string[];
  readonly network: boolean;
  /** Complete child environment, not a merge with the Electron process. */
  readonly env: Readonly<Record<string, string>>;
}

export class LinuxLaunchConfigError extends Error {}

function encode(value: string): string {
  if (value.includes("\0") || value.includes("\r") || value.includes("\n")) {
    throw new LinuxLaunchConfigError("launcher configuration contains an invalid control character");
  }
  return Buffer.from(value, "utf8").toString("base64");
}

/**
 * Line framing is intentionally narrow and binary-safe: every agent-provided
 * value is base64, and the native helper accepts only the fixed labels below.
 * It never sees a shell command line constructed from these values.
 */
export function serializeLinuxLaunchConfig(config: LinuxLaunchConfig): Buffer {
  if (config.argv.length === 0) throw new LinuxLaunchConfigError("launcher configuration needs an executable");
  const lines = [
    "PLOW-LATCH-BWRAP-1",
    `network ${config.network ? "1" : "0"}`,
    `workspace ${encode(config.workspace)}`,
    `cwd ${encode(config.cwd)}`,
    `application ${encode(config.argv[0])}`,
  ];
  for (const arg of config.argv.slice(1)) lines.push(`arg ${encode(arg)}`);
  for (const [key, value] of Object.entries(config.env).sort(([a], [b]) => a.localeCompare(b))) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new LinuxLaunchConfigError("launcher environment key is invalid");
    lines.push(`env ${encode(key)} ${encode(value)}`);
  }
  return Buffer.from(lines.join("\n") + "\n", "ascii");
}

/**
 * Write a per-run config that only the current owner may read. chmod 0600 is
 * the Linux floor (same guarantee as settings.json); the launcher deletes the
 * file before the child starts so a provider token does not linger.
 */
export function writeLinuxLaunchConfig(scratch: string, config: LinuxLaunchConfig): string {
  if (process.platform !== "linux") throw new LinuxLaunchConfigError("Linux launcher config requested off Linux");
  const file = path.join(scratch, `.bwrap-${crypto.randomUUID()}.config`);
  try {
    fs.writeFileSync(file, serializeLinuxLaunchConfig(config), { flag: "wx", mode: 0o600 });
    return file;
  } catch (error) {
    try { fs.rmSync(file, { force: true }); } catch {}
    throw error;
  }
}
