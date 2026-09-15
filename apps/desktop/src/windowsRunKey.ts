/**
 * HKCU Run fallback for Launch at Login on Windows. Electron's
 * setLoginItemSettings is tried first; this seam is only the writer the
 * platform login-item API calls when a get-after-set disagrees.
 *
 * `reg.exe` — no PowerShell. The argv builders live beside the parser so a
 * test can pin the command without touching a real hive.
 */
import { execFileSync } from "node:child_process";
import {
  WINDOWS_RUN_VALUE,
  windowsRunAddArgs,
  windowsRunDeleteArgs,
  windowsRunKeyPresent,
  windowsRunQueryArgs,
} from "./loginItemPlatform.js";

export interface RegRunner {
  (args: string[]): string;
}

function defaultReg(args: string[]): string {
  return execFileSync("reg", args, { encoding: "utf8", windowsHide: true });
}

export function readWindowsRunKey(run: RegRunner = defaultReg): boolean {
  try {
    return windowsRunKeyPresent(run(windowsRunQueryArgs()));
  } catch {
    return false;
  }
}

export function writeWindowsRunKey(openAtLogin: boolean, exePath: string, run: RegRunner = defaultReg): void {
  try {
    if (openAtLogin) run(windowsRunAddArgs(exePath));
    else run(windowsRunDeleteArgs());
  } catch {
    /* a refused write is reported by the next get */
  }
}

export function windowsRunSeam(run: RegRunner = defaultReg): {
  get(): boolean;
  set(openAtLogin: boolean, exePath: string): void;
} {
  return {
    get: () => readWindowsRunKey(run),
    set: (openAtLogin, exePath) => writeWindowsRunKey(openAtLogin, exePath, run),
  };
}

export { WINDOWS_RUN_VALUE };
