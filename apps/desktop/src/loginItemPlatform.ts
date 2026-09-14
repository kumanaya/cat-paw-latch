/**
 * OS seams behind Launch at Login. loginItem.ts owns the packaged-only
 * rules; this file is what those rules write — Electron on macOS, the same
 * API with an explicit exe path on Windows, and an XDG autostart file on
 * Linux so an AppImage does not register its squashfs mount.
 */
import fs from "node:fs";
import path from "node:path";
import { LoginItemApi } from "./loginItem.js";

/** Basename under ~/.config/autostart/. Stable so get/set share one file. */
export const LINUX_AUTOSTART_BASENAME = "plow-latch.desktop";

/** HKCU Run value name. Distinct from Electron's default so a fallback write
 *  is ours to delete. */
export const WINDOWS_RUN_VALUE = "PlowLatch";

export const WINDOWS_RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";

/** The process that should come back after login. An AppImage must use
 *  `$APPIMAGE` — `process.execPath` is the squashfs mount, which is gone
 *  the moment Latch quits. */
export function linuxLaunchExec(env: NodeJS.ProcessEnv, execPath: string): string {
  const appImage = (env.APPIMAGE ?? "").trim();
  return appImage.length > 0 ? appImage : execPath;
}

export function linuxAutostartPath(home: string): string {
  return path.join(home, ".config", "autostart", LINUX_AUTOSTART_BASENAME);
}

/** Get = the file exists and is not Hidden=true. A missing file is off. */
export function isLinuxAutostartEnabled(contents: string | null): boolean {
  if (contents === null) return false;
  if (/^Hidden\s*=\s*true\s*$/im.test(contents)) return false;
  return /^\[Desktop Entry\]/m.test(contents);
}

/** Quote only when the Exec= path needs it (spaces or quotes). */
export function quoteDesktopExec(exec: string): string {
  if (!/[\s"]/.test(exec)) return exec;
  return `"${exec.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function linuxAutostartDesktop(exec: string): string {
  return [
    "[Desktop Entry]",
    "Type=Application",
    "Name=Plow Latch",
    "Comment=Approve what a remote AI agent does on this computer",
    `Exec=${quoteDesktopExec(exec)}`,
    "Hidden=false",
    "X-GNOME-Autostart-enabled=true",
    "StartupNotify=false",
    "",
  ].join("\n");
}

/** Electron's setLoginItemSettings payload on Windows: the real packaged
 *  exe, never a stale electron.exe from a previous run. */
export function electronLoginSettings(openAtLogin: boolean, execPath: string): {
  openAtLogin: boolean;
  path: string;
  args: string[];
} {
  return { openAtLogin, path: execPath, args: [] };
}

export function windowsRunAddArgs(exePath: string): string[] {
  return ["add", WINDOWS_RUN_KEY, "/v", WINDOWS_RUN_VALUE, "/t", "REG_SZ", "/d", exePath, "/f"];
}

export function windowsRunDeleteArgs(): string[] {
  return ["delete", WINDOWS_RUN_KEY, "/v", WINDOWS_RUN_VALUE, "/f"];
}

export function windowsRunQueryArgs(): string[] {
  return ["query", WINDOWS_RUN_KEY, "/v", WINDOWS_RUN_VALUE];
}

/** Whether a `reg query` listing names our value. */
export function windowsRunKeyPresent(stdout: string): boolean {
  return /PlowLatch/i.test(stdout) && /REG_SZ/i.test(stdout);
}

export interface LoginItemFs {
  readFile(file: string): string | null;
  writeFile(file: string, contents: string): void;
  mkdirp(dir: string): void;
  unlink(file: string): void;
}

export interface WindowsRunSeam {
  get(): boolean;
  set(openAtLogin: boolean, exePath: string): void;
}

export interface ElectronLoginItems {
  get(): { openAtLogin: boolean };
  set(settings: { openAtLogin: boolean; path?: string; args?: string[] }): void;
}

export interface PlatformLoginItemDeps {
  platform: NodeJS.Platform;
  execPath: string;
  env: NodeJS.ProcessEnv;
  home: string;
  electron: ElectronLoginItems;
  fs?: LoginItemFs;
  windowsRun?: WindowsRunSeam;
}

const nodeFs: LoginItemFs = {
  readFile(file) {
    try {
      return fs.readFileSync(file, "utf8");
    } catch {
      return null;
    }
  },
  writeFile(file, contents) {
    fs.writeFileSync(file, contents, "utf8");
  },
  mkdirp(dir) {
    fs.mkdirSync(dir, { recursive: true });
  },
  unlink(file) {
    try {
      fs.unlinkSync(file);
    } catch {
      /* already gone */
    }
  },
};

/** Linux XDG autostart as a LoginItemApi. */
export function linuxLoginItems(deps: {
  home: string;
  env: NodeJS.ProcessEnv;
  execPath: string;
  fs?: LoginItemFs;
}): LoginItemApi {
  const io = deps.fs ?? nodeFs;
  const file = linuxAutostartPath(deps.home);
  return {
    get: () => ({ openAtLogin: isLinuxAutostartEnabled(io.readFile(file)) }),
    set: ({ openAtLogin }) => {
      if (!openAtLogin) {
        io.unlink(file);
        return;
      }
      io.mkdirp(path.dirname(file));
      io.writeFile(file, linuxAutostartDesktop(linuxLaunchExec(deps.env, deps.execPath)));
    },
  };
}

/** Windows: Electron first, then HKCU Run if a get-after-set disagrees. */
export function windowsLoginItems(deps: {
  execPath: string;
  electron: ElectronLoginItems;
  windowsRun?: WindowsRunSeam;
}): LoginItemApi {
  return {
    get: () => {
      if (deps.electron.get().openAtLogin) return { openAtLogin: true };
      return { openAtLogin: deps.windowsRun?.get() ?? false };
    },
    set: ({ openAtLogin }) => {
      deps.electron.set(electronLoginSettings(openAtLogin, deps.execPath));
      if (deps.electron.get().openAtLogin === openAtLogin) return;
      deps.windowsRun?.set(openAtLogin, deps.execPath);
    },
  };
}

/** Darwin: Electron's login-item API, unchanged. */
export function darwinLoginItems(electron: ElectronLoginItems): LoginItemApi {
  return {
    get: () => ({ openAtLogin: electron.get().openAtLogin }),
    set: ({ openAtLogin }) => electron.set({ openAtLogin }),
  };
}

export function createPlatformLoginItems(deps: PlatformLoginItemDeps): LoginItemApi {
  if (deps.platform === "linux") {
    return linuxLoginItems({
      home: deps.home,
      env: deps.env,
      execPath: deps.execPath,
      fs: deps.fs,
    });
  }
  if (deps.platform === "win32") {
    return windowsLoginItems({
      execPath: deps.execPath,
      electron: deps.electron,
      windowsRun: deps.windowsRun,
    });
  }
  return darwinLoginItems(deps.electron);
}
