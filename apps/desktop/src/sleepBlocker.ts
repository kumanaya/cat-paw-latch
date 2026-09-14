/**
 * The OS sleep-blocker factory KeepAwake consumes. The AC-only / debounce /
 * revert rules stay in keepAwake.ts; this file only starts and stops the
 * hold the current platform can actually keep.
 *
 * - darwin: `caffeinate -dims -w <pid>` (the four IOKit assertions).
 * - win32: Electron `prevent-display-sleep` + `prevent-app-suspension`.
 * - linux: `systemd-inhibit --what=idle:sleep` (not lid-switch), then the
 *   same Electron pair if the binary is missing.
 */
import { spawn as nodeSpawn, execFileSync } from "node:child_process";
import type { SleepBlocker } from "./keepAwake.js";

export const SYSTEMD_INHIBIT = "systemd-inhibit";
export const CAFFEINATE = "/usr/bin/caffeinate";

export const KEEP_AWAKE_WHY = "Keep this Desktop awake while plugged in";

export interface PowerSaveBlockerApi {
  start(type: string): number;
  stop(id: number): boolean;
  isStarted?(id: number): boolean;
}

export type SleepChild = {
  pid?: number;
  on(event: "error" | "exit", listener: (...args: unknown[]) => void): void;
  kill(signal?: NodeJS.Signals): boolean;
};

export type SleepSpawn = (command: string, args: readonly string[], options?: { stdio?: "ignore" }) => SleepChild;

export interface SleepBlockerDeps {
  platform: NodeJS.Platform;
  pid: number;
  spawn?: SleepSpawn;
  powerSaveBlocker?: PowerSaveBlockerApi;
  /** Override for tests; production looks for systemd-inhibit on PATH. */
  commandExists?: (command: string) => boolean;
  /** Unexpected child exit (caffeinate / systemd-inhibit died). */
  onLost?: (id: number) => void;
}

export function systemdInhibitArgs(why: string = KEEP_AWAKE_WHY): string[] {
  return [
    "--what=idle:sleep",
    "--who=Plow Latch",
    `--why=${why}`,
    "--mode=block",
    "sleep",
    "infinity",
  ];
}

export function caffeinateArgs(pid: number): string[] {
  return ["-dims", "-w", String(pid)];
}

export function commandOnPath(command: string): boolean {
  try {
    execFileSync("command", ["-v", command], { stdio: "ignore" });
    return true;
  } catch {
    try {
      execFileSync("/usr/bin/which", [command], { stdio: "ignore" });
      return true;
    } catch {
      return false;
    }
  }
}

function childBlocker(
  spawn: SleepSpawn,
  command: string,
  args: readonly string[],
  onLost?: (id: number) => void,
): SleepBlocker {
  let held: { pid: number; stopped: boolean; kill: () => void } | null = null;
  return {
    start() {
      const child = spawn(command, args, { stdio: "ignore" });
      child.on("error", () => {});
      if (child.pid === undefined) return null;
      const entry = { pid: child.pid, stopped: false, kill: () => child.kill() };
      held = entry;
      child.on("exit", () => {
        if (entry.stopped || held !== entry) return;
        held = null;
        onLost?.(entry.pid);
      });
      return entry.pid;
    },
    stop(id) {
      if (held?.pid !== id) return;
      held.stopped = true;
      held.kill();
      held = null;
    },
  };
}

function electronSleepBlocker(psb: PowerSaveBlockerApi): SleepBlocker {
  let ids: number[] = [];
  return {
    start() {
      const display = psb.start("prevent-display-sleep");
      const idle = psb.start("prevent-app-suspension");
      const held = [display, idle].filter((id) => typeof id === "number" && (psb.isStarted ? psb.isStarted(id) : true));
      if (held.length === 0) return null;
      ids = held;
      return ids[0]!;
    },
    stop() {
      for (const id of ids) psb.stop(id);
      ids = [];
    },
  };
}

const none: SleepBlocker = {
  start: () => null,
  stop: () => {},
};

export function createSleepBlocker(deps: SleepBlockerDeps): SleepBlocker {
  const spawn: SleepSpawn =
    deps.spawn ?? ((command, args, options) => nodeSpawn(command, [...args], options ?? { stdio: "ignore" }));
  const exists = deps.commandExists ?? commandOnPath;
  if (deps.platform === "darwin") {
    return childBlocker(spawn, CAFFEINATE, caffeinateArgs(deps.pid), deps.onLost);
  }
  if (deps.platform === "win32") {
    return deps.powerSaveBlocker ? electronSleepBlocker(deps.powerSaveBlocker) : none;
  }
  if (deps.platform === "linux") {
    if (exists(SYSTEMD_INHIBIT)) {
      return childBlocker(spawn, SYSTEMD_INHIBIT, systemdInhibitArgs(), deps.onLost);
    }
    return deps.powerSaveBlocker ? electronSleepBlocker(deps.powerSaveBlocker) : none;
  }
  return none;
}
