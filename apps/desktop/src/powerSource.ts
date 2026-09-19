/**
 * Host power source for the Keep-Awake gate. macOS and Windows read it from
 * Electron's `powerMonitor`; Linux cannot — Electron stubs
 * `isOnBatteryPower()` to `false` and never emits `on-ac`/`on-battery` there,
 * so a laptop would be held awake as if permanently plugged in until the app
 * quits or the owner flips the switch. Linux reads sysfs instead, and polls,
 * because sysfs offers no change notification without a udev/D-Bus
 * dependency.
 *
 * Pure over an injected fs, so the parsing is unit-testable on any host.
 */
import fs from "node:fs";
import path from "node:path";
import type { PowerSource, PowerSourceObserver } from "./keepAwake.js";

/** Where the kernel exposes power supplies. */
export const SYS_POWER_SUPPLY = "/sys/class/power_supply";

export interface PowerSourceFs {
  readdir(dir: string): string[];
  readFile(file: string): string | null;
}

export const nodePowerFs: PowerSourceFs = {
  readdir(dir) {
    try {
      return fs.readdirSync(dir);
    } catch {
      return [];
    }
  },
  readFile(file) {
    try {
      return fs.readFileSync(file, "utf8");
    } catch {
      return null;
    }
  },
};

/**
 * "ac" when an AC adapter reports online, "battery" when a battery exists and
 * none does, and "ac" when the host exposes neither — a desktop or a VM,
 * which has no battery to drain, the same answer `powerMonitor` gives a
 * machine with no battery.
 */
export function readLinuxPowerSource(
  fsImpl: PowerSourceFs,
  root: string = SYS_POWER_SUPPLY,
): PowerSource {
  let hasBattery = false;
  let online = false;
  for (const name of fsImpl.readdir(root)) {
    const type = (fsImpl.readFile(path.posix.join(root, name, "type")) ?? "").trim();
    if (type === "Battery") {
      hasBattery = true;
    } else if (type === "Mains" || type === "USB" || type === "AC") {
      if ((fsImpl.readFile(path.posix.join(root, name, "online")) ?? "").trim() === "1") online = true;
    }
  }
  if (online) return "ac";
  return hasBattery ? "battery" : "ac";
}

/**
 * A polling observer over sysfs. The interval is deliberately coarse: the
 * KeepAwake debounce already absorbs charger flap, and a power transition is
 * not a latency-sensitive event. Timers are injectable so a test can drive
 * transitions without real time.
 */
export function sysfsPowerSource(opts: {
  fs?: PowerSourceFs;
  root?: string;
  intervalMs?: number;
  setInterval?: (callback: () => void, ms: number) => unknown;
  clearInterval?: (handle: unknown) => void;
} = {}): PowerSourceObserver {
  const fsImpl = opts.fs ?? nodePowerFs;
  const root = opts.root ?? SYS_POWER_SUPPLY;
  const intervalMs = opts.intervalMs ?? 20_000;
  const set = opts.setInterval ?? ((callback, ms) => setInterval(callback, ms));
  const clear = opts.clearInterval ?? ((handle) => clearInterval(handle as NodeJS.Timeout));
  const read = (): PowerSource => readLinuxPowerSource(fsImpl, root);
  return {
    current: read,
    subscribe(callback) {
      let last = read();
      const handle = set(() => {
        const next = read();
        if (next === last) return;
        last = next;
        callback(next);
      }, intervalMs);
      return () => clear(handle);
    },
  };
}
