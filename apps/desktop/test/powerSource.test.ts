/**
 * Linux is the one OS where Electron's powerMonitor cannot be trusted:
 * `isOnBatteryPower()` is stubbed to false and no on-ac/on-battery events
 * fire, so the Keep-Awake gate would hold a laptop awake until quit. These pin
 * the sysfs read that replaces it, and the poller that turns a change into a
 * transition — the exact behavior that used to be silently missing.
 */
import { describe, expect, it } from "vitest";
import type { PowerSource } from "../src/keepAwake.js";
import {
  readLinuxPowerSource,
  sysfsPowerSource,
  type PowerSourceFs,
} from "../src/powerSource.js";

/** A fake /sys/class/power_supply keyed by supply name. */
function supplies(entries: Record<string, { type: string; online?: string }>): PowerSourceFs {
  return {
    readdir: () => Object.keys(entries),
    readFile: (file) => {
      const parts = file.split("/");
      const name = parts[parts.length - 2];
      const field = parts[parts.length - 1];
      const supply = entries[name];
      if (!supply) return null;
      if (field === "type") return supply.type;
      if (field === "online") return supply.online ?? null;
      return null;
    },
  };
}

describe("readLinuxPowerSource", () => {
  it("is ac when a Mains adapter is online", () => {
    expect(readLinuxPowerSource(supplies({ AC: { type: "Mains", online: "1" } }), "/ps")).toBe("ac");
  });

  it("is battery when a battery exists and no adapter is online", () => {
    const fs = supplies({
      AC: { type: "Mains", online: "0" },
      BAT0: { type: "Battery" },
    });
    expect(readLinuxPowerSource(fs, "/ps")).toBe("battery");
  });

  it("is ac when a battery exists but the adapter is online", () => {
    const fs = supplies({
      AC: { type: "Mains", online: "1" },
      BAT0: { type: "Battery" },
    });
    expect(readLinuxPowerSource(fs, "/ps")).toBe("ac");
  });

  it("is battery when only a battery is present (no adapter node)", () => {
    expect(readLinuxPowerSource(supplies({ BAT0: { type: "Battery" } }), "/ps")).toBe("battery");
  });

  it("is ac on a host with no power supplies at all (desktop, VM)", () => {
    expect(readLinuxPowerSource(supplies({}), "/ps")).toBe("ac");
  });

  it("counts USB-C power as an adapter", () => {
    const fs = supplies({ ucsi: { type: "USB", online: "1" }, BAT0: { type: "Battery" } });
    expect(readLinuxPowerSource(fs, "/ps")).toBe("ac");
  });
});

describe("sysfsPowerSource", () => {
  it("reads current state and emits a transition when the adapter drops", () => {
    let online = "1";
    const fs: PowerSourceFs = {
      readdir: () => ["AC", "BAT0"],
      readFile: (file) => {
        if (file.includes("/AC/type")) return "Mains";
        if (file.includes("/AC/online")) return online;
        if (file.includes("/BAT0/type")) return "Battery";
        return null;
      },
    };
    let tick: (() => void) | null = null;
    const seen: PowerSource[] = [];
    const observer = sysfsPowerSource({
      fs,
      root: "/ps",
      setInterval: (callback) => {
        tick = callback;
        return 1;
      },
      clearInterval: () => {},
    });
    expect(observer.current()).toBe("ac");
    const unsubscribe = observer.subscribe((source) => seen.push(source));
    online = "0";
    tick?.();
    expect(seen).toEqual(["battery"]);
    online = "1";
    tick?.();
    expect(seen).toEqual(["battery", "ac"]);
    unsubscribe();
  });

  it("does not emit when the polled state is unchanged", () => {
    const fs: PowerSourceFs = {
      readdir: () => ["AC"],
      readFile: (file) => (file.endsWith("type") ? "Mains" : "1"),
    };
    let tick: (() => void) | null = null;
    const seen: PowerSource[] = [];
    const observer = sysfsPowerSource({
      fs,
      root: "/ps",
      setInterval: (callback) => {
        tick = callback;
        return 1;
      },
      clearInterval: () => {},
    });
    observer.subscribe((source) => seen.push(source));
    tick?.();
    tick?.();
    expect(seen).toEqual([]);
  });
});
