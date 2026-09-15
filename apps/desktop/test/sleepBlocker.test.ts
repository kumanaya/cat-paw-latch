import { describe, expect, it } from "vitest";
import {
  caffeinateArgs,
  CAFFEINATE,
  createSleepBlocker,
  SYSTEMD_INHIBIT,
  systemdInhibitArgs,
} from "../src/sleepBlocker.js";

function fakeChild(pid: number | undefined) {
  const listeners: Record<string, ((...args: unknown[]) => void)[]> = { error: [], exit: [] };
  return {
    pid,
    on(event: "error" | "exit", listener: (...args: unknown[]) => void) {
      listeners[event]!.push(listener);
    },
    kill() {
      return true;
    },
    listeners,
  };
}

describe("systemdInhibitArgs", () => {
  it("blocks idle and sleep, never the lid switch", () => {
    const args = systemdInhibitArgs();
    expect(args).toContain("--what=idle:sleep");
    expect(args).toContain("--mode=block");
    expect(args.join(" ")).not.toMatch(/handle-lid-switch/);
    expect(args).toContain("sleep");
    expect(args).toContain("infinity");
  });
});

describe("createSleepBlocker", () => {
  it("darwin spawns caffeinate -dims bound to this pid", () => {
    const spawned: { cmd: string; args: readonly string[] }[] = [];
    const child = fakeChild(42);
    const blocker = createSleepBlocker({
      platform: "darwin",
      pid: 99,
      spawn: (cmd, args) => {
        spawned.push({ cmd, args });
        return child;
      },
    });
    expect(blocker.start()).toBe(42);
    expect(spawned).toEqual([{ cmd: CAFFEINATE, args: caffeinateArgs(99) }]);
  });

  it("linux and windows return null when the OS command is absent", () => {
    const linux = createSleepBlocker({
      platform: "linux",
      pid: 1,
      commandExists: () => false,
      spawn: () => {
        throw new Error("must not spawn");
      },
    });
    expect(linux.start()).toBeNull();

    const win = createSleepBlocker({
      platform: "win32",
      pid: 1,
      spawn: () => {
        throw new Error("must not spawn");
      },
    });
    expect(win.start()).toBeNull();
  });

  it("linux uses systemd-inhibit when present, else Electron's pair", () => {
    const child = fakeChild(7);
    const systemd = createSleepBlocker({
      platform: "linux",
      pid: 1,
      commandExists: (cmd) => cmd === SYSTEMD_INHIBIT,
      spawn: (cmd) => {
        expect(cmd).toBe(SYSTEMD_INHIBIT);
        return child;
      },
    });
    expect(systemd.start()).toBe(7);

    const started: string[] = [];
    const electron = createSleepBlocker({
      platform: "linux",
      pid: 1,
      commandExists: () => false,
      powerSaveBlocker: {
        start: (type) => {
          started.push(type);
          return started.length;
        },
        stop: () => true,
        isStarted: () => true,
      },
    });
    expect(electron.start()).toBe(1);
    expect(started).toEqual(["prevent-display-sleep", "prevent-app-suspension"]);
  });

  it("win32 starts the honest Electron pair, and a refused start is null", () => {
    const ok = createSleepBlocker({
      platform: "win32",
      pid: 1,
      powerSaveBlocker: {
        start: (type) => (type === "prevent-display-sleep" ? 3 : 4),
        stop: () => true,
        isStarted: () => true,
      },
    });
    expect(ok.start()).toBe(3);

    const refused = createSleepBlocker({
      platform: "win32",
      pid: 1,
      powerSaveBlocker: {
        start: () => 0,
        stop: () => true,
        isStarted: () => false,
      },
    });
    expect(refused.start()).toBeNull();
  });
});
