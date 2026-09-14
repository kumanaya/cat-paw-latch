import { describe, expect, it } from "vitest";
import { launchAtLoginState, LoginItemApi, setLaunchAtLogin } from "../src/loginItem.js";
import {
  createPlatformLoginItems,
  electronLoginSettings,
  isLinuxAutostartEnabled,
  LINUX_AUTOSTART_BASENAME,
  linuxAutostartDesktop,
  linuxAutostartPath,
  linuxLaunchExec,
} from "../src/loginItemPlatform.js";

/** A stand-in for Electron's login-item API: a settable bit plus a call log. */
function fakeOs(openAtLogin = false) {
  const os = { openAtLogin, writes: [] as boolean[] };
  const api: LoginItemApi = {
    get: () => ({ openAtLogin: os.openAtLogin }),
    set: (settings) => {
      os.writes.push(settings.openAtLogin);
      os.openAtLogin = settings.openAtLogin;
    },
  };
  return { os, api };
}

describe("launchAtLoginState", () => {
  it("reports what the OS holds when supported", () => {
    const { api } = fakeOs(true);
    expect(launchAtLoginState(true, api)).toEqual({ supported: true, openAtLogin: true });
  });

  it("never even reads the OS when unsupported — the dev binary's answer is not this app's", () => {
    const api: LoginItemApi = {
      get: () => {
        throw new Error("must not be called");
      },
      set: () => {
        throw new Error("must not be called");
      },
    };
    expect(launchAtLoginState(false, api)).toEqual({ supported: false, openAtLogin: false });
  });
});

describe("setLaunchAtLogin", () => {
  it("writes the OS bit and answers with a fresh read", () => {
    const { os, api } = fakeOs(false);
    expect(setLaunchAtLogin(true, api, true)).toEqual({ supported: true, openAtLogin: true });
    expect(setLaunchAtLogin(true, api, false)).toEqual({ supported: true, openAtLogin: false });
    expect(os.writes).toEqual([true, false]);
  });

  it("coerces whatever IPC delivered to a boolean before the OS sees it", () => {
    const { os, api } = fakeOs(false);
    setLaunchAtLogin(true, api, "yes" as unknown);
    setLaunchAtLogin(true, api, undefined);
    expect(os.writes).toEqual([true, false]);
  });

  it("REFUSES to write from an unsupported (from-source) run, even via a replayed IPC call", () => {
    const { os, api } = fakeOs(false);
    expect(setLaunchAtLogin(false, api, true)).toEqual({ supported: false, openAtLogin: false });
    expect(os.writes).toEqual([]);
  });

  it("reports the OS's refusal rather than the request — the pane shows what is true", () => {
    const { api } = fakeOs(false);
    const stubborn: LoginItemApi = { get: api.get, set: () => {} };
    expect(setLaunchAtLogin(true, stubborn, true)).toEqual({ supported: true, openAtLogin: false });
  });
});

describe("linuxLaunchExec", () => {
  it("prefers APPIMAGE over the squashfs mount at execPath", () => {
    expect(linuxLaunchExec({ APPIMAGE: "/home/u/Applications/Plow-Latch.AppImage" }, "/tmp/.mount_Plow-Lxxxx/PlowLatch")).toBe(
      "/home/u/Applications/Plow-Latch.AppImage",
    );
  });

  it("falls back to execPath when APPIMAGE is unset (deb / unpacked)", () => {
    expect(linuxLaunchExec({}, "/opt/PlowLatch/PlowLatch")).toBe("/opt/PlowLatch/PlowLatch");
  });
});

describe("linux autostart desktop file", () => {
  it("writes Hidden=false and X-GNOME-Autostart-enabled, with the AppImage as Exec", () => {
    const body = linuxAutostartDesktop("/home/u/Applications/Plow-Latch.AppImage");
    expect(body).toContain("[Desktop Entry]");
    expect(body).toMatch(/^Hidden=false$/m);
    expect(body).toMatch(/^X-GNOME-Autostart-enabled=true$/m);
    expect(body).toMatch(/^Exec=\/home\/u\/Applications\/Plow-Latch\.AppImage$/m);
    expect(linuxAutostartPath("/home/u")).toBe(`/home/u/.config/autostart/${LINUX_AUTOSTART_BASENAME}`);
  });

  it("get is true only when the file exists and is not Hidden=true", () => {
    expect(isLinuxAutostartEnabled(null)).toBe(false);
    expect(isLinuxAutostartEnabled(linuxAutostartDesktop("/opt/PlowLatch"))).toBe(true);
    expect(isLinuxAutostartEnabled("[Desktop Entry]\nHidden=true\n")).toBe(false);
  });

  it("the Linux seam writes and deletes the desktop file, never Electron", () => {
    const files = new Map<string, string>();
    const electron = {
      get: () => {
        throw new Error("Electron login items must not be used on Linux");
      },
      set: () => {
        throw new Error("Electron login items must not be used on Linux");
      },
    };
    const api = createPlatformLoginItems({
      platform: "linux",
      execPath: "/tmp/.mount_Plow-Lxxxx/PlowLatch",
      env: { APPIMAGE: "/home/u/Applications/Plow-Latch.AppImage" },
      home: "/home/u",
      electron,
      fs: {
        readFile: (file) => files.get(file) ?? null,
        writeFile: (file, contents) => {
          files.set(file, contents);
        },
        mkdirp: () => {},
        unlink: (file) => {
          files.delete(file);
        },
      },
    });
    expect(setLaunchAtLogin(true, api, true)).toEqual({ supported: true, openAtLogin: true });
    const written = files.get("/home/u/.config/autostart/plow-latch.desktop");
    expect(written).toContain("Exec=/home/u/Applications/Plow-Latch.AppImage");
    expect(written).not.toContain("/tmp/.mount_");
    expect(setLaunchAtLogin(true, api, false)).toEqual({ supported: true, openAtLogin: false });
    expect(files.size).toBe(0);
  });
});

describe("windows login-item path", () => {
  it("passes the real exe path and empty args to Electron", () => {
    expect(electronLoginSettings(true, "C:\\Program Files\\Plow Latch\\Plow Latch.exe")).toEqual({
      openAtLogin: true,
      path: "C:\\Program Files\\Plow Latch\\Plow Latch.exe",
      args: [],
    });
  });

  it("falls back to the HKCU Run seam when Electron's get-after-set disagrees", () => {
    let electronBit = false;
    const run: { writes: { on: boolean; path: string }[] } = { writes: [] };
    const api = createPlatformLoginItems({
      platform: "win32",
      execPath: "C:\\Latch\\PlowLatch.exe",
      env: {},
      home: "C:\\Users\\u",
      electron: {
        get: () => ({ openAtLogin: electronBit }),
        set: () => {
          /* pretend the OS ignored the write */
        },
      },
      windowsRun: {
        get: () => run.writes.at(-1)?.on ?? false,
        set: (on, exePath) => {
          run.writes.push({ on, path: exePath });
        },
      },
    });
    expect(setLaunchAtLogin(true, api, true)).toEqual({ supported: true, openAtLogin: true });
    expect(run.writes).toEqual([{ on: true, path: "C:\\Latch\\PlowLatch.exe" }]);
  });
});
