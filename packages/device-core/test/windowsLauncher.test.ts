import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { serializeWindowsLaunchConfig } from "@domo/device-core";

const ON_WINDOWS = process.platform === "win32";
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const launcher = path.join(repo, "packages", "native-winsandbox", "build", "Release", "winsandbox_launcher.exe");

describe.skipIf(!ON_WINDOWS)("Windows AppContainer launcher artifact", () => {
  it("is built and exposes only its fail-closed probe before the staged-workspace protocol", () => {
    expect(fs.existsSync(launcher)).toBe(true);
    expect(execFileSync(launcher, ["--probe"], { windowsHide: true }).length).toBe(0);
    try {
      execFileSync(launcher, ["not-a-protocol"], { windowsHide: true, stdio: "pipe" });
      throw new Error("launcher unexpectedly accepted an untrusted command interface");
    } catch (error) {
      expect((error as { status?: number }).status).toBe(64);
    }
  });

  it("launches only from the private config and deletes it before the AppContainer child starts", () => {
    const dir = fs.mkdtempSync(path.join(repo, "packages", "native-winsandbox", "build", "launcher-test-"));
    try {
      const config = path.join(dir, "private.config");
      const child = path.join(dir, "child.exe");
      fs.copyFileSync(launcher, child);
      fs.writeFileSync(config, serializeWindowsLaunchConfig({
        workspace: dir,
        cwd: dir,
        argv: [child, "--probe"],
        network: false,
        env: {
          ComSpec: process.env.ComSpec ?? "C:\\Windows\\System32\\cmd.exe",
          LOCALAPPDATA: dir,
          OS: "Windows_NT",
          PATHEXT: process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD",
          Path: process.env.Path ?? "C:\\Windows\\System32;C:\\Windows",
          SystemDrive: process.env.SystemDrive ?? "C:",
          SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
          TEMP: dir,
          TMP: dir,
          windir: process.env.SystemRoot ?? "C:\\Windows",
        },
      }));
      expect(spawnSync(launcher, ["--config", config], { windowsHide: true }).status).toBe(0);
      expect(fs.existsSync(config)).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
