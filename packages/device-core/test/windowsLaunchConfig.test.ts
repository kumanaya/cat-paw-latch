import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { WindowsLaunchConfigError, serializeWindowsLaunchConfig, writeWindowsLaunchConfig } from "@domo/device-core";

const cleanups: string[] = [];
afterEach(() => {
  while (cleanups.length) fs.rmSync(cleanups.pop()!, { recursive: true, force: true });
});

const config = {
  workspace: "C:\\owner\\scratch\\workspace",
  cwd: "C:\\owner\\scratch\\workspace",
  argv: ["C:\\Windows\\System32\\whoami.exe", "a b", "& not shell"],
  network: false,
  env: { TEMP: "C:\\owner\\scratch", PROVIDER_TOKEN: "secret value" },
};

describe("Windows launch config encoding", () => {
  it("uses fixed labels and base64 values, never a shell command line", () => {
    const text = serializeWindowsLaunchConfig(config).toString("ascii");
    expect(text).toMatch(/^PLOW-LATCH-APPCONTAINER-1\nnetwork 0\n/);
    expect(text).not.toContain("& not shell");
    expect(text).not.toContain("secret value");
    expect(text).toContain(`application ${Buffer.from(config.argv[0], "utf8").toString("base64")}`);
  });

  it("rejects control characters and unsafe environment names", () => {
    expect(() => serializeWindowsLaunchConfig({ ...config, argv: ["x\ny"] })).toThrow(WindowsLaunchConfigError);
    expect(() => serializeWindowsLaunchConfig({ ...config, env: { "BAD-NAME": "x" } })).toThrow(WindowsLaunchConfigError);
  });

  it.skipIf(process.platform !== "win32")("writes a native-ACL-locked private config", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-launch-config-"));
    cleanups.push(dir);
    const file = writeWindowsLaunchConfig(dir, config);
    expect(fs.existsSync(file)).toBe(true);
    expect(fs.readFileSync(file, "ascii")).not.toContain("secret value");
  });
});
