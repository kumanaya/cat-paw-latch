import { afterEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { windowsCodePayloads } from "../../../scripts/verify-windows-release-signature.mjs";

const root = fileURLToPath(new URL("../../..", import.meta.url));
const verifier = path.join(root, "scripts", "verify-windows-release-signature.mjs");
const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) fs.rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe.skipIf(process.platform !== "win32")("Windows release signature gate", () => {
  const run = (dir: string) => spawnSync(
    process.execPath,
    [verifier, dir, "The Plow Collective, Inc."],
    { encoding: "utf8" },
  );

  it("refuses a directory without an installer", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-signature-test-"));
    dirs.push(dir);
    const result = run(dir);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("no Plow Latch Windows installer");
  });

  it("refuses an unsigned installer before it can become an update", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-signature-test-"));
    dirs.push(dir);
    fs.writeFileSync(path.join(dir, "Plow-Latch-0.1.1-x64.exe"), "not a PE");
    const result = run(dir);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("invalid Authenticode signature");
  });

  it("refuses an unsigned native payload even when the installer is present", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-signature-test-"));
    dirs.push(dir);
    fs.writeFileSync(path.join(dir, "Plow-Latch-0.1.1-x64.exe"), "not a PE");
    const addon = path.join(dir, "win-unpacked", "resources", "app.asar.unpacked", "node_modules", "addon.node");
    fs.mkdirSync(path.dirname(addon), { recursive: true });
    fs.writeFileSync(addon, "not a PE");
    const result = run(dir);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("invalid Authenticode signature");
  });

  it("includes nested executable payloads in the signature verification set", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-signature-test-"));
    dirs.push(dir);
    const installer = path.join(dir, "Plow-Latch-0.1.1-x64.exe");
    const addon = path.join(dir, "win-unpacked", "resources", "app.asar.unpacked", "node_modules", "addon.node");
    const dll = path.join(dir, "win-unpacked", "resources", "browser-runtime", "browser.dll");
    fs.mkdirSync(path.dirname(addon), { recursive: true });
    fs.mkdirSync(path.dirname(dll), { recursive: true });
    fs.writeFileSync(installer, "installer");
    fs.writeFileSync(addon, "addon");
    fs.writeFileSync(dll, "dll");
    expect(windowsCodePayloads(dir)).toEqual(expect.arrayContaining([installer, addon, dll]));
  });
});
