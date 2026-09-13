import { afterEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../..", import.meta.url));
const verifier = path.join(root, "scripts", "verify-linux-release-feed.mjs");
const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) fs.rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("Linux release feed digest gate", () => {
  const run = (dir: string, arch = "x64") =>
    spawnSync(process.execPath, [verifier, dir, "--arch", arch], { encoding: "utf8" });

  it("refuses a directory without an AppImage", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-linux-feed-"));
    dirs.push(dir);
    const result = run(dir);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("no Plow Latch x64 AppImage");
  });

  it("refuses a feed that names the AppImage but carries no sha512", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-linux-feed-"));
    dirs.push(dir);
    const name = "Plow-Latch-0.1.1-x64.AppImage";
    fs.writeFileSync(path.join(dir, name), "payload");
    fs.writeFileSync(path.join(dir, "latest-linux.yml"), `version: 0.1.1\npath: ${name}\n`);
    const result = run(dir);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("has no sha512");
  });

  it("refuses a feed whose sha512 is not the file on disk", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-linux-feed-"));
    dirs.push(dir);
    const name = "Plow-Latch-0.1.1-x64.AppImage";
    fs.writeFileSync(path.join(dir, name), "payload");
    fs.writeFileSync(
      path.join(dir, "latest-linux.yml"),
      `version: 0.1.1\npath: ${name}\nsha512: ${"A".repeat(88)}\n`,
    );
    const result = run(dir);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("sha512 does not match");
  });

  it("accepts a feed whose sha512 is the AppImage bytes", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-linux-feed-"));
    dirs.push(dir);
    const name = "Plow-Latch-0.1.1-x64.AppImage";
    const bytes = Buffer.from("payload");
    fs.writeFileSync(path.join(dir, name), bytes);
    const digest = createHash("sha512").update(bytes).digest("base64");
    fs.writeFileSync(
      path.join(dir, "latest-linux.yml"),
      `version: 0.1.1\nfiles:\n  - url: ${name}\n    sha512: ${digest}\npath: ${name}\nsha512: ${digest}\n`,
    );
    const result = run(dir);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("sha512 matches");
  });
});
