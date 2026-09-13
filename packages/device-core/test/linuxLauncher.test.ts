import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { serializeLinuxLaunchConfig } from "@domo/device-core";

const ON_LINUX = process.platform === "linux";
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const launcher = path.join(repo, "packages", "native-linuxsandbox", "build", "Release", "linuxsandbox_launcher");

describe.skipIf(!ON_LINUX)("Linux bubblewrap launcher artifact", () => {
  it("is built and exposes only its fail-closed probe before the staged-workspace protocol", () => {
    expect(fs.existsSync(launcher)).toBe(true);
    expect(execFileSync(launcher, ["--probe"]).length).toBe(0);
    try {
      execFileSync(launcher, ["not-a-protocol"], { stdio: "pipe" });
      throw new Error("launcher unexpectedly accepted an untrusted command interface");
    } catch (error) {
      expect((error as { status?: number }).status).toBe(64);
    }
  });

  it("launches only from the private config and deletes it before the bwrap child starts", () => {
    const dir = fs.mkdtempSync(path.join(repo, "packages", "native-linuxsandbox", "build", "launcher-test-"));
    try {
      const config = path.join(dir, "private.config");
      const child = path.join(dir, "true");
      fs.copyFileSync("/usr/bin/true", child);
      fs.chmodSync(child, 0o755);
      fs.writeFileSync(config, serializeLinuxLaunchConfig({
        workspace: dir,
        cwd: dir,
        argv: [child],
        network: false,
        env: {
          HOME: dir,
          PATH: "/usr/bin:/bin",
          TMPDIR: dir,
        },
      }));
      expect(spawnSync(launcher, ["--config", config]).status).toBe(0);
      expect(fs.existsSync(config)).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
