import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { Executor } from "@domo/device-core";

const ON_WINDOWS = process.platform === "win32";
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const launcher = path.join(repo, "packages", "native-winsandbox", "build", "Release", "winsandbox_launcher.exe");
const cleanups: string[] = [];
afterEach(() => { while (cleanups.length) fs.rmSync(cleanups.pop()!, { recursive: true, force: true }); });

describe.skipIf(!ON_WINDOWS)("Executor Windows AppContainer integration", () => {
  it("runs only a staged executable and returns its exit status", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "plow-executor-appcontainer-"));
    cleanups.push(root);
    const source = path.join(root, "approved-runtime");
    fs.mkdirSync(source);
    const probe = path.join(source, "probe.exe");
    fs.copyFileSync(launcher, probe);
    const executor = new Executor(path.join(root, "scratch"));
    const result = await executor.run({
      argv: [probe, "--probe"],
      cwd: source,
      readPaths: [source],
      writePaths: [],
      network: false,
      appleEvents: false,
      waitMs: 5_000,
    });
    expect(result.running).toBe(false);
    expect(result.exitCode).toBe(0);
  });

  it("refuses an executable not materialized in an approved root", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "plow-executor-appcontainer-"));
    cleanups.push(root);
    const input = path.join(root, "input");
    fs.mkdirSync(input);
    const executor = new Executor(path.join(root, "scratch"));
    await expect(executor.run({
      argv: [path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe"), "/c", "exit 0"],
      cwd: input,
      readPaths: [input],
      writePaths: [],
      network: false,
      appleEvents: false,
      waitMs: 5_000,
    })).rejects.toThrow(/outside the approved staged workspace/);
  });
});
