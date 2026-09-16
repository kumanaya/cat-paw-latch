import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Executor } from "@domo/device-core";

const ON_LINUX = process.platform === "linux";
const cleanups: string[] = [];
afterEach(() => { while (cleanups.length) fs.rmSync(cleanups.pop()!, { recursive: true, force: true }); });

describe.skipIf(!ON_LINUX)("Executor Linux bubblewrap integration", () => {
  it("runs only a staged executable and returns its exit status", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "plow-executor-bwrap-"));
    cleanups.push(root);
    const source = path.join(root, "approved-runtime");
    fs.mkdirSync(source);
    const probe = path.join(source, "true");
    fs.copyFileSync("/usr/bin/true", probe);
    fs.chmodSync(probe, 0o755);
    const executor = new Executor(path.join(root, "scratch"));
    const result = await executor.run({
      argv: [probe],
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
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "plow-executor-bwrap-"));
    cleanups.push(root);
    const input = path.join(root, "input");
    fs.mkdirSync(input);
    const executor = new Executor(path.join(root, "scratch"));
    await expect(executor.run({
      argv: ["/usr/bin/true"],
      cwd: input,
      readPaths: [input],
      writePaths: [],
      network: false,
      appleEvents: false,
      waitMs: 5_000,
    })).rejects.toThrow(/outside the approved staged workspace/);
  });

  it("stages an absolute plugin argv[0] under an approved bin dir", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "plow-executor-bwrap-"));
    cleanups.push(root);
    const binDir = path.join(root, "plugins", "gog", "runtime", process.arch, "bin");
    fs.mkdirSync(binDir, { recursive: true });
    const gog = path.join(binDir, "gog");
    fs.writeFileSync(gog, "#!/bin/sh\necho PLUGIN_GOG\n", { mode: 0o755 });
    // The provider path hands the executor an ABSOLUTE argv[0] under the
    // plugin's bin dir, and the bin dir rides in readPaths — the workspace
    // stages it like any other approved root and rewrites the argv into it.
    const executor = new Executor(path.join(root, "scratch"));
    const result = await executor.run({
      argv: [gog],
      readPaths: [binDir],
      writePaths: [],
      network: false,
      appleEvents: false,
      waitMs: 5_000,
    });
    expect(result.running).toBe(false);
    expect(result.exitCode).toBe(0);
    expect(result.output.toString()).toContain("PLUGIN_GOG");
  });

  it("cannot exec a live host /usr/bin tool from a staged script", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "plow-executor-bwrap-"));
    cleanups.push(root);
    const source = path.join(root, "approved-runtime");
    fs.mkdirSync(source);
    // Stage a tiny static-ish runner: copy /bin/sh (shebang rewrite stages it)
    // and a script that tries to run the host's unstaged /usr/bin/id.
    const script = path.join(source, "escape.sh");
    fs.writeFileSync(script, "#!/bin/sh\n/usr/bin/id\n", { mode: 0o755 });
    const executor = new Executor(path.join(root, "scratch"));
    const result = await executor.run({
      argv: [script],
      cwd: source,
      readPaths: [source],
      writePaths: [],
      network: false,
      appleEvents: false,
      waitMs: 5_000,
    });
    expect(result.running).toBe(false);
    expect(result.exitCode).not.toBe(0);
  });
});
