import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { WindowsWorkspace, WindowsWorkspaceError } from "@domo/device-core";

const cleanups: string[] = [];
afterEach(() => {
  while (cleanups.length) fs.rmSync(cleanups.pop()!, { recursive: true, force: true });
});

function root(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-windows-workspace-"));
  cleanups.push(dir);
  return dir;
}

describe.skipIf(process.platform !== "win32")("WindowsWorkspace", () => {
  it("stages only approved roots, rewrites paths, and copies regular output back", () => {
    const tmp = root();
    const input = path.join(tmp, "input");
    const output = path.join(tmp, "output");
    fs.mkdirSync(input);
    fs.mkdirSync(output);
    fs.writeFileSync(path.join(input, "in.txt"), "input");
    const workspace = WindowsWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: [input], writePaths: [output] });

    const stagedInput = workspace.rewrite(path.join(input, "in.txt"));
    const stagedOutput = workspace.rewrite(path.join(output, "out.txt"));
    expect(stagedInput).not.toBe(path.join(input, "in.txt"));
    expect(fs.readFileSync(stagedInput, "utf8")).toBe("input");
    fs.writeFileSync(stagedOutput, "result");
    workspace.reconcile();
    expect(fs.readFileSync(path.join(output, "out.txt"), "utf8")).toBe("result");
    expect(() => workspace.rewriteCwd(tmp)).toThrow(WindowsWorkspaceError);
  });

  it("rejects device/ADS approved roots before staging", () => {
    const tmp = root();
    expect(() => WindowsWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: ["\\\\.\\PhysicalDrive0"], writePaths: [] }))
      .toThrow(WindowsWorkspaceError);
    expect(() => WindowsWorkspace.create({ scratch: path.join(tmp, "scratch-two"), readPaths: [`${tmp}:secret`], writePaths: [] }))
      .toThrow(WindowsWorkspaceError);
  });

  it("does not reconcile a reparse point created by the sandboxed process", () => {
    const tmp = root();
    const input = path.join(tmp, "input");
    const output = path.join(tmp, "output");
    fs.mkdirSync(input);
    fs.mkdirSync(output);
    const target = path.join(input, "private");
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, "private.txt"), "must not be copied through a link");
    const workspace = WindowsWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: [input], writePaths: [output] });
    // A junction is a reparse point and, unlike file symlinks, needs no
    // Developer Mode / SeCreateSymbolicLinkPrivilege in the CI account.
    fs.symlinkSync(target, workspace.rewrite(path.join(output, "escape")), "junction");
    expect(() => workspace.reconcile()).toThrow(WindowsWorkspaceError);
    expect(fs.existsSync(path.join(output, "escape"))).toBe(false);
  });

  it("refuses overlapping roots rather than choosing an accidental mapping", () => {
    const tmp = root();
    const parent = path.join(tmp, "parent");
    const child = path.join(parent, "child");
    fs.mkdirSync(child, { recursive: true });
    expect(() => WindowsWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: [parent, child], writePaths: [] }))
      .toThrow(WindowsWorkspaceError);
  });

  it("does not copy the scratch tree when an approved root contains it", () => {
    const tmp = root();
    fs.writeFileSync(path.join(tmp, "note.txt"), "keep");
    const scratch = path.join(tmp, "scratch");
    const workspace = WindowsWorkspace.create({ scratch, readPaths: [tmp], writePaths: [] });
    const staged = workspace.rewrite(path.join(tmp, "note.txt"));
    expect(fs.readFileSync(staged, "utf8")).toBe("keep");
    expect(fs.existsSync(path.join(workspace.rewrite(tmp), "scratch"))).toBe(false);
  });
});
