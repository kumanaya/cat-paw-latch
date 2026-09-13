import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { LinuxWorkspace, LinuxWorkspaceError } from "@domo/device-core";

const cleanups: string[] = [];
afterEach(() => {
  while (cleanups.length) fs.rmSync(cleanups.pop()!, { recursive: true, force: true });
});

function root(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plow-linux-workspace-"));
  cleanups.push(dir);
  return dir;
}

describe("LinuxWorkspace", () => {
  it("stages only approved roots, rewrites paths, and copies regular output back", () => {
    const tmp = root();
    const input = path.join(tmp, "input");
    const output = path.join(tmp, "output");
    fs.mkdirSync(input);
    fs.mkdirSync(output);
    fs.writeFileSync(path.join(input, "in.txt"), "input");
    const workspace = LinuxWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: [input], writePaths: [output] });

    const stagedInput = workspace.rewrite(path.join(input, "in.txt"));
    const stagedOutput = workspace.rewrite(path.join(output, "out.txt"));
    expect(stagedInput).not.toBe(path.join(input, "in.txt"));
    expect(fs.readFileSync(stagedInput, "utf8")).toBe("input");
    fs.writeFileSync(stagedOutput, "result");
    workspace.reconcile();
    expect(fs.readFileSync(path.join(output, "out.txt"), "utf8")).toBe("result");
    expect(() => workspace.rewriteCwd(tmp)).toThrow(LinuxWorkspaceError);
  });

  it("rejects symbolic-link trees before staging", () => {
    const tmp = root();
    const input = path.join(tmp, "input");
    const real = path.join(tmp, "real");
    fs.mkdirSync(real);
    fs.writeFileSync(path.join(real, "secret.txt"), "no");
    fs.symlinkSync(real, input);
    expect(() => LinuxWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: [input], writePaths: [] }))
      .toThrow(LinuxWorkspaceError);
  });

  it("does not reconcile a symlink created by the sandboxed process", () => {
    const tmp = root();
    const input = path.join(tmp, "input");
    const output = path.join(tmp, "output");
    fs.mkdirSync(input);
    fs.mkdirSync(output);
    const target = path.join(input, "private");
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, "private.txt"), "must not be copied through a link");
    const workspace = LinuxWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: [input], writePaths: [output] });
    fs.symlinkSync(target, workspace.rewrite(path.join(output, "escape")));
    expect(() => workspace.reconcile()).toThrow(LinuxWorkspaceError);
    expect(fs.existsSync(path.join(output, "escape"))).toBe(false);
  });

  it("refuses overlapping roots rather than choosing an accidental mapping", () => {
    const tmp = root();
    const parent = path.join(tmp, "parent");
    const child = path.join(parent, "child");
    fs.mkdirSync(child, { recursive: true });
    expect(() => LinuxWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: [parent, child], writePaths: [] }))
      .toThrow(LinuxWorkspaceError);
  });

  it("stages shebang interpreters under .interp and rewrites the script", () => {
    const tmp = root();
    const input = path.join(tmp, "input");
    fs.mkdirSync(input);
    const script = path.join(input, "run.sh");
    fs.writeFileSync(script, "#!/bin/sh\necho hi\n", { mode: 0o755 });
    const workspace = LinuxWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: [input], writePaths: [] });
    const staged = workspace.rewrite(script);
    const text = fs.readFileSync(staged, "utf8");
    expect(text.startsWith("#!")).toBe(true);
    expect(text).not.toMatch(/^#!\/bin\/sh/m);
    expect(text).toMatch(/\.interp\//);
    const interpLine = text.split("\n")[0]!.slice(2).split(/\s/)[0]!;
    expect(fs.existsSync(interpLine)).toBe(true);
    expect(interpLine.startsWith(workspace.root)).toBe(true);
  });

  it("propagates deletes for inventoried writable files missing from the stage", () => {
    const tmp = root();
    const output = path.join(tmp, "output");
    fs.mkdirSync(output);
    const keep = path.join(output, "keep.txt");
    const gone = path.join(output, "gone.txt");
    fs.writeFileSync(keep, "keep");
    fs.writeFileSync(gone, "gone");
    const workspace = LinuxWorkspace.create({ scratch: path.join(tmp, "scratch"), readPaths: [], writePaths: [output] });
    fs.unlinkSync(workspace.rewrite(gone));
    fs.writeFileSync(workspace.rewrite(keep), "kept");
    workspace.reconcile();
    expect(fs.readFileSync(keep, "utf8")).toBe("kept");
    expect(fs.existsSync(gone)).toBe(false);
  });
});
