import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** A suite's throwaway dirs: `tmp()` makes one, `cleanup()` (from `afterEach`) removes them all. */
export function tempDirs(prefix: string): { tmp: () => string; cleanup: () => void } {
  const made: string[] = [];
  const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix)); made.push(d); return d; };
  const cleanup = () => { for (const d of made.splice(0)) fs.rmSync(d, { recursive: true, force: true }); };
  return { tmp, cleanup };
}

export const MINIMAL = {
  name: "fix", version: "1", command: "fix",
  runtime: { binaries: [] },
  exec: { argv: ["/bin/sh", "cli.sh"] },
  env: { FIX_HOME: { fixed: "${plugin_home}" } },
  argv: { read: [["query"]], write: [["put"]] },
  skill: "skill.md",
};

/**
 * A gzipped tarball holding an executable `tool` that prints its argv, plus
 * DECOY — a second member no manifest names, so every stage test exercises
 * the narrowing that keeps an archive's other contents out of the runtime
 * tree. `tmp` is the caller's own throwaway-dir helper, so cleanup stays
 * with it.
 */
export const DECOY = "decoy";

export function tarball(tmp: () => string): { file: string; sha256: string } {
  const src = tmp();
  fs.writeFileSync(path.join(src, "tool"), '#!/bin/sh\necho "ARGV=$*"\n', { mode: 0o755 });
  fs.writeFileSync(path.join(src, DECOY), "not ours\n");
  const file = path.join(tmp(), "tool.tgz");
  execFileSync("tar", ["czf", file, "-C", src, "tool", DECOY]);
  return { file, sha256: createHash("sha256").update(fs.readFileSync(file)).digest("hex") };
}

/**
 * The name `stageBinaries` writes a binary under on this host — `<name>.exe`
 * on Windows. Tests that stage or delete a staged binary must use it, not the
 * manifest's declared name, or they pass on the wrong half of the matrix.
 */
export const stagedName = (name: string): string =>
  process.platform === "win32" ? `${name}.exe` : name;

/**
 * A plugin directory on disk: its manifest, plus `script` staged as each of
 * its declared binaries. A plugin declaring none (MINIMAL) gets no bin/ at
 * all — per registry.ts, presence for those comes from the manifest alone.
 *
 * Off macOS, a binary entry with no `platforms` block gets one for THIS host,
 * carrying the same placeholder pins. Production manifests pin every OS they
 * ship for; a suite fixture that declared only darwin pins would be invisible
 * to `loadPlugins` on the Linux and Windows legs, taking the whole test down
 * for a reason the test never meant to exercise. The one test that DOES
 * exercise the refusal writes its manifest by hand.
 */
export function fakePlugin(root: string, manifest: Record<string, unknown>, script: string): string {
  const name = manifest.name as string;
  const runtime = (manifest.runtime ?? {}) as { binaries?: Record<string, unknown>[] };
  const binaries = runtime.binaries ?? [];
  const host = process.platform;
  const hostPins = (b: Record<string, unknown>) => ({
    url: b.url,
    sha256: b.sha256,
    ...(b.executable === undefined ? {} : { executable: b.executable }),
  });
  const augmented = {
    ...manifest,
    runtime: {
      ...runtime,
      binaries: binaries.map((b) =>
        host === "darwin" || b.platforms !== undefined ? b : { ...b, platforms: { [host]: hostPins(b) } },
      ),
    },
  };
  const dir = path.join(root, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "latch-plugin.json"), JSON.stringify(augmented));
  if (binaries.length > 0) {
    const bin = path.join(dir, "runtime", process.arch, "bin");
    fs.mkdirSync(bin, { recursive: true });
    for (const b of binaries) fs.writeFileSync(path.join(bin, stagedName(b.name as string)), script, { mode: 0o755 });
  }
  return dir;
}
