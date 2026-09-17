import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { parseManifest, PluginError } from "../src/plugins/manifest.js";
import { binDir, runPostinstall, stageBinaries, stagedName, type Arch } from "../src/plugins/stage.js";
import { DECOY, MINIMAL, tarball, tempDirs } from "./pluginFixtures.js";

const ARCH = process.arch as Arch;
// The fixtures pin darwin (the top-level url/sha block is darwin's), so the
// staging tests pass the platform explicitly: they must be the same on every
// host this suite runs on, not follow the CI machine.
const DARWIN = "darwin" as const;
const { tmp, cleanup } = tempDirs("latch-stage-");
afterEach(cleanup);

function manifestWith(sha256: string, extra: Record<string, unknown> = {}) {
  return parseManifest(JSON.stringify({
    ...MINIMAL,
    exec: { argv: ["tool", "--fixed"] },
    runtime: { binaries: [{
      name: "tool",
      url: { arm64: "https://example.invalid/tool", x64: "https://example.invalid/tool" },
      sha256: { arm64: sha256, x64: sha256 },
    }] },
    ...extra,
  }));
}

describe("stageBinaries", () => {
  it("verifies the archive, extracts it, and puts the executable in runtime/<arch>/bin", async () => {
    const { file, sha256 } = tarball(tmp);
    const pluginDir = tmp();
    let fetched = 0;
    await stageBinaries(manifestWith(sha256), pluginDir, ARCH, tmp(), async () => { fetched++; return fs.readFileSync(file); }, DARWIN);
    const staged = path.join(binDir(pluginDir, ARCH), stagedName("tool", DARWIN));
    expect(fetched).toBe(1);
    expect(fs.existsSync(staged)).toBe(true);
    // Running the staged bytes is a POSIX-only assertion: the fixture is a
    // shell script, and Windows will not execute one however it is named.
    if (process.platform !== "win32") {
      expect(execFileSync(staged, ["a"], { encoding: "utf8" })).toBe("ARGV=a\n");
    }
    // Only the member the manifest names is extracted, so the rest of a
    // digest-matching archive never lands under runtime/.
    expect(fs.existsSync(path.join(pluginDir, "runtime", ARCH, "tool", DECOY))).toBe(false);
  });

  it("refuses an archive whose bytes do not match the pin, staging nothing", async () => {
    const { file } = tarball(tmp);
    const pluginDir = tmp();
    const wrong = "0".repeat(64);
    await expect(
      stageBinaries(manifestWith(wrong), pluginDir, ARCH, tmp(), async () => fs.readFileSync(file), DARWIN),
    ).rejects.toThrow(PluginError);
    expect(fs.existsSync(binDir(pluginDir, ARCH))).toBe(false);
  });

  it("re-hashes a cached archive instead of downloading, and rebuilds the runtime tree", async () => {
    const { file, sha256 } = tarball(tmp);
    const pluginDir = tmp();
    const downloads = tmp();
    const m = manifestWith(sha256);
    let fetched = 0;
    const fetch = async () => { fetched++; return fs.readFileSync(file); };
    await stageBinaries(m, pluginDir, ARCH, downloads, fetch, DARWIN);
    // Something modified the staged copy. The next stage must replace it from the verified archive.
    const staged = path.join(binDir(pluginDir, ARCH), stagedName("tool", DARWIN));
    fs.writeFileSync(staged, "#!/bin/sh\necho tampered\n");
    await stageBinaries(m, pluginDir, ARCH, downloads, fetch, DARWIN);
    expect(fetched).toBe(1);
    // Read, not executed: the assertion holds on Windows too, where the
    // staged shell script is not a runnable program.
    const replaced = fs.readFileSync(staged, "utf8");
    expect(replaced).toContain("ARGV=$*");
    expect(replaced).not.toContain("tampered");
    if (process.platform !== "win32") {
      expect(execFileSync(staged, ["x"], { encoding: "utf8" })).toBe("ARGV=x\n");
    }
  });

  it("stages two binaries whose executables share a basename without one overwriting the other", async () => {
    const a = tarball(tmp);
    const b = tarball(tmp);
    const pluginDir = tmp();
    const bin = (name: string, sha: string) => ({
      name, executable: "tool",
      url: { arm64: `https://example.invalid/${name}`, x64: `https://example.invalid/${name}` },
      sha256: { arm64: sha, x64: sha },
    });
    const manifest = parseManifest(JSON.stringify({
      ...MINIMAL,
      exec: { argv: ["tool-a", "--fixed"] },
      runtime: { binaries: [bin("tool-a", a.sha256), bin("tool-b", b.sha256)] },
    }));
    await stageBinaries(
      manifest, pluginDir, ARCH, tmp(),
      async (url) => fs.readFileSync(url.endsWith("tool-a") ? a.file : b.file),
      DARWIN,
    );
    expect(fs.readdirSync(binDir(pluginDir, ARCH)).sort()).toEqual(["tool-a", "tool-b"]);
  });

  it("leaves no runtime tree when a later binary in the manifest fails to stage", async () => {
    const { file, sha256 } = tarball(tmp);
    const pluginDir = tmp();
    const manifest = parseManifest(JSON.stringify({
      ...MINIMAL,
      exec: { argv: ["tool", "--fixed"] },
      runtime: {
        binaries: [
          { name: "tool", url: { arm64: "https://example.invalid/tool", x64: "https://example.invalid/tool" }, sha256: { arm64: sha256, x64: sha256 } },
          { name: "broken", url: { arm64: "https://example.invalid/broken", x64: "https://example.invalid/broken" }, sha256: { arm64: "1".repeat(64), x64: "1".repeat(64) } },
        ],
      },
    }));
    await expect(
      stageBinaries(manifest, pluginDir, ARCH, tmp(), async (url) => {
        if (url.endsWith("broken")) throw new Error("network down");
        return fs.readFileSync(file);
      }, DARWIN),
    ).rejects.toThrow("network down");
    expect(fs.existsSync(binDir(pluginDir, ARCH))).toBe(false);
  });

  it("takes the platform's own pin and writes the Windows staged name", async () => {
    const { file, sha256 } = tarball(tmp);
    const pluginDir = tmp();
    const manifest = parseManifest(JSON.stringify({
      ...MINIMAL,
      exec: { cwd: "plugin", argv: ["tool", "--fixed"] },
      runtime: { binaries: [{
        name: "tool",
        url: { arm64: "https://example.invalid/darwin-arm64", x64: "https://example.invalid/darwin-x64" },
        sha256: { arm64: "0".repeat(64), x64: "0".repeat(64) },
        platforms: { win32: {
          url: { arm64: "https://example.invalid/win-arm64", x64: "https://example.invalid/win-x64" },
          sha256: { arm64: sha256, x64: sha256 },
        } },
      }], sources: [] },
    }));
    const seen: string[] = [];
    await stageBinaries(
      manifest, pluginDir, ARCH, tmp(),
      async (url) => { seen.push(url); return fs.readFileSync(file); },
      "win32",
    );
    // The darwin URL is never touched when staging for Windows.
    expect(seen).toEqual([`https://example.invalid/win-${ARCH}`]);
    // Windows stages `<name>.exe`: CreateProcess will not run an
    // extensionless PE, and the packed-app gate expects the same name.
    expect(fs.readdirSync(binDir(pluginDir, ARCH))).toEqual(["tool.exe"]);
  });

  it("refuses a platform the manifest pins nothing for, staging nothing", async () => {
    const { file, sha256 } = tarball(tmp);
    const pluginDir = tmp();
    await expect(
      stageBinaries(manifestWith(sha256), pluginDir, ARCH, tmp(), async () => fs.readFileSync(file), "win32"),
    ).rejects.toThrow(/has no win32 binary pinned/);
    expect(fs.existsSync(binDir(pluginDir, ARCH))).toBe(false);
  });
});

describe("runPostinstall", () => {
  // POSIX-only: this exercises the direct-exec branch, where the hook's own
  // shebang picks the interpreter. Windows has no shebang execution — a
  // `.sh` hook is EFTYPE there — and its branch is covered by the test below.
  it.skipIf(process.platform === "win32")(
    "runs the hook with the staged bin first on PATH, and returns what it printed",
    async () => {
      const { file, sha256 } = tarball(tmp);
      const pluginDir = tmp();
      fs.writeFileSync(path.join(pluginDir, "check.sh"), '#!/bin/sh\ntool probe\n', { mode: 0o755 });
      const m = manifestWith(sha256, { hooks: { postinstall: "check.sh" } });
      await stageBinaries(m, pluginDir, ARCH, tmp(), async () => fs.readFileSync(file), DARWIN);
      expect(runPostinstall(m, pluginDir, ARCH, DARWIN)).toBe("ARGV=probe");
    },
  );

  it("hands a Windows hook to Node explicitly — the real .mjs shape", () => {
    // Host-independent on purpose: the assertion is about the win32 BRANCH,
    // which runs `process.execPath` — the one interpreter every host has.
    const pluginDir = tmp();
    fs.writeFileSync(path.join(pluginDir, "check.mjs"), 'console.log("WIN-HOOK");\n');
    const m = manifestWith("0".repeat(64), { hooks: { postinstall: "check.mjs" } });
    expect(runPostinstall(m, pluginDir, ARCH, "win32")).toBe("WIN-HOOK");
  });

  it("is null when the manifest declares no hook", () => {
    expect(runPostinstall(manifestWith("0".repeat(64)), tmp(), ARCH, DARWIN)).toBeNull();
  });
});
