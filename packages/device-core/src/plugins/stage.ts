/**
 * Staging a plugin's pinned binaries into `runtime/<arch>/bin`.
 *
 * ONE code path for a bundled plugin (`scripts/stage-plugins.mjs`, into
 * `vendor/plugins`) and an installed one (into `$DOMO_HOME/plugins`). The
 * archive is kept under `downloads` and re-hashed on every run; the runtime
 * tree is rebuilt from it every time, so a modified staged binary never
 * survives a stage — the property the old per-binary digest pin carried.
 *
 * The staging host IS the target host: `platform` picks which pins a manifest
 * contributes (`darwin` is the top-level block, every other OS is a
 * `platforms` block), and the staged name carries `.exe` on Windows. A plugin
 * whose manifest pins nothing for this platform is refused by name, never
 * staged with another OS's bytes.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { PluginError, type Arch, type PlatformBinary, type PluginManifest, type PluginPlatform } from "./manifest.js";

export type { Arch } from "./manifest.js";
export type FetchBytes = (url: string) => Promise<Buffer>;

/**
 * GitHub's release CDN intermittently answers 504 for a large asset while it
 * is busy — seen on both gog Linux tarballs, at different times, on runners
 * that had just downloaded the other arch fine. The asset is immutable and its
 * digest is checked by the caller, so retrying the same URL is safe; a single
 * transient gateway error used to fail a whole package job. A 4xx is the
 * release being wrong (a moved asset, a typo in a pin) and is not retried —
 * five attempts with backoff would only delay a failure that cannot heal.
 */
const DOWNLOAD_ATTEMPTS = 5;

export const fetchBytes: FetchBytes = async (url) => {
  for (let attempt = 1; ; attempt += 1) {
    let res: Response;
    try {
      res = await fetch(url);
    } catch (error) {
      if (attempt >= DOWNLOAD_ATTEMPTS) throw error;
      await new Promise((resolve) => setTimeout(resolve, attempt * 5_000));
      continue;
    }
    if (res.ok) return Buffer.from(await res.arrayBuffer());
    const status = res.status;
    if (status < 500 || attempt >= DOWNLOAD_ATTEMPTS) {
      throw new PluginError(`download failed with status ${status}`);
    }
    await new Promise((resolve) => setTimeout(resolve, attempt * 5_000));
  }
};

/** The one directory a child's PATH and the sandbox's reads name. */
export const binDir = (pluginDir: string, arch: Arch): string => path.join(pluginDir, "runtime", arch, "bin");

/**
 * What a staged binary is CALLED in `bin/`: Windows will not run an
 * extensionless file (CreateProcess appends `.exe`, and the staged copy has to
 * be there under that name for the Windows/Linux workspace to stage it and
 * for `loadPlugins` to accept it).
 */
export const stagedName = (name: string, platform: PluginPlatform): string =>
  platform === "win32" ? `${name}.exe` : name;

/**
 * The pinned build a manifest contributes for one platform. darwin lives in
 * the top-level `url`/`sha256`/`executable`; every other platform must have
 * its own block. A platform with no block is a fixed refusal naming the
 * binary — the caller is on a host this plugin does not ship for, or the pin
 * checklist missed one, and both want to hear about it rather than run the
 * wrong bytes.
 */
export function binaryFor(
  binary: PluginManifest["runtime"]["binaries"][number],
  platform: PluginPlatform,
): PlatformBinary {
  if (platform === "darwin") {
    return {
      url: binary.url,
      sha256: binary.sha256,
      ...(binary.executable === undefined ? {} : { executable: binary.executable }),
    };
  }
  const spec = binary.platforms[platform];
  if (spec === undefined) throw new PluginError(`${binary.name} has no ${platform} binary pinned`);
  return spec;
}

const digest = (file: string): string => createHash("sha256").update(fs.readFileSync(file)).digest("hex");

/**
 * Extract exactly one named member. bsdtar (macOS, Windows) matches a bare
 * name; GNU tar (Linux) does not, and gogcli's Linux tarballs store `./gog` —
 * so the `./`-prefixed spelling is tried as a fallback. Either way only the
 * named member lands, and a miss leaves the directory empty rather than
 * extracting the archive's other contents.
 */
function extractMember(archive: string, into: string, member: string): void {
  // stderr piped: a miss on the first spelling is expected on Linux and the
  // fallback's answer is the one worth surfacing; the last failure still
  // carries tar's own message.
  const run = (name: string): void => {
    execFileSync("tar", ["xf", archive, "-C", into, "--", name], { stdio: ["ignore", "ignore", "pipe"] });
  };
  try {
    run(member);
  } catch {
    run(`./${member}`);
  }
}

export async function stageBinaries(
  manifest: PluginManifest,
  pluginDir: string,
  arch: Arch,
  downloads: string,
  fetch: FetchBytes,
  platform: PluginPlatform = process.platform as PluginPlatform,
): Promise<void> {
  const runtime = path.join(pluginDir, "runtime", arch);
  fs.rmSync(runtime, { recursive: true, force: true });
  const bin = binDir(pluginDir, arch);
  fs.mkdirSync(bin, { recursive: true });
  // One try/catch for the whole loop: a fetch or tar failure partway through
  // must leave no runtime tree behind, same as a digest mismatch does — a
  // half-staged plugin would still pass loadPlugins' single-executable check.
  try {
    for (const b of manifest.runtime.binaries) {
      const spec = binaryFor(b, platform);
      const want = spec.sha256[arch];
      // Keyed on the pin itself: a bump changes the sha, so it can never hit a
      // stale cache entry. The platform is part of the key because the same
      // name/arch has different bytes per OS.
      const archive = path.join(downloads, `${manifest.name}-${b.name}-${platform}-${arch}-${want}`);
      if (!fs.existsSync(archive) || digest(archive) !== want) {
        fs.mkdirSync(downloads, { recursive: true });
        fs.writeFileSync(archive, await fetch(spec.url[arch]));
        if (digest(archive) !== want) {
          fs.rmSync(archive, { force: true });
          throw new PluginError(`binary ${b.name} does not match its sha256 for ${platform} ${arch}`);
        }
      }
      const into = path.join(runtime, b.name);
      fs.mkdirSync(into, { recursive: true });
      extractMember(archive, into, spec.executable ?? b.name);
      const executable = path.join(into, spec.executable ?? b.name);
      // Keyed on the binary's own (already unique) name, not the archive's
      // internal executable basename, so two binaries whose executables
      // happen to share a basename never overwrite each other in bin/.
      // Windows gets `.exe`: an extensionless PE is not a name it will run.
      const staged = path.join(bin, stagedName(b.name, platform));
      fs.copyFileSync(executable, staged);
      fs.chmodSync(staged, 0o755);
    }
  } catch (err) {
    fs.rmSync(runtime, { recursive: true, force: true });
    throw err;
  }
}

export function runPostinstall(
  manifest: PluginManifest,
  pluginDir: string,
  arch: Arch,
  platform: PluginPlatform = process.platform as PluginPlatform,
): string | null {
  if (manifest.hooks.postinstall === undefined) return null;
  const hook = path.join(pluginDir, manifest.hooks.postinstall);
  const env = { ...process.env, PATH: `${binDir(pluginDir, arch)}${path.delimiter}${process.env.PATH ?? ""}` };
  // POSIX executes the hook directly, so its own shebang decides the
  // interpreter (a bundled `postinstall.mjs` is Node by its first line; a
  // test or an operator may hand in a shell script). Windows has no shebang
  // execution — the file is not a program there — so the hook is handed to
  // Node explicitly.
  const said =
    platform === "win32"
      ? execFileSync(process.execPath, [hook], { cwd: pluginDir, encoding: "utf8", env })
      : execFileSync(hook, [], { cwd: pluginDir, encoding: "utf8", env });
  return said.trim();
}
