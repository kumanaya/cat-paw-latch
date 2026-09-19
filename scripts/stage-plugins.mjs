/**
 * Stage every bundled plugin (apps/desktop/plugins/<name>) into
 * vendor/plugins/<name>, both arches of THIS host platform, through the SAME
 * staging code the installer uses. Needs `just build` first: it imports
 * device-core's dist. `--all` skips a plugin that pins nothing for this
 * host (wiki is darwin-only); a named plugin is still refused by name — a
 * Windows pack must never carry a macOS payload it asked for.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fetchBytes, parseManifest, runPostinstall, stageBinaries } from "../packages/device-core/dist/index.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bundled = path.join(repoRoot, "apps", "desktop", "plugins");
const vendor = path.join(repoRoot, "vendor", "plugins");
const downloads = path.join(repoRoot, "vendor", "downloads");

// Filtered to entries that actually have a manifest, so a stray non-plugin
// file under apps/desktop/plugins (a .DS_Store, say) doesn't abort --all.
const bundledPlugins = fs
  .readdirSync(bundled)
  .filter((name) => fs.existsSync(path.join(bundled, name, "latch-plugin.json")));
const arg = process.argv[2] ?? "--all";
if (arg !== "--all" && !bundledPlugins.includes(arg)) {
  console.error(`usage: stage-plugins.mjs <${bundledPlugins.join("|")}|--all>`);
  process.exit(2);
}
const names = arg === "--all" ? bundledPlugins : [arg];
for (const name of names) {
  const src = path.join(bundled, name);
  const dest = path.join(vendor, name);
  const manifest = parseManifest(fs.readFileSync(path.join(src, "latch-plugin.json"), "utf8"));
  const host = process.platform;
  const pinsHost = manifest.runtime.binaries.every(
    (b) => host === "darwin" || b.platforms[host] !== undefined,
  );
  if (!pinsHost && arg === "--all") {
    console.log(`[plugins] skipping ${name}: no ${host} pin`);
    continue;
  }
  fs.rmSync(dest, { recursive: true, force: true });
  fs.cpSync(src, dest, { recursive: true });
  console.log(`[plugins] staging ${name} ${manifest.version} for ${process.platform}`);
  for (const arch of ["arm64", "x64"]) {
    await stageBinaries(manifest, dest, arch, downloads, fetchBytes, process.platform);
  }
  const said = runPostinstall(manifest, dest, process.arch, process.platform);
  if (said !== null) console.log(`  ${said}`);
}
