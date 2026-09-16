#!/usr/bin/env node
/**
 * Package the Linux AppImage (see `just package-linux`). Must run on Linux so
 * @domo/native-linuxsandbox compiles for the packaging host; afterPack refuses
 * a pack whose launcher --probe fails (bubblewrap + systemd user session) or
 * whose Camoufox / plugin ELF is missing or the wrong arch.
 *
 * Version stamping matches `package-win.mjs` / `just package`: major.minor from
 * the desktop package.json + a UTC timestamp patch, with the git commit riding
 * alongside ("-dirty" when the tree isn't clean). electron-updater compares
 * that stamped semver, so a local pack is never yanked back by the stable feed.
 */
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux") {
  console.error("package-linux must run on Linux (addons compile for the packaging host)");
  process.exit(1);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const desktop = path.join(root, "apps", "desktop");

const args = process.argv.slice(2);
const hostArch = process.arch === "arm64" ? "arm64" : "x64";
let arch = hostArch;
if (args.length !== 0) {
  if (args.length !== 2 || args[0] !== "--arch" || !["x64", "arm64"].includes(args[1])) {
    throw new Error("usage: package-linux.mjs [--arch x64|arm64]");
  }
  arch = args[1];
}

const run = (cmd, argv, opts = {}) =>
  execFileSync(cmd, argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts }).trim();

const base = JSON.parse(fs.readFileSync(path.join(desktop, "package.json"), "utf8"))
  .version.split(".")
  .slice(0, 2)
  .join(".");
const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 12);
const version = `${base}.${stamp}`;
let sha = run("git", ["-C", root, "rev-parse", "--short=12", "HEAD"]);
if (run("git", ["-C", root, "status", "--porcelain"]) !== "") sha += "-dirty";

for (const [label, argv] of [
  ["stage-plugins", [path.join(root, "scripts", "stage-plugins.mjs"), "--all"]],
  ["fetch-browser", [path.join(root, "scripts", "build-browser-runtime.mjs"), "--browser"]],
]) {
  const prep = spawnSync(process.execPath, argv, { cwd: root, stdio: "inherit", shell: false });
  if ((prep.status ?? 1) !== 0) {
    console.error(`package-linux: ${label} failed`);
    process.exit(prep.status ?? 1);
  }
}

console.log(`packaging Plow Latch ${version} (${sha}) for Linux ${arch}`);
const result = spawnSync(
  process.execPath,
  [
    path.join(root, "node_modules", "electron-builder", "out", "cli", "cli.js"),
    "--linux",
    `--${arch}`,
    "--publish",
    "never",
    `-c.extraMetadata.version=${version}`,
    `-c.extraMetadata.gitCommit=${sha}`,
    `-c.buildVersion=${stamp}`,
  ],
  { cwd: desktop, stdio: "inherit", shell: false },
);
process.exit(result.status ?? 1);
