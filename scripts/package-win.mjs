// Package for Windows (see `just package-win`): NSIS installer + unpacked
// tree in apps/desktop/release/. Cross-platform on purpose — the justfile
// recipe shell differs per host, so the version stamping and the
// electron-builder call live here, in one clock like `just package`:
// major.minor from the desktop package.json + a UTC timestamp patch, with
// the git commit riding alongside ("-dirty" when the tree isn't clean).
// A Windows package is a release-shaped artifact, so it is never unsigned:
// electron-updater will only accept an update signed by Plow's publisher and
// this script verifies that signature plus timestamp before returning success.
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const desktop = path.join(root, "apps", "desktop");
const publisher = "The Plow Collective, Inc.";

const args = process.argv.slice(2);
let arches = ["x64", "arm64"];
if (args.length !== 0) {
  if (args.length !== 2 || args[0] !== "--arch" || !["x64", "arm64"].includes(args[1])) {
    throw new Error("usage: package-win.mjs [--arch x64|arm64]");
  }
  arches = [args[1]];
}

const signingConfigured = ["CSC_LINK", "WIN_CSC_LINK", "CSC_NAME", "WIN_CSC_NAME"]
  .some((name) => (process.env[name] ?? "").trim() !== "");
if (!signingConfigured) {
  throw new Error(
    "refusing to create an unsigned Windows installer: configure CSC_LINK (or WIN_CSC_LINK) " +
    "with the Authenticode certificate before running package-win",
  );
}

const run = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts }).trim();

const base = JSON.parse(
  (await import("node:fs")).readFileSync(path.join(desktop, "package.json"), "utf8"),
).version.split(".").slice(0, 2).join(".");
const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 12);
const version = `${base}.${stamp}`;
let sha = run("git", ["-C", root, "rev-parse", "--short=12", "HEAD"]);
if (run("git", ["-C", root, "status", "--porcelain"]) !== "") sha += "-dirty";

console.log(`packaging Plow Latch ${version} (${sha}) for Windows ${arches.join(", ")}`);
const built = spawnSync(
  process.execPath,
  [
    path.join(root, "node_modules", "electron-builder", "out", "cli", "cli.js"),
    "--win",
    ...arches.map((arch) => `--${arch}`),
    "--publish",
    "never",
    "-c.extraMetadata.version=" + version,
    "-c.extraMetadata.gitCommit=" + sha,
  ],
  { cwd: desktop, stdio: "inherit" },
);
if (built.status !== 0) process.exit(built.status ?? 1);
execFileSync(
  process.execPath,
  [path.join(root, "scripts", "verify-windows-release-signature.mjs"), path.join(desktop, "release"), publisher],
  { stdio: "inherit" },
);
