#!/usr/bin/env node
/**
 * Refuse a Linux release candidate unless the AppImage and latest-linux.yml
 * agree on the digest electron-updater will check (sha512, base64).
 *
 * Linux has no Authenticode publisher check. The feed digest is the whole
 * install-time trust: a YAML without sha512, or a YAML whose sha512 is not
 * the file on disk, must not be uploaded. electron-updater then repeats the
 * same comparison before applying an update.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function electronUpdaterSha512(bytes) {
  return createHash("sha512").update(bytes).digest("base64");
}

function feedSha512s(text) {
  return [...text.matchAll(/^\s*sha512:\s*(\S+)\s*$/gm)].map((m) => m[1]);
}

export function verifyLinuxReleaseFeed(releaseDir, opts = {}) {
  if (!releaseDir) throw new Error("usage: verify-linux-release-feed.mjs <release-dir> [--arch x64|arm64]");
  const resolved = path.resolve(releaseDir);
  if (!fs.existsSync(resolved)) throw new Error(`release directory does not exist: ${resolved}`);

  const arch = opts.arch ?? "x64";
  const appimage =
    opts.appimage ??
    fs.readdirSync(resolved).find((name) => new RegExp(`^Plow-Latch-.*-${arch}\\.AppImage$`).test(name));
  if (!appimage) throw new Error(`no Plow Latch ${arch} AppImage exists in ${resolved}`);
  const appimagePath = path.join(resolved, appimage);
  if (!fs.statSync(appimagePath).isFile()) throw new Error(`AppImage is not a file: ${appimagePath}`);

  let feedName = "";
  for (const candidate of ["latest-linux.yml", `latest-linux-${arch}.yml`]) {
    if (fs.existsSync(path.join(resolved, candidate))) {
      feedName = candidate;
      break;
    }
  }
  if (!feedName) throw new Error(`no latest-linux.yml (or latest-linux-${arch}.yml) in ${resolved}`);
  const feedText = fs.readFileSync(path.join(resolved, feedName), "utf8");
  if (!feedText.includes(appimage)) {
    throw new Error(`${feedName} does not reference ${appimage}`);
  }
  const listed = feedSha512s(feedText);
  if (listed.length === 0) {
    throw new Error(`${feedName} has no sha512 — electron-updater would accept nothing we can prove`);
  }
  const actual = electronUpdaterSha512(fs.readFileSync(appimagePath));
  if (listed.some((digest) => digest !== actual)) {
    throw new Error(`${feedName} sha512 does not match ${appimage}`);
  }
  console.log(`[linux-feed] ${feedName} sha512 matches ${appimage}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const dir = args.find((a) => !a.startsWith("--"));
  const archFlag = args.indexOf("--arch");
  const arch = archFlag >= 0 ? args[archFlag + 1] : "x64";
  try {
    verifyLinuxReleaseFeed(dir, { arch });
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
