// Loader for the compiled addon. CommonJS so it can be pulled in with
// createRequire from ESM (the pattern vaultSecretStore.ts already uses for
// Electron). Returns null rather than throwing when the addon was never
// built — secret-file writes fall back to the inherited ACL with a loud
// warning (see fileLockdown.ts); the packaged app always carries the addon,
// enforced by afterPackWin.
"use strict";
const path = require("node:path");

let addon = null;
try {
  if (process.platform === "win32") {
    addon = require(path.join(__dirname, "build", "Release", "winfs.node"));
  }
} catch {
  addon = null;
}

module.exports = addon;
