// Loader for the compiled addon. CommonJS so it can be pulled in with
// createRequire from ESM (the pattern vaultSecretStore.ts already uses for
// Electron). Returns null rather than throwing when the addon was never
// built — the executor treats that as "no sandbox on this host" and fails
// command runs closed rather than running them uncaged.
"use strict";
const path = require("node:path");

let addon = null;
try {
  if (process.platform === "win32") {
    addon = require(path.join(__dirname, "build", "Release", "winsandbox.node"));
  }
} catch {
  addon = null;
}

module.exports = addon;
