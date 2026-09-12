// Loader for the compiled addon. CommonJS so it can be pulled in with
// createRequire from ESM. Returns null rather than throwing when the addon
// was never built — Hello-gated providers are then unavailable and the
// vault screen says so (see vaultKeyStore.ts); the packaged app always
// carries the addon, enforced by afterPackWin.
"use strict";
const path = require("node:path");

let addon = null;
try {
  if (process.platform === "win32") {
    addon = require(path.join(__dirname, "build", "Release", "winhello.node"));
  }
} catch {
  addon = null;
}

module.exports = addon;
