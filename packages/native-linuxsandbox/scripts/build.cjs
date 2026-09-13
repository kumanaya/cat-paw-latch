// Build the addon, tolerantly — the same contract as @domo/native-winsandbox.
// The bubblewrap + cgroup cage is what stands between an approved command and
// the bare machine, so a machine that cannot compile it (no toolchain, CI on
// macOS/Windows) must still be able to `just install` — the executor then
// fails command runs closed rather than running them uncaged.
"use strict";
const { spawnSync } = require("node:child_process");
const path = require("node:path");

if (process.platform !== "linux") {
  console.log("@domo/native-linuxsandbox: not Linux, skipping build");
  process.exit(0);
}

const root = path.join(__dirname, "..");
const result = spawnSync("npx", ["node-gyp", "rebuild"], {
  cwd: root,
  stdio: "inherit",
  shell: false,
});

if (result.status !== 0) {
  console.warn(
    "@domo/native-linuxsandbox: build failed (see above). " +
      "Command execution is DISABLED on this host until it builds — " +
      "install a C++ toolchain and `npm rebuild @domo/native-linuxsandbox`.",
  );
}
process.exit(0);
