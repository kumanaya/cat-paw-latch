// Build the addon, tolerantly — the same contract as @domo/native-wincred's.
// Secret-file ACL lockdown hardens the inherited profile-dir ACL; a machine
// that cannot compile it (no VS Build Tools, CI on macOS/Linux) must still
// be able to `just install` — writers warn once and keep the inherited ACL.
// A real build failure is printed, not hidden.
//
// node-gyp locates Visual Studio on its own up to VS 2022; newer Build Tools
// (VS 18+) are found through vswhere + vcvars instead: compiling from inside
// the VS environment makes node-gyp trust it (its "running in a VS Command
// Prompt" path) rather than fail its own version lookup.
"use strict";
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

if (process.platform !== "win32") {
  console.log("@domo/native-fs: not Windows, skipping build");
  process.exit(0);
}

function vsVcvars() {
  try {
    const vswhere = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe";
    if (!fs.existsSync(vswhere)) return null;
    const out = execFileSync(
      vswhere,
      // No -requires filter: newer vswhere schemas omit the package list,
      // and vcvars' existence below is the real check for a C++ toolchain.
      ["-products", "*", "-property", "installationPath"],
      { encoding: "utf8", timeout: 30_000 },
    );
    const installDir = out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)[0];
    if (!installDir) return null;
    const vcvars = path.join(installDir, "VC", "Auxiliary", "Build", "vcvars64.bat");
    return fs.existsSync(vcvars) ? vcvars : null;
  } catch {
    return null;
  }
}

const root = path.join(__dirname, "..");
let status = null;
const vcvars = vsVcvars();
if (vcvars) {
  // Inside the VS environment node-gyp takes the toolchain as given; the
  // --msvs_version only names the toolset generation it should assume.
  // A temp .bat carries the spaced vcvars path. Note: the .bat path goes
  // UNQUOTED — Node quotes spaced spawn args itself, and pre-quoting turns
  // the quotes into literals cmd cannot run (learned the loud way).
  const bat = path.join(root, "build", "vs-build.bat");
  fs.mkdirSync(path.dirname(bat), { recursive: true });
  fs.writeFileSync(
    bat,
    `@echo off\r\ncall "${vcvars}" x64 >NUL\r\nif errorlevel 1 exit /b 1\r\nnpx node-gyp rebuild --msvs_version=2022\r\n`,
  );
  const result = spawnSync("cmd", ["/s", "/c", bat], {
    cwd: root,
    stdio: "inherit",
    shell: false,
  });
  try {
    fs.unlinkSync(bat);
  } catch {}
  status = result.status;
} else {
  const result = spawnSync("npx", ["node-gyp", "rebuild"], {
    cwd: root,
    stdio: "inherit",
    shell: true,
  });
  status = result.status;
}

if (status !== 0) {
  console.warn(
    "@domo/native-fs: build failed (see above). " +
      "Secret files keep their inherited ACL with a warning; " +
      "install the VS Build Tools and `npm rebuild @domo/native-fs` to enable ACL lockdown.",
  );
}
process.exit(0);
