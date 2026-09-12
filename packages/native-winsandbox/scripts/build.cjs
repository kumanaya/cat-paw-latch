// Build the addon, tolerantly — the same contract as @domo/native-keychain's.
// The Job Object sandbox is the only thing standing between an approved
// command and the bare machine, so a machine that cannot compile it (no VS
// Build Tools, CI on macOS/Linux) must still be able to `just install` — the
// executor then fails command runs closed rather than running them uncaged.
// A real build failure is printed, not hidden.
//
// node-gyp 13+ locates VS 2026 (v18) on its own; the vcvars fallback below
// is for older node-gyp copies resolving from another workspace member.
"use strict";
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

if (process.platform !== "win32") {
  console.log("@domo/native-winsandbox: not Windows, skipping build");
  process.exit(0);
}

const root = path.join(__dirname, "..");

function rebuild(extraArgs = []) {
  const result = spawnSync("npx", ["node-gyp", "rebuild", ...extraArgs], {
    cwd: root,
    stdio: "inherit",
    shell: true,
  });
  return result.status;
}

function vsVcvars() {
  try {
    const vswhere = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe";
    if (!fs.existsSync(vswhere)) return null;
    const out = execFileSync(vswhere, ["-products", "*", "-property", "installationPath"], {
      encoding: "utf8",
      timeout: 30_000,
    });
    const installDir = out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)[0];
    if (!installDir) return null;
    const vcvars = path.join(installDir, "VC", "Auxiliary", "Build", "vcvars64.bat");
    return fs.existsSync(vcvars) ? vcvars : null;
  } catch {
    return null;
  }
}

let status = rebuild();
if (status !== 0) {
  // Inside the VS environment node-gyp takes the toolchain as given; the
  // --msvs_version only names the toolset generation it should assume.
  // The .bat path goes UNQUOTED — Node quotes spaced spawn args itself.
  const vcvars = vsVcvars();
  if (vcvars) {
    const bat = path.join(root, "build", "vs-build.bat");
    fs.mkdirSync(path.dirname(bat), { recursive: true });
    fs.writeFileSync(
      bat,
      `@echo off\r\ncall "${vcvars}" x64 >NUL\r\nif errorlevel 1 exit /b 1\r\nnpx node-gyp rebuild --msvs_version=2022\r\n`,
    );
    const result = spawnSync("cmd", ["/s", "/c", bat], { cwd: root, stdio: "inherit", shell: false });
    status = result.status;
    try {
      fs.unlinkSync(bat);
    } catch {}
  }
}

if (status !== 0) {
  console.warn(
    "@domo/native-winsandbox: build failed (see above). " +
      "Command execution is DISABLED on this host until it builds — " +
      "install the VS Build Tools and `npm rebuild @domo/native-winsandbox`.",
  );
}
process.exit(0);
