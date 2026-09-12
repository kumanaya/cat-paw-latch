// Build the addon, tolerantly — the same contract as @domo/native-wincred's.
// Hello-gated vault providers need it; a machine that cannot compile it (no
// VS Build Tools, CI on macOS/Linux) must still be able to `just install` —
// those providers report unavailable and the vault screen says so. A real
// build failure is printed, not hidden.
//
// C++/WinRT ships in the Windows SDK (10.0.17134+), so no extra dependency:
// the VS Build Tools' SDK already carries winrt/ headers. The toolchain
// notes from native-wincred's script apply unchanged (vswhere + vcvars for
// VS 18+, unquoted .bat path).
"use strict";
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

if (process.platform !== "win32") {
  console.log("@domo/native-hello: not Windows, skipping build");
  process.exit(0);
}

function vsVcvars() {
  try {
    const vswhere = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe";
    if (!fs.existsSync(vswhere)) return null;
    const out = execFileSync(
      vswhere,
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
    "@domo/native-hello: build failed (see above). " +
      "Hello-gated vault providers stay unavailable; " +
      "install the VS Build Tools and `npm rebuild @domo/native-hello` to enable them.",
  );
}
process.exit(0);
