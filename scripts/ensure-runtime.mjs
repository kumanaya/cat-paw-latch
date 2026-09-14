/**
 * Floor for a from-source run. `npm install` can skip Electron's postinstall
 * (npm 11 allowScripts, ignore-scripts, or a partial download), and then
 * `just app` fails with a missing binary. On Linux the bubblewrap cage also
 * has to compile, or command execution fails closed.
 *
 * Idempotent: if the Electron binary is already executable and the host
 * sandbox addon is present, this is a no-op.
 */
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const run = (cmd, argv, opts = {}) =>
  spawnSync(cmd, argv, { cwd: root, stdio: "inherit", shell: false, ...opts });

function electronPath() {
  try {
    return require(path.join(root, "node_modules", "electron"));
  } catch {
    return null;
  }
}

function electronReady() {
  const bin = electronPath();
  if (!bin) return false;
  try {
    fs.accessSync(bin, fs.constants.X_OK);
    return fs.statSync(bin).size > 0;
  } catch {
    return false;
  }
}

function ensureElectron() {
  if (electronReady()) return;
  const installer = path.join(root, "node_modules", "electron", "install.js");
  if (!fs.existsSync(installer)) {
    console.error(
      "ensure-runtime: electron is not installed. Run `just install` (or `npm install`) in the checkout.",
    );
    process.exit(1);
  }
  console.log("ensure-runtime: Electron binary missing — running electron/install.js");
  const result = run(process.execPath, [installer]);
  if ((result.status ?? 1) !== 0 || !electronReady()) {
    console.error(
      "ensure-runtime: Electron failed to download. Check the network, then retry `just install`.",
    );
    process.exit(result.status ?? 1);
  }
}

function linuxAddonReady() {
  const dir = path.join(root, "packages", "native-linuxsandbox", "build", "Release");
  const addon = path.join(dir, "linuxsandbox.node");
  const launcher = path.join(dir, "linuxsandbox_launcher");
  try {
    return fs.statSync(addon).size > 0 && fs.statSync(launcher).size > 0;
  } catch {
    return false;
  }
}

function ensureLinuxSandbox() {
  if (process.platform !== "linux") return;
  if (linuxAddonReady()) return;
  console.log("ensure-runtime: rebuilding @domo/native-linuxsandbox");
  const result = run("npm", ["rebuild", "@domo/native-linuxsandbox"]);
  if ((result.status ?? 1) !== 0 || !linuxAddonReady()) {
    console.error(
      "ensure-runtime: the Linux sandbox addon did not build. Install a C++ toolchain " +
        "(Arch/Omarchy: `sudo pacman -S --needed base-devel`) and retry `just install`.",
    );
    process.exit(result.status ?? 1);
  }
}

function ensureBubblewrap() {
  if (process.platform !== "linux") return;
  const probe = spawnSync("bwrap", ["--version"], { encoding: "utf8", shell: false });
  if ((probe.status ?? 1) === 0) return;
  console.error(
    "ensure-runtime: bubblewrap (`bwrap`) is not on PATH. Command execution fails closed without it.\n" +
      "  Arch/Omarchy: sudo pacman -S --needed bubblewrap\n" +
      "  Debian/Ubuntu: sudo apt-get install -y bubblewrap",
  );
  process.exit(1);
}

ensureElectron();
ensureLinuxSandbox();
ensureBubblewrap();
console.log(`ensure-runtime: ok (${electronPath()})`);
