/**
 * The packaged-app path rewrite. The bug this pins: in the AppImage,
 * `require.resolve("@domo/native-linuxsandbox")` returns a path inside
 * `app.asar`, `fs.existsSync` says true (Electron's asar wrapper is
 * archive-aware), and `spawn` of the launcher then fails with the bare
 * `spawn ENOTDIR` — because `app.asar` is a file where a directory was
 * expected. Package-only, which is why the suite (real from-source paths)
 * and `afterPack --probe` (the unpacked tree) both pass while the shipped
 * app cannot run a single command.
 */
import { describe, expect, it } from "vitest";
import { unpackedPath } from "../src/asarPath.js";

describe("unpackedPath", () => {
  it("rewrites a launcher resolved inside app.asar to its unpacked sibling", () => {
    expect(
      unpackedPath(
        "/tmp/.mount_Plow-Ln5viuw/resources/app.asar/node_modules/@domo/native-linuxsandbox/build/Release/linuxsandbox_launcher",
      ),
    ).toBe(
      "/tmp/.mount_Plow-Ln5viuw/resources/app.asar.unpacked/node_modules/@domo/native-linuxsandbox/build/Release/linuxsandbox_launcher",
    );
  });

  it("rewrites a Windows path with backslashes", () => {
    expect(
      unpackedPath(
        "C:\\Program Files\\Plow Latch\\resources\\app.asar\\node_modules\\@domo\\native-winsandbox\\build\\Release\\winsandbox_launcher.exe",
      ),
    ).toBe(
      "C:\\Program Files\\Plow Latch\\resources\\app.asar.unpacked\\node_modules\\@domo\\native-winsandbox\\build\\Release\\winsandbox_launcher.exe",
    );
  });

  it("leaves a from-source path alone", () => {
    const p = "/home/dev/repo/packages/native-linuxsandbox/build/Release/linuxsandbox_launcher";
    expect(unpackedPath(p)).toBe(p);
  });

  it("does not rewrite a directory that merely contains 'app.asar'", () => {
    expect(unpackedPath("/tmp/x/app.asar.backup/node_modules/tool")).toBe(
      "/tmp/x/app.asar.backup/node_modules/tool",
    );
    expect(unpackedPath("/tmp/x/my-app.asar/node_modules/tool")).toBe(
      "/tmp/x/my-app.asar/node_modules/tool",
    );
  });
});
