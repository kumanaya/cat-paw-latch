/**
 * The window icon is a surface only a real window can show; what a headless
 * test can pin is the plumbing — the wrong file in the wrong build — so a
 * packaged Linux run (which never gets an icon from the desktop entry) does
 * not silently fall back to Electron's default.
 */
import path from "node:path";
import { describe, expect, it } from "vitest";
import { resolveAppIconPath } from "../src/appIcon.js";

describe("resolveAppIconPath", () => {
  it("packaged: the extraResource beside the asar, never the repo", () => {
    const p = resolveAppIconPath({
      isPackaged: true,
      dirname: "/repo/apps/desktop/dist",
      resourcesPath: "/opt/PlowLatch/resources",
    });
    expect(p).toBe(path.join("/opt/PlowLatch/resources", "app-icon.png"));
    expect(p).not.toContain("artwork");
  });

  it("from source: the repo artwork, three levels above dist", () => {
    const p = resolveAppIconPath({
      isPackaged: false,
      dirname: path.join("/repo", "apps", "desktop", "dist"),
      resourcesPath: "/nowhere",
    });
    expect(p).toBe(path.join("/repo", "artwork", "domo-desktop-icon.png"));
  });
});
