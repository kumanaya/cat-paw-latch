/**
 * The tray icon is the one surface a DOM read can never prove: only a
 * running app on a real shelf shows it. What CAN go wrong headlessly is the
 * plumbing around it — the wrong file in the wrong build, or a size the
 * shelf was never meant to show — so that is what these pin down.
 */
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  resolveTrayIconPath,
  TRAY_ICON_FILE,
  trayIconSize,
} from "../src/trayIcon.js";

describe("trayIconSize", () => {
  it("is square on every platform", () => {
    for (const platform of ["win32", "darwin", "linux"] as const) {
      const size = trayIconSize(platform);
      expect(size.width).toBe(size.height);
      expect(size.width).toBeGreaterThan(0);
    }
  });

  it("uses the small Windows shelf size, not the source artwork", () => {
    expect(trayIconSize("win32")).toEqual({ width: 16, height: 16 });
  });
});

describe("resolveTrayIconPath", () => {
  it("packaged: the extraResource beside the asar, never the repo", () => {
    const p = resolveTrayIconPath({
      isPackaged: true,
      dirname: "/repo/apps/desktop/dist",
      resourcesPath: "/Applications/Plow Latch.app/Contents/Resources",
    });
    expect(p).toBe(
      path.join("/Applications/Plow Latch.app/Contents/Resources", TRAY_ICON_FILE),
    );
    expect(p).not.toContain("artwork");
  });

  it("from source: the repo artwork, three levels above dist", () => {
    const p = resolveTrayIconPath({
      isPackaged: false,
      dirname: path.join("/repo", "apps", "desktop", "dist"),
      resourcesPath: "/nowhere",
    });
    expect(p).toBe(path.join("/repo", "artwork", "domo-desktop-icon.png"));
  });
});
