/**
 * Menu-bar/tray icon. Pure so it is unit-testable without Electron
 * (trayIcon.test.ts); main.ts feeds it app.isPackaged, its own dist dir and
 * process.resourcesPath, then loads and resizes the PNG itself.
 *
 * The tray used to be a 1x1 transparent placeholder on every platform, so on
 * Windows the "floating menu" had no icon at all. The packaged app now ships
 * the repo artwork as an extraResource (electron-builder.yml); a from-source
 * run reads it straight from artwork/.
 */
import path from "node:path";

/** File name of the tray PNG inside the packaged resources dir. */
export const TRAY_ICON_FILE = "tray-icon.png";

/** File name of the source artwork in the repo. */
export const TRAY_ICON_SOURCE = "domo-desktop-icon.png";

export interface TrayIconSize {
  width: number;
  height: number;
}

/**
 * Pixel size the tray icon is resized to. One size per platform: the OS
 * scales a 1024px source down on its own, but the result is blurrier than
 * resizing in-process, and the size differs per shelf.
 */
export function trayIconSize(platform: NodeJS.Platform): TrayIconSize {
  if (platform === "win32") return { width: 16, height: 16 };
  if (platform === "darwin") return { width: 18, height: 18 };
  return { width: 22, height: 22 };
}

/**
 * Where the tray PNG lives. Packaged: the extraResource beside the asar.
 * From source: the repo artwork (dist/main.js is three levels below the
 * repo root — the same climb main.ts uses for its dev dock icon).
 */
export function resolveTrayIconPath(opts: {
  isPackaged: boolean;
  dirname: string;
  resourcesPath: string;
}): string {
  if (opts.isPackaged) return path.join(opts.resourcesPath, TRAY_ICON_FILE);
  return path.join(opts.dirname, "..", "..", "..", "artwork", TRAY_ICON_SOURCE);
}
