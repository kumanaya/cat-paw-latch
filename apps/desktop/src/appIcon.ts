/**
 * The application/window icon. On macOS the bundle carries its icon
 * (`mac.icon`) and the Dock reads it, but Windows and Linux take a window's
 * taskbar icon from the `BrowserWindow` `icon` option — so with no icon set a
 * from-source run, and a packaged Linux AppImage whose desktop entry never
 * reaches `_NET_WM_ICON`, draw Electron's default. The packaged app ships the
 * repo artwork as an extraResource (electron-builder.yml); a from-source run
 * reads it straight from artwork/.
 *
 * Pure like trayIcon.ts, so the path logic is unit-testable without Electron.
 */
import path from "node:path";

/** File name of the app PNG inside the packaged resources dir. */
export const APP_ICON_FILE = "app-icon.png";

/** File name of the source artwork in the repo. */
export const APP_ICON_SOURCE = "domo-desktop-icon.png";

/**
 * Where the window PNG lives. Packaged: the extraResource beside the asar.
 * From source: the repo artwork (dist/main.js is three levels below the repo
 * root — the same climb trayIcon.ts and the dev dock icon make).
 */
export function resolveAppIconPath(opts: {
  isPackaged: boolean;
  dirname: string;
  resourcesPath: string;
}): string {
  if (opts.isPackaged) return path.join(opts.resourcesPath, APP_ICON_FILE);
  return path.join(opts.dirname, "..", "..", "..", "artwork", APP_ICON_SOURCE);
}
