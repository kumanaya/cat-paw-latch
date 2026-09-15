/**
 * Settings' fork-notice artwork. Bundled beside the asar as extraResource
 * (electron-builder.yml); from-source reads artwork/banner.png. The renderer
 * never fetches GitHub — CSP + offline.
 */
import path from "node:path";

export const FORK_BANNER_FILE = "fork-banner.png";
export const FORK_BANNER_SOURCE = "banner.png";

export function resolveForkBannerPath(opts: {
  isPackaged: boolean;
  dirname: string;
  resourcesPath: string;
}): string {
  if (opts.isPackaged) return path.join(opts.resourcesPath, FORK_BANNER_FILE);
  return path.join(opts.dirname, "..", "..", "..", "artwork", FORK_BANNER_SOURCE);
}
