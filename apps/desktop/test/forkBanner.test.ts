import path from "node:path";
import { describe, expect, it } from "vitest";
import { FORK_BANNER_FILE, resolveForkBannerPath } from "../src/forkBanner.js";

describe("resolveForkBannerPath", () => {
  it("packaged: the extraResource beside the asar, never GitHub", () => {
    const p = resolveForkBannerPath({
      isPackaged: true,
      dirname: "/repo/apps/desktop/dist",
      resourcesPath: "/opt/PlowLatch/resources",
    });
    expect(p).toBe(path.join("/opt/PlowLatch/resources", FORK_BANNER_FILE));
    expect(p).not.toMatch(/github|hermes-cat-paw/);
  });

  it("from source: the repo artwork, three levels above dist", () => {
    const p = resolveForkBannerPath({
      isPackaged: false,
      dirname: path.join("/repo", "apps", "desktop", "dist"),
      resourcesPath: "/nowhere",
    });
    expect(p).toBe(path.join("/repo", "artwork", "banner.png"));
  });
});
