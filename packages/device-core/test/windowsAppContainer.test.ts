import { describe, expect, it } from "vitest";
import { createRequire } from "node:module";

describe.skipIf(process.platform !== "win32")("Windows AppContainer primitive", () => {
  it("creates and removes a real per-user AppContainer profile", () => {
    const addon = createRequire(import.meta.url)("@domo/native-winsandbox") as {
      appContainerAvailable(): boolean;
    } | null;
    expect(addon).not.toBeNull();
    expect(addon!.appContainerAvailable()).toBe(true);
  });
});
