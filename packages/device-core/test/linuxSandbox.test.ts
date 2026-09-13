import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

const ON_LINUX = process.platform === "linux";

describe.skipIf(!ON_LINUX)("Linux bubblewrap cage addon", () => {
  it("loads and reports the cage available on a desktop host with bwrap + systemd", () => {
    const addon = createRequire(import.meta.url)("@domo/native-linuxsandbox") as { available(): boolean } | null;
    expect(addon).not.toBeNull();
    expect(addon!.available()).toBe(true);
  });
});
