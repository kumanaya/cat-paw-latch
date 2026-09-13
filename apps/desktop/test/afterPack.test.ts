/**
 * The packaging hook is the last gate before a distributable exists, and the
 * app it must never let through is the one that installs, launches and serves
 * intents with browsing dead — nothing downstream catches that. Every way it
 * refuses fires before the first codesign call, so they are pure fs + throw and
 * belong here.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const afterPack = createRequire(import.meta.url)("../build/afterPack.cjs") as (
  context: unknown,
) => Promise<void>;

/** What a packaged build cannot work under browser-runtime: only the Camoufox
 * tree now. No Python ships, the server is a Node script in app.asar.unpacked,
 * and the vault ships no payload (TypeScript in dist/ plus a Keychain item). */
const PAYLOADS = ["camoufox"];

// @ts-expect-error — a build-time .mjs with no type declarations.
import { VENDORED } from "../../../scripts/vendored-providers.mjs";

/** Every vendored CLI the packed app must carry, and the arches it stages. */
const PROVIDERS: { command: string; arches: Record<string, unknown> }[] = VENDORED;

const IDENTITY = "Developer ID Application: Nobody (TEAMID)";

/** `mac` is electron-builder's resolved mac config. It defaults to carrying the
 * identity the environment also has, because that agreement is what every
 * packaging recipe produces; pass `{}` for a build that configured none. */
const contextFor = (appOutDir: string, mac: { identity?: string | null } = { identity: IDENTITY }) => ({
  appOutDir,
  packager: {
    appInfo: { productFilename: "Plow Latch" },
    platformSpecificBuildOptions: mac,
  },
});

describe("the packaging hook refuses before it signs", () => {
  let dir: string;
  const realIdentity = process.env.CODESIGN_IDENTITY;

  const resourcesDir = () => path.join(dir, "Plow Latch.app", "Contents", "Resources");
  const runtimeDir = () => path.join(resourcesDir(), "browser-runtime");

  /** Every provider as production ships it: one thin binary per arch. */
  const packProviders = () => {
    for (const { command, arches } of PROVIDERS) {
      for (const arch of Object.keys(arches)) {
        fs.mkdirSync(path.join(resourcesDir(), "providers", command, arch), { recursive: true });
        fs.writeFileSync(path.join(resourcesDir(), "providers", command, arch, command), "#!/bin/sh\n");
      }
    }
  };

  /** A universal (fat) Mach-O header carrying x86_64 + arm64 — all the hook
   * reads. 20-byte nfat_arch entries, cputype first, big-endian. */
  const fatUniversalHeader = () => {
    const buf = Buffer.alloc(8 + 2 * 20);
    buf.writeUInt32BE(0xcafebabe, 0);
    buf.writeUInt32BE(2, 4);
    buf.writeUInt32BE(0x01000007, 8); // x86_64
    buf.writeUInt32BE(0x0100000c, 28); // arm64
    return buf;
  };

  /** A thin little-endian 64-bit Mach-O header for one arch. */
  const thinHeader = (cputype: number) => {
    const buf = Buffer.alloc(8);
    buf.writeUInt32LE(0xfeedfacf, 0);
    buf.writeUInt32LE(cputype, 4);
    return buf;
  };

  const keychainAddonPath = () =>
    path.join(
      resourcesDir(), "app.asar.unpacked", "node_modules", "@domo", "native-keychain",
      "build", "Release", "keychain.node",
    );

  const packKeychainAddon = (bytes: Buffer = fatUniversalHeader()) => {
    fs.mkdirSync(path.dirname(keychainAddonPath()), { recursive: true });
    fs.writeFileSync(keychainAddonPath(), bytes);
  };

  /** A packed app whose payloads all carry something, minus `omit`. */
  const pack = (omit?: string) => {
    const runtime = runtimeDir();
    packProviders();
    if (omit !== "keychain-addon") packKeychainAddon();
    for (const payload of PAYLOADS) {
      if (payload === omit) continue;
      fs.mkdirSync(path.join(runtime, payload), { recursive: true });
      fs.writeFileSync(path.join(runtime, payload, "carried"), "");
    }
    // The payload the hook looks inside, built as production ships it.
    if (omit !== "camoufox") {
      fs.mkdirSync(path.join(runtime, "camoufox", "Camoufox.app"), { recursive: true });
    }
    return runtime;
  };

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "afterpack-"));
    process.env.CODESIGN_IDENTITY = IDENTITY;
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    if (realIdentity === undefined) delete process.env.CODESIGN_IDENTITY;
    else process.env.CODESIGN_IDENTITY = realIdentity;
    // Credential-exchange path knobs some tests set; never set outside them.
    delete process.env.DOMO_CX_APPEX_SOURCE;
    delete process.env.DOMO_CX_PROFILE;
  });

  it("leaves the per-arch temp packs to the universal merge", async () => {
    await expect(afterPack(contextFor(path.join(dir, "mac-arm64-temp")))).resolves.toBeUndefined();
  });

  it("refuses an unsigned runtime rather than shipping one macOS will not load", async () => {
    delete process.env.CODESIGN_IDENTITY;
    pack();
    await expect(afterPack(contextFor(dir, {}))).rejects.toThrow(/no signing identity/);
  });

  it("falls back to the environment when the packager configured none", async () => {
    // Past both identity guards on the env alone: the camoufox refusal only
    // happens after an identity resolved.
    pack("camoufox");
    await expect(afterPack(contextFor(dir, {}))).rejects.toThrow("camoufox browser payload");
  });

  it("refuses an environment identity that is not the one sealing the app", async () => {
    pack();
    await expect(
      afterPack(contextFor(dir, { identity: "Developer ID Application: Someone Else (OTHER1)" })),
    ).rejects.toThrow(/is not the packager's identity/);
  });

  // However the camoufox payload comes up carrying no file — the runtime never
  // packed, packed empty, or all empty directories — it is the same refusal.
  it.each([
    { how: "never packed", prep: () => {} },
    { how: "runtime packed empty", prep: () => fs.mkdirSync(runtimeDir(), { recursive: true }) },
    { how: "camoufox left out", prep: () => pack("camoufox") },
    {
      how: "camoufox all empty directories",
      prep: () => {
        const runtime = pack("camoufox");
        fs.mkdirSync(path.join(runtime, "camoufox", "browsers", "official"), { recursive: true });
      },
    },
  ])("refuses when the camoufox payload was $how", async ({ prep }) => {
    prep();
    await expect(afterPack(contextFor(dir))).rejects.toThrow("camoufox browser payload");
  });

  // The addon's install script is tolerant on purpose (dev boxes without
  // Xcode CLT); the hook is where a release that lost the vault's SecItem
  // provider gets stopped instead of silently downgrading to safeStorage.
  it.each([
    { how: "absent", damage: () => fs.rmSync(keychainAddonPath()) },
    { how: "empty", damage: () => fs.writeFileSync(keychainAddonPath(), "") },
  ])("refuses a pack whose native-keychain addon is $how", async ({ damage }) => {
    pack();
    damage();
    await expect(afterPack(contextFor(dir))).rejects.toThrow(/no native-keychain addon/);
  });

  it.each([
    { arch: "arm64-only", cputype: 0x0100000c, missing: "x86_64" },
    { arch: "x86_64-only", cputype: 0x01000007, missing: "arm64" },
  ])("refuses a THIN ($arch) addon — it lands broken on the other arch's users", async ({ cputype, missing }) => {
    pack();
    packKeychainAddon(thinHeader(cputype));
    await expect(afterPack(contextFor(dir))).rejects.toThrow(
      new RegExp(`native-keychain addon is missing ${missing}`),
    );
  });

  it("refuses a build whose identity is explicitly null", async () => {
    pack();
    await expect(afterPack(contextFor(dir, { identity: null }))).rejects.toThrow(/ships unsigned/);
  });

  // Credential exchange (docs/CREDENTIAL-EXCHANGE.md) is UNCONDITIONAL in a
  // packaged build: the app is always signed with the AutoFill entitlement,
  // so a pack that quietly dropped the extension, the addon, or the Swift
  // shim would ship a release where the feature silently stopped. Every
  // piece missing is a refusal, exactly like the keychain addon's.
  describe("the credential-exchange pieces are mandatory", () => {
    const receivingPaths = () => [
      path.join(
        resourcesDir(), "app.asar.unpacked", "node_modules",
        "@domo", "native-credential-import", "build", "Release", "credential_import.node",
      ),
      path.join(resourcesDir(), "native", "libdomo-credential-import.dylib"),
    ];

    /** The addon + shim as production packs them: one universal binary each. */
    const packReceiving = () => {
      for (const file of receivingPaths()) {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, fatUniversalHeader());
      }
    };

    /** A built appex as build-native.mjs leaves it, minus nothing. */
    const packAppex = (bytes: Buffer = fatUniversalHeader()) => {
      const appex = path.join(dir, "fixture.appex");
      fs.mkdirSync(path.join(appex, "Contents", "MacOS"), { recursive: true });
      fs.writeFileSync(path.join(appex, "Contents", "MacOS", "PlowLatchCredentialProvider"), bytes);
      process.env.DOMO_CX_APPEX_SOURCE = appex;
      return appex;
    };

    beforeEach(() => {
      pack();
      packReceiving();
    });

    it.each([
      { what: "addon", at: 0 },
      { what: "shim", at: 1 },
    ])("refuses a pack whose credential-import $what is absent", async ({ at }) => {
      fs.rmSync(receivingPaths()[at]!);
      await expect(afterPack(contextFor(dir))).rejects.toThrow(/no credential-import/);
    });

    it("refuses a THIN shim — it lands broken on the other arch's users", async () => {
      fs.writeFileSync(receivingPaths()[1]!, thinHeader(0x0100000c));
      await expect(afterPack(contextFor(dir))).rejects.toThrow(/credential-import shim is missing x86_64/);
    });

    it("refuses when no appex was built", async () => {
      process.env.DOMO_CX_APPEX_SOURCE = path.join(dir, "never-built.appex");
      process.env.DOMO_CX_PROFILE = path.join(dir, "unused.provisionprofile");
      await expect(afterPack(contextFor(dir))).rejects.toThrow(/no built credential-provider appex/);
    });

    it("refuses when the extension's provisioning profile is missing", async () => {
      packAppex();
      process.env.DOMO_CX_PROFILE = path.join(dir, "missing.provisionprofile");
      await expect(afterPack(contextFor(dir))).rejects.toThrow(/provisionprofile is missing/);
    });

    it.each([
      { arch: "arm64-only", cputype: 0x0100000c, missing: "x86_64" },
      { arch: "x86_64-only", cputype: 0x01000007, missing: "arm64" },
    ])("refuses a THIN ($arch) appex — it lands broken on the other arch's users", async ({ cputype, missing }) => {
      packAppex(thinHeader(cputype));
      const profile = path.join(dir, "fixture.provisionprofile");
      fs.writeFileSync(profile, "not a real profile; the arch gate fires first");
      process.env.DOMO_CX_PROFILE = profile;
      await expect(afterPack(contextFor(dir))).rejects.toThrow(
        new RegExp(`credential-provider appex is missing ${missing}`),
      );
    });
  });

  // One expectation over every way an arch can be unusable, for every arch of
  // every row: absent, empty and stray-file-only are the same failure to the
  // gate — the binary is not there.
  it.each(
    PROVIDERS.flatMap(({ command, arches }) =>
      Object.keys(arches).flatMap((arch) =>
        [
          { how: "absent", damage: (d: string) => fs.rmSync(d, { recursive: true, force: true }) },
          { how: "a zero-byte binary", damage: (d: string) => fs.writeFileSync(path.join(d, command), "") },
          {
            how: "an arch folder carrying only a stray file",
            damage: (d: string) => {
              fs.rmSync(path.join(d, command));
              fs.writeFileSync(path.join(d, ".DS_Store"), "junk");
            },
          },
        ].map((c) => ({ ...c, command, arch })),
      ),
    ),
  )("refuses $command/$arch when it is $how", async ({ command, arch, damage }) => {
    // Silent half-install: a tree carrying only the packaging Mac's arch clears
    // every other gate and reaches the other arch's users with nothing.
    pack();
    damage(path.join(resourcesDir(), "providers", command, arch));
    await expect(afterPack(contextFor(dir))).rejects.toThrow(
      new RegExp(`no ${command} for ${arch}`),
    );
  });

  it.each(PROVIDERS)("names every arch $command is missing, not just the first", async (p) => {
    // One run of `just fetch-vendored` fixes them all; being told about one
    // arch at a time means one package run per arch to learn that.
    //
    // MEMBERSHIP, not a joined string. The claim is that every missing arch is
    // named — a hook that sorted them, or listed them one per line, would still
    // satisfy it. Asserting the join would pin the row's declaration order and
    // the separator, and fail a correct hook.
    pack();
    fs.rmSync(path.join(resourcesDir(), "providers", p.command), { recursive: true, force: true });
    const failure = await afterPack(contextFor(dir)).catch((e: Error) => e);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    // Anchored to the arch gate, then membership within it. Without the anchor
    // any error naming both arches passes — a refusal enumerating missing
    // binary PATHS would, without the gate ever emitting its summary.
    expect(message).toContain(`no ${p.command} for`);
    for (const arch of Object.keys(p.arches)) expect(message).toContain(arch);
  });

  it("refuses a camoufox tree a fuse left without a bundle", async () => {
    const runtime = pack();
    fs.rmSync(path.join(runtime, "camoufox", "Camoufox.app"), { recursive: true });
    await expect(afterPack(contextFor(dir))).rejects.toThrow(/holds no Camoufox\.app/);
  });
});

describe("the Windows pack gate", () => {
  // Same philosophy as the macOS keychain gate, per Windows payload: a
  // release missing the vault's Credential Manager provider would silently
  // downgrade every new vault to the key file, and one missing the Job
  // Object cage would disable command execution entirely. Both refuse.
  // The Windows camoufox runtime is not fetched yet, so its absence only
  // warns (asserted by the passing case below).
  let winDir: string;
  beforeEach(() => {
    winDir = fs.mkdtempSync(path.join(os.tmpdir(), "afterpack-win-"));
  });
  afterEach(() => {
    fs.rmSync(winDir, { recursive: true, force: true });
  });
  const winContextFor = (appOutDir: string, arch?: number | string) => ({
    appOutDir,
    electronPlatformName: "win32",
    ...(arch === undefined ? {} : { arch }),
  });
  const winResources = () => path.join(winDir, "resources");
  const winAddon = (pkg: string, file: string) =>
    path.join(winResources(), "app.asar.unpacked", "node_modules", "@domo", pkg, "build", "Release", file);
  const winLauncher = () => winAddon("native-winsandbox", "winsandbox_launcher.exe");
  // The smallest header the gate's PE reader accepts: DOS magic + e_lfanew +
  // PE signature + machine. Everything else about the file is unread.
  const winPeHeader = (machine: number) => {
    const header = Buffer.alloc(64 + 6);
    header.write("MZ", 0);
    header.writeUInt32LE(64, 0x3c);
    header.writeUInt32LE(0x00004550, 64);
    header.writeUInt16LE(machine, 68);
    return header;
  };
  const hostMachine = process.arch === "arm64" ? 0xaa64 : 0x8664;
  const packWinAddons = (machine = hostMachine) => {
    for (const [pkg, file] of [
      ["native-wincred", "wincred.node"],
      ["native-hello", "winhello.node"],
      ["native-winsandbox", "winsandbox.node"],
      ["native-fs", "winfs.node"],
    ] as const) {
      fs.mkdirSync(path.dirname(winAddon(pkg, file)), { recursive: true });
      fs.writeFileSync(winAddon(pkg, file), winPeHeader(machine));
    }
    fs.writeFileSync(winLauncher(), winPeHeader(machine));
  };
  const packWinBrowserAndProviders = (arch = process.arch === "arm64" ? "arm64" : "x64", machine = hostMachine) => {
    const browser = path.join(
      winResources(), "browser-runtime", "camoufox", arch,
      "browsers", "official", "fixture", "camoufox.exe",
    );
    fs.mkdirSync(path.dirname(browser), { recursive: true });
    fs.writeFileSync(browser, winPeHeader(machine));
    for (const { command } of PROVIDERS) {
      const provider = path.join(winResources(), "providers", command, arch, `${command}.exe`);
      fs.mkdirSync(path.dirname(provider), { recursive: true });
      fs.writeFileSync(provider, winPeHeader(machine));
    }
  };

  it.each([
    ["native-wincred", "wincred.node"],
    ["native-hello", "winhello.node"],
    ["native-winsandbox", "winsandbox.node"],
    ["native-fs", "winfs.node"],
  ])("refuses a pack whose %s addon is absent", async (pkg, file) => {
    packWinAddons();
    fs.rmSync(winAddon(pkg, file));
    await expect(afterPack(winContextFor(winDir))).rejects.toThrow(new RegExp(`no ${pkg} addon`));
  });

  it.each([
    ["native-wincred", "wincred.node"],
    ["native-hello", "winhello.node"],
    ["native-winsandbox", "winsandbox.node"],
    ["native-fs", "winfs.node"],
  ])("refuses a pack whose %s addon is empty", async (pkg, file) => {
    packWinAddons();
    fs.writeFileSync(winAddon(pkg, file), "");
    await expect(afterPack(winContextFor(winDir))).rejects.toThrow(new RegExp(`no ${pkg} addon`));
  });

  it("passes only with native addons, AppContainer, browser and providers for the target architecture", async () => {
    packWinAddons();
    packWinBrowserAndProviders();
    await expect(afterPack(winContextFor(winDir))).resolves.toBeUndefined();
  });

  it("accepts electron-builder's numeric x64 architecture enum", async () => {
    packWinAddons(0x8664);
    packWinBrowserAndProviders("x64", 0x8664);
    await expect(afterPack(winContextFor(winDir, 1))).resolves.toBeUndefined();
  });

  it("refuses a missing or wrong-arch Windows Camoufox payload", async () => {
    packWinAddons();
    await expect(afterPack(winContextFor(winDir))).rejects.toThrow(/no Windows Camoufox/);
    packWinBrowserAndProviders();
    const arch = process.arch === "arm64" ? "arm64" : "x64";
    const browser = path.join(winResources(), "browser-runtime", "camoufox", arch,
      "browsers", "official", "fixture", "camoufox.exe");
    fs.writeFileSync(browser, winPeHeader(process.arch === "arm64" ? 0x8664 : 0xaa64));
    await expect(afterPack(winContextFor(winDir))).rejects.toThrow(/Camoufox is not/);
  });

  it("refuses a missing or wrong-arch Windows provider", async () => {
    packWinAddons();
    packWinBrowserAndProviders();
    const arch = process.arch === "arm64" ? "arm64" : "x64";
    const provider = path.join(winResources(), "providers", PROVIDERS[0]!.command, arch, `${PROVIDERS[0]!.command}.exe`);
    fs.rmSync(provider);
    await expect(afterPack(winContextFor(winDir))).rejects.toThrow(/provider for/);
    fs.writeFileSync(provider, winPeHeader(process.arch === "arm64" ? 0x8664 : 0xaa64));
    await expect(afterPack(winContextFor(winDir))).rejects.toThrow(/provider is not/);
  });

  it("refuses a pack whose AppContainer launcher is absent or wrong-arch", async () => {
    packWinAddons();
    packWinBrowserAndProviders();
    fs.rmSync(winLauncher());
    await expect(afterPack(winContextFor(winDir))).rejects.toThrow(/no AppContainer launcher/);
    fs.writeFileSync(winLauncher(), winPeHeader(process.arch === "x64" ? 0xaa64 : 0x8664));
    await expect(afterPack(winContextFor(winDir))).rejects.toThrow(/launcher has a PE machine mismatch/);
  });

  it("refuses an addon built for the wrong arch", async () => {
    // Same crafted header, stamped with the machine this host is not.
    packWinAddons();
    packWinBrowserAndProviders();
    fs.writeFileSync(
      winAddon("native-winsandbox", "winsandbox.node"),
      winPeHeader(process.arch === "x64" ? 0xaa64 : 0x8664),
    );
    await expect(afterPack(winContextFor(winDir))).rejects.toThrow(/not .* \(PE machine mismatch\)/);
  });
});

describe("the Linux pack gate", () => {
  let linuxDir: string;
  beforeEach(() => {
    linuxDir = fs.mkdtempSync(path.join(os.tmpdir(), "afterpack-linux-"));
  });
  afterEach(() => {
    fs.rmSync(linuxDir, { recursive: true, force: true });
  });
  const linuxContextFor = (appOutDir: string, arch?: number | string) => ({
    appOutDir,
    electronPlatformName: "linux",
    ...(arch === undefined ? {} : { arch }),
  });
  const linuxResources = () => path.join(linuxDir, "resources");
  const linuxAddon = (...segs: string[]) =>
    path.join(linuxResources(), "app.asar.unpacked", "node_modules", "@domo", ...segs);
  // Minimal ELF header: magic + class/data/version + e_machine at offset 18.
  const elfHeader = (machine: number) => {
    const header = Buffer.alloc(20);
    header.writeUInt32BE(0x7f454c46, 0); // "\x7fELF"
    header[4] = 2; // ELFCLASS64
    header[5] = 1; // ELFDATA2LSB
    header[6] = 1;
    header.writeUInt16LE(machine, 18);
    return header;
  };
  const hostElf = process.arch === "arm64" ? 183 : 62;
  const otherElf = process.arch === "arm64" ? 62 : 183;

  it("refuses a pack whose native-linuxsandbox addon is absent", async () => {
    await expect(afterPack(linuxContextFor(linuxDir))).rejects.toThrow(/no native-linuxsandbox addon/);
  });

  it("refuses a pack whose bubblewrap launcher is absent", async () => {
    fs.mkdirSync(path.dirname(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox.node")), { recursive: true });
    fs.writeFileSync(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox.node"), elfHeader(hostElf));
    await expect(afterPack(linuxContextFor(linuxDir))).rejects.toThrow(/no bubblewrap launcher/);
  });

  it("refuses an addon built for the wrong arch", async () => {
    const dir = path.dirname(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox.node"));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox.node"), elfHeader(otherElf));
    fs.writeFileSync(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox_launcher"), elfHeader(hostElf));
    await expect(afterPack(linuxContextFor(linuxDir))).rejects.toThrow(/ELF machine mismatch/);
  });

  const packLinuxCage = () => {
    const dest = path.dirname(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox.node"));
    fs.mkdirSync(dest, { recursive: true });
    fs.writeFileSync(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox.node"), elfHeader(hostElf));
    fs.writeFileSync(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox_launcher"), elfHeader(hostElf));
  };
  const packLinuxBrowser = (machine = hostElf) => {
    const arch = process.arch === "arm64" ? "arm64" : "x64";
    const browser = path.join(linuxResources(), "browser-runtime", "camoufox", arch, "camoufox-bin");
    fs.mkdirSync(path.dirname(browser), { recursive: true });
    fs.writeFileSync(browser, elfHeader(machine));
  };
  const packLinuxProviders = (machine = hostElf) => {
    const arch = process.arch === "arm64" ? "arm64" : "x64";
    for (const { command } of PROVIDERS) {
      const provider = path.join(linuxResources(), "providers", command, arch, command);
      fs.mkdirSync(path.dirname(provider), { recursive: true });
      fs.writeFileSync(provider, elfHeader(machine));
    }
  };

  it("refuses a missing or wrong-arch Linux Camoufox payload", async () => {
    packLinuxCage();
    await expect(afterPack(linuxContextFor(linuxDir))).rejects.toThrow(/no Linux Camoufox/);
    packLinuxBrowser(otherElf);
    await expect(afterPack(linuxContextFor(linuxDir))).rejects.toThrow(/Linux Camoufox is not/);
  });

  it("refuses a missing or wrong-arch Linux provider", async () => {
    packLinuxCage();
    packLinuxBrowser();
    await expect(afterPack(linuxContextFor(linuxDir))).rejects.toThrow(/provider for/);
    packLinuxProviders(otherElf);
    await expect(afterPack(linuxContextFor(linuxDir))).rejects.toThrow(/provider is not/);
  });

  it.skipIf(process.platform !== "linux")(
    "passes when the real cage addon, launcher and Camoufox are packed and --probe succeeds",
    async () => {
      const built = path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        "../../../packages/native-linuxsandbox/build/Release",
      );
      const addonSrc = path.join(built, "linuxsandbox.node");
      const launcherSrc = path.join(built, "linuxsandbox_launcher");
      if (!fs.existsSync(addonSrc) || !fs.existsSync(launcherSrc)) return;
      const dest = path.dirname(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox.node"));
      fs.mkdirSync(dest, { recursive: true });
      fs.copyFileSync(addonSrc, linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox.node"));
      fs.copyFileSync(launcherSrc, linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox_launcher"));
      fs.chmodSync(linuxAddon("native-linuxsandbox", "build", "Release", "linuxsandbox_launcher"), 0o755);
      packLinuxBrowser();
      packLinuxProviders();
      await expect(afterPack(linuxContextFor(linuxDir))).resolves.toBeUndefined();
    },
  );
});
