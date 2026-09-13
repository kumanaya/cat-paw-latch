/**
 * Windows secret-file ACL lockdown: a fresh file's inherited profile DACL
 * (SYSTEM, Administrators, other users) becomes one protected owner-only
 * ACE — and the file stays readable, writable and appendable by us.
 *
 * Real addon, real temp files. Skipped where the addon is absent, like
 * every other native-gated suite; the packaged app always carries it
 * (afterPackWin refuses a pack without winfs.node).
 */
import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { lockdownSecretFile, readSecretFileSddl } from "@domo/device-core";

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});

function tempFile(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "domo-lock-"));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "secret.txt");
  fs.writeFileSync(file, "secret");
  return file;
}

/** Null unless the addon is built and answering on this host. */
function addonSddl(file: string): string | null {
  try {
    return readSecretFileSddl(file);
  } catch {
    return null;
  }
}

const probe = tempFile();
const HAVE_ADDON = addonSddl(probe) !== null;
cleanups.pop()!();
fs.rmSync(path.dirname(probe), { recursive: true, force: true });

const aceCount = (sddl: string): number => sddl.split("(A;").length - 1;

describe.skipIf(!HAVE_ADDON)("secret-file ACL lockdown", () => {
  it("replaces the inherited DACL with one protected owner-only ACE", () => {
    const file = tempFile();
    const before = readSecretFileSddl(file)!;
    // Inherited DACL: control flags vary (D:AI vs D: with ID on each ACE —
    // GHA Server 2025 TEMP uses the latter). More than the one ACE we leave.
    expect(before).toMatch(/D:[A-Z]*\(/);
    expect(aceCount(before)).toBeGreaterThan(1);
    const sid = lockdownSecretFile(file)!;
    expect(sid).toMatch(/^S-1-/);
    const after = readSecretFileSddl(file)!;
    // Protected (P right after D: — the observed form is D:PAI, where AI
    // governs propagation to children, not inheritance from the parent),
    // the SID granted, and nothing else.
    expect(after).toMatch(/D:P/);
    expect(after).toContain(sid);
    expect(aceCount(after)).toBe(1);
  });

  it("leaves the file readable, writable and appendable", () => {
    const file = tempFile();
    lockdownSecretFile(file);
    fs.appendFileSync(file, "+more");
    expect(fs.readFileSync(file, "utf8")).toBe("secret+more");
    fs.writeFileSync(file, "replaced");
    expect(fs.readFileSync(file, "utf8")).toBe("replaced");
  });

  it("is idempotent: a second lockdown writes the same single ACE", () => {
    const file = tempFile();
    const first = lockdownSecretFile(file)!;
    const second = lockdownSecretFile(file)!;
    expect(second).toBe(first);
    const sddl = readSecretFileSddl(file)!;
    expect(aceCount(sddl)).toBe(1);
    // ConvertStringSecurityDescriptor emits well-known aliases (LA = RID 500)
    // on some images; the numeric SID is what lockdown returned.
    expect(sddl.includes(first) || (/^S-1-5-21-.*-500$/.test(first) && /;;;LA(?:;|\))/.test(sddl))).toBe(true);
  });
});
