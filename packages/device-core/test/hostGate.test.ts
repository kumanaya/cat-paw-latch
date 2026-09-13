/**
 * Host-gate diagnosis: the pure tree over scripted facts, the helpers that
 * read an error, the path-to-permission table, and the real probes against
 * fixtures — a readable file, a missing one, a `chmod 000` one, and a FIFO
 * that hangs an open exactly the way a consent prompt does.
 *
 * Nothing here needs a TCC-protected file: the tree is a function over
 * facts, and the facts are written down per case. Whether the real macOS
 * answers match is the manual pass in docs/TESTING-THE-APP.md.
 */
import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonicalize } from "@domo/protocol";
import {
  appleEventTarget,
  candidatePaths,
  collectFacts,
  diagnose,
  diagnosisPayload,
  guardedPrefix,
  HostFacts,
  isHostGate,
  nodeProbes,
  probeWindowsFolderAccess,
  sandboxGrants,
  sandboxKindFor,
  scriptedProbes,
  errnoFromHint,
  serviceBehind,
  sipProtected,
  stderrHint,
  tildeRelative,
  windowsGuardedPrefix,
  windowsSystemProtected,
  linuxGuardedPrefix,
  linuxSystemProtected,
} from "@domo/device-core";

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});
function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "domo-gate-"));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

const HOME = "/Users/probe";

/** The macOS tree, pinned: these leaves assert TCC sentences, so they run
 *  under the darwin platform on any host — including Windows and Linux CI. */
const diagnoseMac = (f: HostFacts) => diagnose(f, { platform: "darwin" });

/** The macOS profile's decision, pinned for the same reason. */
const grantsMac = (
  args: Parameters<typeof sandboxGrants>[0],
  target: string,
) => sandboxGrants(args, target, { platform: "darwin" });

/** A fact set with nothing wrong in it; each case overrides what it needs. */
function facts(overrides: Partial<HostFacts> = {}): HostFacts {
  return {
    op: "read",
    path: "~/Documents/report.txt",
    paths_examined: ["~/Documents/report.txt"],
    path_exists: true,
    is_directory: false,
    posix_readable: true,
    posix_writable: true,
    immutable_flag: false,
    errno: null,
    syscall: null,
    stderr_hint: null,
    ran_sandboxed: false,
    sandbox_kind: "none",
    sandbox_allows_read: null,
    sandbox_allows_write: null,
    path_approved: true,
    probe_withheld: false,
    app_process_open: "ok",
    hung: false,
    tcc_guarded_prefix: null,
    full_disk_access_granted: null,
    sip_protected: false,
    automation_target: null,
    automation_status: null,
    service_permission: null,
    service_status: null,
    ...overrides,
  };
}

describe("guardedPrefix — which switch governs a path", () => {
  it.each([
    [`${HOME}/Downloads/x.zip`, "files_downloads"],
    [`${HOME}/Desktop`, "files_desktop"],
    [`${HOME}/Documents/a/b/c.txt`, "files_documents"],
    [`${HOME}/Library/Mobile Documents/com~apple~CloudDocs/n.md`, "files_icloud_drive"],
    [`${HOME}/Library/Messages/chat.db`, "full_disk_access"],
    [`${HOME}/Library/Safari/Bookmarks.plist`, "full_disk_access"],
    [`${HOME}/Library/Mail/V10/x.emlx`, "full_disk_access"],
    [`${HOME}/Library/Application Support/com.apple.TCC/TCC.db`, "full_disk_access"],
    [`${HOME}/Library/Application Support/AddressBook/AddressBook-v22.abcddb`, "contacts"],
    [`${HOME}/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite`, "full_disk_access"],
    [`${HOME}/Library/Containers/com.apple.Notes/Data/x`, "full_disk_access"],
    [`${HOME}/Library/Calendars/x.ics`, "calendars"],
    [`${HOME}/Pictures/Photos Library.photoslibrary/database/x`, "photos"],
    ["/Volumes/Backup/x", "files_volumes"],
    ["/Library/Application Support/com.apple.TCC/TCC.db", "full_disk_access"],
  ])("%s → %s", (p, permission) => {
    expect(guardedPrefix(p, HOME)).toBe(permission);
  });

  it.each([
    `${HOME}/.ssh/id_rsa`,
    `${HOME}/Plow/out.txt`,
    `${HOME}/Library/Application Support/Plow-Latch/settings.json`,
    `${HOME}/Library/Caches/x`,
    "/tmp/x",
    "/Users/Shared/x",
    `${HOME}/DocumentsArchive/x`, // a sibling that merely starts with the name
    `${HOME}/Downloads2/x`,
  ])("%s is not guarded", (p) => {
    expect(guardedPrefix(p, HOME)).toBeNull();
  });

  it("tolerates a home given with a trailing slash", () => {
    expect(guardedPrefix(`${HOME}/Desktop/x`, `${HOME}/`)).toBe("files_desktop");
  });

  it("names SIP roots and their carve-outs", () => {
    expect(sipProtected("/System/Library/x")).toBe(true);
    expect(sipProtected("/usr/bin/ls")).toBe(true);
    expect(sipProtected("/usr/local/bin/x")).toBe(false);
    expect(sipProtected("/System/Volumes/Data/Users/x")).toBe(false);
    expect(sipProtected(`${HOME}/x`)).toBe(false);
  });

  it("folds the owner's home to ~ and leaves other paths alone", () => {
    expect(tildeRelative(`${HOME}/Documents/x`, HOME)).toBe("~/Documents/x");
    expect(tildeRelative(HOME, HOME)).toBe("~");
    expect(tildeRelative("/Users/probefake/x", HOME)).toBe("/Users/probefake/x");
    expect(tildeRelative("/tmp/x", "")).toBe("/tmp/x");
  });
});

describe("reading an error", () => {
  it("reads sqlite's 'authorization denied' as macOS refusing the open", () => {
    // Verbatim from a packaged build without Full Disk Access.
    const out = 'Error: unable to open database "/Users/x/Library/Messages/chat.db": authorization denied\n';
    expect(stderrHint(out)).toBe("authorization_denied");
    expect(errnoFromHint("authorization_denied")).toBe("EPERM");
    expect(candidatePaths([out])).toEqual(["/Users/x/Library/Messages/chat.db"]);
  });

  it("reads -10004 as the app refusing a sandboxed sender, and names it so", () => {
    expect(stderrHint("59:141: execution error: Mail got an error: A privilege violation occurred. (-10004)")).toBe("apple_event_privilege_violation");
    const base = { automation_target: "Mail", stderr_hint: "apple_event_privilege_violation" as const, ran_sandboxed: true, sandbox_kind: "seatbelt" as const };
    const granted = diagnoseMac(facts({ ...base, automation_status: "granted" }));
    expect(granted.cause).toBe("app_refuses_sandboxed_sender");
    expect(granted.confidence).toBe("confirmed");
    expect(granted.permission).toBeNull();
    // The way out is the unsandboxed script tool, and the agent is told so.
    expect(granted.retry).toBe("with_plow_run_applescript");
    expect(granted.owner_action).toMatch(/^Mail refuses this command from any sandboxed process/);
    expect(granted.owner_action).toMatch(/no permission in System Settings changes that/);
    expect(granted.owner_action).toMatch(/AppleScript tool instead, which runs outside the sandbox/);
    expect(diagnoseMac(facts({ ...base, automation_status: "not_asked" })).confidence).toBe("likely");
    // The same error from a script that ran OUTSIDE the sandbox is not the
    // sender's doing: the app refused on its own terms, and no gate is named.
    const bare = diagnoseMac(facts({ ...base, ran_sandboxed: false, sandbox_kind: "none" as const, automation_status: "granted" }));
    expect(bare.cause).toBe("unknown");
    expect(bare.evidence.join(" ")).toMatch(/ran outside the sandbox/);
  });

  it("reads AppleScript's -54 as a scripted app refusing its data", () => {
    expect(stderrHint("143:474: execution error: File permission error. (-54)")).toBe("scripted_data_not_permitted");
    expect(errnoFromHint("scripted_data_not_permitted")).toBeNull();
    expect(serviceBehind("Contacts")).toBe("contacts");
    expect(serviceBehind("Calendar")).toBe("calendars");
    expect(serviceBehind("Messages")).toBeNull();
  });

  it("a scripted app refusing its data is that service's own permission, by what macOS reports", () => {
    // The event reached Contacts.app (Automation consent is granted); what
    // came back is a -54, which is the Contacts data permission refusing
    // the calling app. Denied: confirmed. Never asked: likely, since a
    // scripted read raises no dialog — the Capabilities tab's row does.
    // Granted: something else, and no switch to send the owner to.
    const base = {
      automation_target: "Contacts",
      automation_status: "granted" as const,
      stderr_hint: "scripted_data_not_permitted" as const,
      service_permission: "contacts" as const,
    };
    const denied = diagnoseMac(facts({ ...base, service_status: "denied" }));
    expect(denied.cause).toBe("macos_permission");
    expect(denied.confidence).toBe("confirmed");
    expect(denied.permission).toBe("contacts");
    expect(denied.owner_action).toMatch(/Capabilities tab, allow Contacts/);
    expect(denied.owner_action).toMatch(/System Settings > Privacy & Security > Contacts/);
    const unasked = diagnoseMac(facts({ ...base, service_status: "not_asked" }));
    expect(unasked.cause).toBe("macos_permission");
    expect(unasked.confidence).toBe("likely");
    expect(unasked.evidence.join(" ")).toMatch(/never asked/);
    const granted = diagnoseMac(facts({ ...base, service_status: "granted" }));
    expect(granted.cause).toBe("unknown");
    // Not a data-holding target: the hint means nothing, and the tree moves on.
    const messages = diagnoseMac(facts({ ...base, automation_target: "Messages", service_permission: null, service_status: null }));
    expect(messages.cause).not.toBe("macos_permission");
  });

  it("reads the whole sqlite and AppleScript shapes, not the words on their own", () => {
    // Ordinary output can say these things; only the tools' own error lines count.
    expect(stderrHint("authorization denied for user bob, see the policy")).toBeNull();
    expect(stderrHint("a privilege violation was logged at 09:00")).toBeNull();
    expect(stderrHint("Runtime error: near line 1: authorization denied (23)")).toBe("authorization_denied");
    expect(stderrHint("Error: authorization denied")).toBe("authorization_denied");
    expect(stderrHint("execution error: Mail got an error: A privilege violation occurred. (-10004)")).toBe("apple_event_privilege_violation");
  });

  it("recognises the few stderr shapes worth following up", () => {
    expect(stderrHint("ls: /Users/x/Desktop: Operation not permitted")).toBe("operation_not_permitted");
    expect(stderrHint("cat: /etc/shadow: Permission denied")).toBe("permission_denied");
    expect(stderrHint("Error: in prepare, unable to open database file (14)")).toBe("sqlite_unable_to_open");
    expect(stderrHint("execution error: Not authorized to send Apple events to Messages. (-1743)")).toBe(
      "apple_event_not_permitted",
    );
    expect(stderrHint("cp: /System/x: Read-only file system")).toBe("read_only_filesystem");
    expect(stderrHint("all good")).toBeNull();
  });

  it("collects absolute and ~ paths from argv and stderr, bounded and deduplicated", () => {
    const argv = ["sqlite3", "-readonly", "~/Library/Messages/chat.db", "select 1"];
    const stderr = "Error: unable to open database \"/Users/x/Library/Messages/chat.db\": Operation not permitted";
    expect(candidatePaths([argv.join(" "), stderr])).toEqual([
      "~/Library/Messages/chat.db",
      "/Users/x/Library/Messages/chat.db",
    ]);
    // Glued to a flag or a key, wrapped in quotes, trailing punctuation.
    expect(candidatePaths(["--db=/a/b", "path:'/c/d',", "\"/e/f\"."])).toEqual(["/a/b", "/c/d", "/e/f"]);
    // The program reporting a refusal is not the path it reports about —
    // unless the line names nothing else.
    expect(candidatePaths(["/bin/sh: /Users/x/Desktop/a: Operation not permitted"])).toEqual(["/Users/x/Desktop/a"]);
    expect(candidatePaths(["sh: line 1: /Users/x/Desktop/a: Operation not permitted"])).toEqual(["/Users/x/Desktop/a"]);
    expect(candidatePaths(["/Users/x/Desktop/a: Operation not permitted"])).toEqual(["/Users/x/Desktop/a"]);
    // Relative paths are never guessed at, and a bare "/" is not a file.
    expect(candidatePaths(["ls / ./x ../y"])).toEqual([]);
    const many = Array.from({ length: 20 }, (_, i) => `/p/${i}`).join(" ");
    expect(candidatePaths([many])).toHaveLength(8);
  });
});

describe("diagnose — the tree, one leaf per case", () => {
  it("names the hang: a consent dialog is holding the open", () => {
    const d = diagnoseMac(facts({ app_process_open: "hung", tcc_guarded_prefix: "files_downloads" }));
    expect(d.cause).toBe("prompt_waiting");
    expect(d.confidence).toBe("confirmed");
    expect(d.permission).toBe("files_downloads");
    expect(d.retry).toBe("after_owner_answers_prompt");
    expect(d.owner_action).toMatch(/dialog is open on the Mac's screen/);
    expect(isHostGate(d.cause)).toBe(true);
  });

  it("a hang outside any known gate is only likely a prompt", () => {
    const d = diagnoseMac(facts({ hung: true, app_process_open: null, path: "/Volumes/x", tcc_guarded_prefix: null }));
    expect(d.cause).toBe("prompt_waiting");
    expect(d.confidence).toBe("likely");
  });

  it("confirms a TCC refusal: the app itself is refused, the path is guarded, FDA is off", () => {
    const d = diagnoseMac(
      facts({
        errno: "EPERM",
        app_process_open: "EPERM",
        tcc_guarded_prefix: "full_disk_access",
        full_disk_access_granted: false,
        path: "~/Library/Messages/chat.db",
      }),
    );
    expect(d.cause).toBe("macos_permission");
    expect(d.confidence).toBe("confirmed");
    expect(d.permission).toBe("full_disk_access");
    expect(d.requires_relaunch).toBe(true);
    expect(d.retry).toBe("after_owner_grants");
    expect(d.owner_action).toMatch(/Full Disk Access, turn on Plow Latch/);
    expect(d.ruled_out).toEqual(expect.arrayContaining(["file missing", "sandbox bound"]));
    expect(d.evidence.join(" ")).toMatch(/Full Disk Access is not granted/);
  });

  it("a folder gate names its own switch and offers FDA as the umbrella", () => {
    const d = diagnoseMac(
      facts({
        errno: "EPERM",
        app_process_open: "EPERM",
        tcc_guarded_prefix: "files_desktop",
        full_disk_access_granted: false,
        path: "~/Desktop/notes.txt",
      }),
    );
    expect(d.cause).toBe("macos_permission");
    expect(d.permission).toBe("files_desktop");
    expect(d.requires_relaunch).toBe(false);
    expect(d.owner_action).toMatch(/Files and Folders > Desktop Folder/);
    expect(d.owner_action).toMatch(/Full Disk Access instead covers/);
  });

  it("rules TCC out when Full Disk Access is granted and the path is still refused", () => {
    const d = diagnoseMac(
      facts({
        errno: "EPERM",
        app_process_open: "EPERM",
        tcc_guarded_prefix: "full_disk_access",
        full_disk_access_granted: true,
      }),
    );
    expect(d.cause).toBe("unknown");
    expect(d.ruled_out).toContain("macOS permission (Full Disk Access is granted)");
    expect(d.owner_action).toBeNull();
    expect(isHostGate(d.cause)).toBe(false);
  });

  it("tells our own seatbelt from macOS: the app can open it, the profile could not", () => {
    const d = diagnoseMac(
      facts({
        op: "exec",
        errno: "EPERM",
        ran_sandboxed: true,
        sandbox_kind: "seatbelt",
        app_process_open: "ok",
        sandbox_allows_read: true,
        sandbox_allows_write: false,
        path: "~/Plow/out.txt",
      }),
    );
    expect(d.cause).toBe("outside_approved_bound");
    expect(d.confidence).toBe("confirmed");
    expect(d.retry).toBe("with_declared_path");
    expect(d.ruled_out).toContain("macOS permission");
    expect(d.owner_action).toMatch(/write_paths/);
    // Under seatbelt the profile is the mechanism, and the evidence says so.
    expect(d.evidence.join(" ")).toMatch(/sandbox profile allows no writes/);
  });

  it("does not blame the sandbox when the profile allowed the path too", () => {
    const d = diagnoseMac(
      facts({
        op: "exec",
        errno: "EPERM",
        ran_sandboxed: true,
        sandbox_kind: "seatbelt",
        app_process_open: "ok",
        sandbox_allows_read: true,
        sandbox_allows_write: true,
      }),
    );
    expect(d.cause).toBe("unknown");
    expect(d.evidence.join(" ")).toMatch(/refusal was elsewhere/);
  });

  it("sqlite's WAL case under a read-only profile is the sandbox, not a missing file", () => {
    const d = diagnoseMac(
      facts({
        op: "exec",
        stderr_hint: "sqlite_unable_to_open",
        ran_sandboxed: true,
        sandbox_kind: "seatbelt",
        app_process_open: "ok",
        sandbox_allows_read: true,
        sandbox_allows_write: false,
        path: "~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite",
      }),
    );
    expect(d.cause).toBe("outside_approved_bound");
    expect(d.confidence).toBe("likely");
    expect(d.evidence.join(" ")).toMatch(/-shm/);
  });

  it("EACCES with denying mode bits is ordinary permissions", () => {
    const d = diagnoseMac(facts({ errno: "EACCES", posix_readable: false, app_process_open: "EACCES" }));
    expect(d.cause).toBe("posix_permissions");
    expect(d.confidence).toBe("confirmed");
    expect(d.owner_action).toMatch(/chown\/chmod/);
    // EACCES with bits that should allow it: still the best guess, less sure.
    expect(diagnoseMac(facts({ errno: "EACCES", posix_readable: true })).confidence).toBe("likely");
  });

  it("sqlite's 'unable to open' is the WAL bound only when the app itself can open the file", () => {
    // The words are the same for a database the app is refused — Full
    // Disk Access off — and that refusal is the story, not the -shm index.
    const base = { stderr_hint: "sqlite_unable_to_open" as const, ran_sandboxed: true, sandbox_kind: "seatbelt" as const, sandbox_allows_read: true, sandbox_allows_write: false, path: "~/Library/Messages/chat.db", tcc_guarded_prefix: "full_disk_access" as const, full_disk_access_granted: false, errno: null };
    const refused = diagnoseMac(facts({ ...base, app_process_open: "EPERM" }));
    expect(refused.cause).toBe("macos_permission");
    expect(refused.permission).toBe("full_disk_access");
    expect(refused.confidence).toBe("confirmed");
    const wal = diagnoseMac(facts({ ...base, app_process_open: "ok" }));
    expect(wal.cause).toBe("outside_approved_bound");
  });

  it("a locked flag and a SIP root each get their own verdict", () => {
    const locked = diagnoseMac(facts({ errno: "EPERM", immutable_flag: true, app_process_open: "EPERM" }));
    expect(locked.cause).toBe("immutable_file");
    expect(locked.owner_action).toMatch(/chflags nouchg/);
    const sip = diagnoseMac(facts({ errno: "EPERM", sip_protected: true, path: "/System/x", app_process_open: "EPERM" }));
    expect(sip.cause).toBe("sip_protected");
    expect(sip.retry).toBe("with_different_path");
    const rofs = diagnoseMac(facts({ errno: "EROFS", sip_protected: true, path: "/usr/x" }));
    expect(rofs.cause).toBe("sip_protected");
  });

  it("a missing file is a finding, not a gate", () => {
    const d = diagnoseMac(facts({ errno: "ENOENT", path_exists: false, app_process_open: "ENOENT" }));
    expect(d.cause).toBe("not_found");
    expect(d.confidence).toBe("confirmed");
    expect(isHostGate(d.cause)).toBe(false);
    expect(d.owner_action).toBeNull();
  });

  it("with no probe answer, a guarded prefix is only a likely TCC refusal", () => {
    const d = diagnoseMac(
      facts({ errno: "EPERM", app_process_open: null, tcc_guarded_prefix: "files_documents", full_disk_access_granted: false }),
    );
    expect(d.cause).toBe("macos_permission");
    expect(d.confidence).toBe("likely");
  });

  it("an EPERM the app itself cannot reproduce, on an unguarded path, is unknown with evidence", () => {
    const d = diagnoseMac(facts({ errno: "EPERM", app_process_open: "EPERM", path: "/opt/x" }));
    expect(d.cause).toBe("unknown");
    expect(d.evidence.join(" ")).toMatch(/not under any location macOS is known to guard/);
    expect(d.ruled_out).toContain("sandbox bound");
  });

  it("a failure with no errno and no path is honestly unknown", () => {
    const d = diagnoseMac(facts({ path: null, path_exists: null, app_process_open: null }));
    expect(d.cause).toBe("unknown");
    expect(d.evidence.join(" ")).toMatch(/no errno and no path/);
  });

  describe("Apple events", () => {
    it("denied Automation consent is a confirmed permission", () => {
      const d = diagnoseMac(facts({ op: "exec", automation_target: "Messages", automation_status: "denied" }));
      expect(d.cause).toBe("macos_permission");
      expect(d.permission).toBe("automation");
      expect(d.confidence).toBe("confirmed");
      expect(d.owner_action).toMatch(/Automation, allow Plow Latch to control Messages/);
    });

    it("-1743 with consent never asked is the dialog, likely", () => {
      const d = diagnoseMac(
        facts({
          op: "exec",
          automation_target: "Messages",
          automation_status: "not_asked",
          stderr_hint: "apple_event_not_permitted",
        }),
      );
      expect(d.cause).toBe("prompt_waiting");
      expect(d.confidence).toBe("likely");
    });

    it("-1743 with consent granted points at the build, not the owner", () => {
      const d = diagnoseMac(
        facts({
          op: "exec",
          automation_target: "Messages",
          automation_status: "granted",
          stderr_hint: "apple_event_not_permitted",
        }),
      );
      expect(d.cause).toBe("unknown");
      expect(d.evidence.join(" ")).toMatch(/automation entitlement/);
    });

    it("-1743 with the target not running is a likely permission with that noted", () => {
      const d = diagnoseMac(
        facts({
          op: "exec",
          automation_target: "Messages",
          automation_status: "target_not_running",
          stderr_hint: "apple_event_not_permitted",
        }),
      );
      expect(d.cause).toBe("macos_permission");
      expect(d.confidence).toBe("likely");
      expect(d.evidence.join(" ")).toMatch(/not running/);
    });

    it("a hang with consent never asked is the consent dialog, confirmed", () => {
      const d = diagnoseMac(facts({ op: "exec", hung: true, automation_target: "Messages", automation_status: "not_asked" }));
      expect(d.cause).toBe("prompt_waiting");
      expect(d.confidence).toBe("confirmed");
      expect(d.permission).toBe("automation");
    });
  });
});

// POSIX fixture paths (/Users/probe, /opt, /x) resolved through the
// platform path module: these pin the macOS battery and run darwin-only.
// Windows coverage of the same battery lives in the "Windows gates"
// block below, against real temp paths.
describe.skipIf(process.platform !== "darwin")("collectFacts — the battery over scripted probes", () => {
  it("examines every candidate and settles on the one the app is refused", async () => {
    const probes = scriptedProbes({
      openAsApp: { [`${HOME}/Library/Messages/chat.db`]: "EPERM" },
      fullDiskAccess: false,
    });
    const f = await collectFacts(
      {
        op: "exec",
        paths: ["/opt/scratch", `${HOME}/Library/Messages/chat.db`],
        stderr: "Error: unable to open database \"~/Library/Messages/chat.db\": Operation not permitted",
        ranSandboxed: true,
        sandbox: () => ({ read: true, write: false }),
      },
      probes,
      HOME,
    );
    expect(f.path).toBe("~/Library/Messages/chat.db");
    // What the failure named comes first, what was merely declared last.
    expect(f.paths_examined).toEqual(["~/Library/Messages/chat.db", "/opt/scratch"]);
    expect(f.errno).toBe("EPERM");
    expect(f.stderr_hint).toBe("operation_not_permitted");
    expect(f.app_process_open).toBe("EPERM");
    expect(f.tcc_guarded_prefix).toBe("full_disk_access");
    expect(f.full_disk_access_granted).toBe(false);
    expect(f.sandbox_allows_write).toBe(false);
    // Every candidate was probed, not just the first — and the ~ form was
    // expanded so it did not count as a third path.
    expect(probes.calls.filter((c) => c.startsWith("openAsApp"))).toHaveLength(2);
    expect(probes.calls).toContain("fullDiskAccess");
    expect(diagnose(f).cause).toBe("macos_permission");
  });

  it("keeps a named path whole and mines argv text for more", async () => {
    const spaced = `${HOME}/Documents/My Report/draft.txt`;
    const probes = scriptedProbes({ openAsApp: { [spaced]: "EPERM" } });
    const f = await collectFacts(
      { op: "exec", paths: [spaced], texts: ["cat /opt/other.txt"], ranSandboxed: true },
      probes,
      HOME,
    );
    expect(f.paths_examined).toEqual(["/opt/other.txt", "~/Documents/My Report/draft.txt"]);
    expect(f.path).toBe("~/Documents/My Report/draft.txt");
  });

  it("a locked file a shell reported is diagnosed on the file, not on the shell", async () => {
    // `/bin/sh: ~/Plow/x: Operation not permitted`. The shell is under a SIP
    // root and no profile lets a run write it, which once made it the path
    // of interest — and the verdict "sealed by SIP" — for a write the locked
    // flag refused. The file the failure named carries the flag; that is
    // the story.
    const locked = `${HOME}/Plow/locked.txt`;
    const probes = scriptedProbes({
      inspect: { [locked]: { isDirectory: false, readable: true, writable: true, flags: ["uchg"] } },
    });
    const f = await collectFacts(
      {
        op: "exec",
        paths: [locked],
        texts: [`/bin/sh -c "printf new > ${locked}"`],
        stderr: `/bin/sh: ${locked}: Operation not permitted`,
        ranSandboxed: true,
        sandbox: (p) => ({ read: true, write: p === locked }),
      },
      probes,
      HOME,
    );
    expect(f.path).toBe("~/Plow/locked.txt");
    expect(f.immutable_flag).toBe(true);
    expect(f.sip_protected).toBe(false);
    expect(diagnose(f).cause).toBe("immutable_file");
  });

  it("names the app an AppleScript addresses", () => {
    expect(appleEventTarget(["osascript", "-e", 'tell application "Messages" to send "x" to buddy "y"'])).toBe("Messages");
    expect(appleEventTarget(["osascript", "-e", 'tell app "Contacts"', "-e", 'tell application "Mail"'])).toBe("Contacts");
    expect(appleEventTarget(["ls"])).toBeNull();
  });

  it("reads the path out of a Node error when the caller named none", async () => {
    const probes = scriptedProbes({ inspect: { "/x/y": null }, openAsApp: { "/x/y": "ENOENT" } });
    const f = await collectFacts(
      { op: "read", paths: [], error: { code: "ENOENT", syscall: "open", path: "/x/y" }, ranSandboxed: false },
      probes,
      HOME,
    );
    expect(f.path).toBe("/x/y");
    expect(f.path_exists).toBe(false);
    expect(f.syscall).toBe("open");
    expect(diagnose(f).cause).toBe("not_found");
  });

  it("asks about Automation only when a target was declared", async () => {
    const probes = scriptedProbes({ automation: { Messages: "denied" } });
    const without = await collectFacts({ op: "exec", paths: [], ranSandboxed: true }, probes, HOME);
    expect(without.automation_status).toBeNull();
    const withTarget = await collectFacts(
      { op: "exec", paths: [], ranSandboxed: true, automationTarget: "Messages" },
      probes,
      HOME,
    );
    expect(withTarget.automation_status).toBe("denied");
    expect(probes.calls.filter((c) => c.startsWith("automationStatus"))).toHaveLength(1);
  });

  it("judges a missing write target by its parent: a folder the app is refused", async () => {
    const target = `${HOME}/Documents/new.txt`;
    const probes = scriptedProbes({
      inspect: { [target]: null },
      openAsApp: { [`${HOME}/Documents`]: "EPERM" },
      fullDiskAccess: false,
    });
    const f = await collectFacts(
      { op: "write", paths: [target], error: { code: "EPERM", syscall: "open", path: target }, ranSandboxed: false },
      probes,
      HOME,
    );
    expect(f.path_exists).toBe(false);
    expect(f.app_process_open).toBe("EPERM");
    expect(probes.calls).toContain(`openAsApp ${HOME}/Documents`);
    const d = diagnoseMac(f);
    expect(d.cause).toBe("macos_permission");
    expect(d.permission).toBe("files_documents");
    expect(d.evidence.join(" ")).toMatch(/refusal is on creating it/);
  });

  it("judges a write target outside the approval as the bound, without touching it", async () => {
    // The path is the command's own word (argv and its output); nothing the
    // owner approved contains it. It is classified by name — the profile
    // allows it nothing — and never stat'd or opened: those are this
    // process's hands, outside any seatbelt, on a path nobody approved.
    const target = "/opt/elsewhere/new.txt";
    const probes = scriptedProbes({ inspect: { [target]: null } });
    const f = await collectFacts(
      {
        op: "exec",
        paths: [],
        argv: ["sh", "-c", "echo hi > /opt/elsewhere/new.txt"],
        stderr: "sh: /opt/elsewhere/new.txt: Operation not permitted",
        ranSandboxed: true,
        sandbox: () => ({ read: false, write: false }),
      },
      probes,
      HOME,
    );
    expect(f.path).toBe(target);
    expect(f.path_approved).toBe(false);
    expect(f.app_process_open).toBeNull();
    expect(f.path_exists).toBeNull();
    expect(probes.calls.filter((c) => c.startsWith("inspect") || c.startsWith("openAsApp"))).toEqual([]);
    const d = diagnoseMac(f);
    expect(d.cause).toBe("outside_approved_bound");
    expect(d.confidence).toBe("confirmed");
  });

  it("a command's output cannot make this Mac open a path the owner never approved", async () => {
    // Forged: the run was approved to read ~/Plow, and prints a refusal for a
    // file under ~/Desktop it never touched. No inspect, no open — a
    // folder gate there would raise the owner's consent dialog for
    // something they never approved, and answer whether the file exists.
    const secret = `${HOME}/Desktop/secret.txt`;
    const probes = scriptedProbes({ openAsApp: { [secret]: "hung" } });
    const f = await collectFacts(
      {
        op: "exec",
        paths: [`${HOME}/Plow`],
        argv: ["/bin/sh", "-c", `echo "cat: ${secret}: Operation not permitted" >&2; exit 1`],
        stderr: `cat: ${secret}: Operation not permitted`,
        ranSandboxed: true,
        sandbox: (p) => ({ read: p.startsWith(`${HOME}/Plow`), write: false }),
      },
      probes,
      HOME,
    );
    expect(probes.calls.filter((c) => c.includes("Desktop"))).toEqual([]);
    expect(f.path).toBe("~/Desktop/secret.txt");
    expect(f.path_approved).toBe(false);
    expect(f.paths_examined).toContain("~/Desktop/secret.txt");
    expect(diagnose(f).cause).toBe("outside_approved_bound");
  });

  it("an approved path a live run could rewrite is classified, never opened", async () => {
    // Approved to write ~/Plow/w; the run is still going. Between deciding
    // ~/Plow/w/a/x is approved and opening it, the run can make `a` a link
    // to ~/Desktop — so nothing under a root it can write is opened by
    // name while it lives. The location still speaks: guarded, so likely.
    const w = `${HOME}/Plow/w`;
    const target = `${HOME}/Documents/report.txt`;
    const probes = scriptedProbes({ openAsApp: { [`${w}/a/x`]: "EPERM", [target]: "ok" }, fullDiskAccess: false });
    const f = await collectFacts(
      {
        op: "exec",
        paths: [w, target],
        argv: ["/bin/cat", `${w}/a/x`],
        stderr: `cat: ${w}/a/x: Operation not permitted`,
        ranSandboxed: true,
        sandbox: () => ({ read: true, write: true }),
        mutable: () => [w],
      },
      probes,
      HOME,
    );
    expect(probes.calls.filter((c) => c.includes("/Plow/w"))).toEqual([]);
    expect(f.path).toBe("~/Plow/w/a/x");
    expect(f.path_approved).toBe(true);
    expect(f.probe_withheld).toBe(true);
    expect(f.app_process_open).toBeNull();
    // A declared path outside every rewritable root is still probed.
    expect(probes.calls).toContain(`openAsApp ${target}`);
    // Under a guarded location, the withheld probe leaves a likely verdict.
    const guarded = await collectFacts(
      { op: "exec", paths: [`${HOME}/Documents/out`], argv: ["/bin/sh", "-c", `echo x > ${HOME}/Documents/out`], stderr: `sh: ${HOME}/Documents/out: Operation not permitted`, ranSandboxed: true, sandbox: () => ({ read: true, write: true }), mutable: () => [`${HOME}/Documents/out`] },
      scriptedProbes({ fullDiskAccess: false }),
      HOME,
    );
    const d = diagnoseMac(guarded);
    expect(d.cause).toBe("macos_permission");
    expect(d.confidence).toBe("likely");
    expect(d.permission).toBe("files_documents");
  });

  it("an argv word that is a path is one candidate, spaces and all", async () => {
    const spaced = `${HOME}/Plow/My Report.txt`;
    const probes = scriptedProbes({ openAsApp: { [spaced]: "EPERM" } });
    const f = await collectFacts(
      { op: "exec", paths: [`${HOME}/Plow`], argv: ["/bin/cat", spaced], ranSandboxed: true, sandbox: () => ({ read: true, write: true }) },
      probes,
      HOME,
    );
    expect(f.paths_examined).toContain("~/Plow/My Report.txt");
    expect(f.paths_examined).not.toContain("~/Plow/My");
    expect(f.path).toBe("~/Plow/My Report.txt");
  });

  it("a missing path with no errno at all is simply missing", async () => {
    const f = await collectFacts(
      { op: "read", paths: ["/opt/nothing/here"], ranSandboxed: false },
      scriptedProbes({ inspect: { "/opt/nothing/here": null } }),
      HOME,
    );
    expect(diagnose(f).cause).toBe("not_found");
  });

  it("prefers a guarded path over an unguarded one when neither was refused", async () => {
    const f = await collectFacts(
      { op: "exec", paths: ["/opt/a", `${HOME}/Downloads/b`], ranSandboxed: true, hung: true },
      scriptedProbes(),
      HOME,
    );
    expect(f.path).toBe("~/Downloads/b");
    expect(f.hung).toBe(true);
    expect(diagnose(f).cause).toBe("prompt_waiting");
  });
});

describe.skipIf(process.platform !== "darwin")("sandboxGrants — the profile's decision, asked after the fact", () => {
  // The seatbelt profile is macOS-only: these pin its over-approximation
  // (broad home, boilerplate roots, housekeeping) over macOS paths.
  // Windows answers the approval instead of a cage — pinned below.
  // Canonical, like every path the generator sees: a temp dir under /var is
  // really under /private/var, and the profile is written in physical paths.
  const home = canonicalize(tempDir());
  const scratch = path.join(home, "scratch");
  const base = { readPaths: [] as string[], writePaths: [] as string[], network: false, appleEvents: false, scratch, home };

  it("grants reads broadly under home and the boilerplate roots, writes only where approved", () => {
    const out = path.join(home, "Plow/out.txt");
    expect(grantsMac(base, out)).toEqual({ read: true, write: false });
    expect(grantsMac({ ...base, writePaths: [path.join(home, "Plow")] }, out)).toEqual({ read: true, write: true });
    expect(grantsMac(base, "/usr/bin/ls")).toEqual({ read: true, write: false });
    expect(grantsMac(base, "/private/var/db/x")).toEqual({ read: true, write: false });
    expect(grantsMac(base, "/Users/Shared/x")).toEqual({ read: false, write: false });
    expect(grantsMac(base, "/Users")).toEqual({ read: true, write: false });
    expect(grantsMac(base, path.join(scratch, "tmp.txt"))).toEqual({ read: true, write: true });
  });

  it("gives housekeeping writes only to a run the reaper cannot kill", () => {
    const cache = path.join(home, ".cache/x");
    expect(grantsMac(base, cache).write).toBe(false);
    expect(grantsMac({ ...base, network: true }, cache).write).toBe(true);
    expect(grantsMac({ ...base, appleEvents: true }, cache).write).toBe(true);
  });

  it("reads outside home need a declared read path", () => {
    const outside = canonicalize(tempDir());
    expect(grantsMac(base, path.join(outside, "x")).read).toBe(false);
    expect(grantsMac({ ...base, readPaths: [outside] }, path.join(outside, "x")).read).toBe(true);
  });
});

describe("sandboxGrants on Windows — the approval, not a cage", () => {
  // No Job Object confines files, so these answer what the owner approved:
  // reads are the broad home grant plus declared roots, writes are the
  // writable roots. Pinned explicitly to win32 so they run on any host.
  const win = (args: Parameters<typeof sandboxGrants>[0], target: string) =>
    sandboxGrants(args, target, { platform: "win32" });
  const home = "C:\\Users\\x";
  const scratch = `${home}\\scratch`;
  const base = { readPaths: [] as string[], writePaths: [] as string[], network: false, appleEvents: false, scratch, home };

  it("reads home broadly and case-insensitively, writes only where approved", () => {
    const out = `${home}\\Plow\\out.txt`;
    expect(win(base, out)).toEqual({ read: true, write: false });
    expect(win({ ...base, writePaths: [`${home}\\Plow`] }, out)).toEqual({ read: true, write: true });
    expect(win(base, `${home}\\PLOW\\OUT.TXT`)).toEqual({ read: true, write: false });
    expect(win(base, "C:\\Windows\\System32\\x")).toEqual({ read: false, write: false });
    expect(win(base, `${scratch}\\tmp.txt`)).toEqual({ read: true, write: true });
  });

  it("reads outside home need a declared read path", () => {
    const outside = "D:\\data\\x";
    expect(win(base, outside).read).toBe(false);
    expect(win({ ...base, readPaths: ["D:\\data"] }, outside).read).toBe(true);
  });
});

describe("nodeProbes — the real answers, against fixtures", () => {
  it("opens a readable file and lists a readable directory as ok", async () => {
    const dir = tempDir();
    const file = path.join(dir, "a.txt");
    fs.writeFileSync(file, "x");
    const probes = nodeProbes({ fullDiskPaths: [file] });
    expect(await probes.openAsApp(file)).toBe("ok");
    expect(await probes.openAsApp(dir)).toBe("ok");
    expect(await probes.fullDiskAccess()).toBe(true);
    const info = await probes.inspect(file);
    expect(info).toMatchObject({ isDirectory: false, readable: true, writable: true, flags: [] });
    expect((await probes.inspect(dir))?.isDirectory).toBe(true);
  });

  it("reports a missing path as ENOENT from both probes", async () => {
    const probes = nodeProbes({ fullDiskPaths: ["/nonexistent/x"] });
    expect(await probes.inspect("/nonexistent/x")).toBeNull();
    expect(await probes.openAsApp("/nonexistent/x")).toBe("ENOENT");
    expect(await probes.fullDiskAccess()).toBe(false);
  });

  // Root reads a 0o000 file regardless; Windows ACLs do not express Unix
  // mode bits at all, so there is nothing to assert there.
  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)("reads a chmod 000 file as EACCES, with the mode bits saying so", async () => {
    const dir = tempDir();
    const file = path.join(dir, "locked.txt");
    fs.writeFileSync(file, "x");
    fs.chmodSync(file, 0o000);
    cleanups.push(() => fs.chmodSync(file, 0o600));
    const probes = nodeProbes();
    expect(await probes.openAsApp(file)).toBe("EACCES");
    expect((await probes.inspect(file))?.readable).toBe(false);
  });

  // mkfifo(1) and a parked FIFO open are POSIX: on Windows the probe
  // reads in-process and a hang is not a state it can report.
  it.skipIf(process.platform === "win32")("answers 'hung' for an open that never returns, and kills the child", async () => {
    const dir = tempDir();
    const fifo = path.join(dir, "blocked.pipe");
    execFileSync("/usr/bin/mkfifo", [fifo]);
    const probes = nodeProbes({ timeoutMs: 300 });
    const started = Date.now();
    expect(await probes.openAsApp(fifo)).toBe("hung");
    expect(Date.now() - started).toBeGreaterThanOrEqual(250);
    // The reader died with the timer: a writer that shows up now finds no one
    // waiting and would block, so the check is that the directory is
    // removable — a live reader would have kept the FIFO's inode busy on
    // some filesystems. The cleanup above is that check.
  });

  it("answers unknown for Automation and the queryable services without the helper", async () => {
    // A fixture home, never the real one: a request touches the store.
    const probes = nodeProbes({ ownerHome: tempDir() });
    expect(await probes.automationStatus("Messages")).toBe("unknown");
    expect(await probes.permissionStatus("contacts")).toBe("unknown");
    expect(await probes.requestPermission("accessibility")).toBe("unknown");
    expect(await probes.requestPermission("contacts")).toBe("unknown");
  });

  it("asks for Contacts and Calendars in process, through the addon the app hands in", async () => {
    const calls: string[] = [];
    const native = {
      contactsStatus: () => "not_asked",
      calendarsStatus: () => {
        throw new Error("framework unavailable");
      },
      requestContacts: async () => {
        calls.push("requestContacts");
        return "granted";
      },
      requestCalendars: async () => {
        calls.push("requestCalendars");
        return "nonsense";
      },
    };
    const probes = nodeProbes({ ownerHome: tempDir(), native });
    expect(probes.canRequestInProcess()).toBe(true);
    expect(await probes.permissionStatus("contacts")).toBe("not_asked");
    // A throwing addon is an unknown, never a crash.
    expect(await probes.permissionStatus("calendars")).toBe("unknown");
    expect(await probes.requestPermission("contacts")).toBe("granted");
    expect(await probes.requestPermission("calendars")).toBe("unknown");
    expect(calls).toEqual(["requestContacts", "requestCalendars"]);
    // Without the addon there is no way to ask, and the probes say so.
    expect(nodeProbes({ ownerHome: tempDir() }).canRequestInProcess()).toBe(false);
  });

  it.skipIf(process.platform === "win32")("reads the helper's answer, and the request mode's, off its one JSON line", async () => {
    // A stand-in helper: a shell script that answers by flag, so the parsing
    // and flag spelling are checked without the Swift toolchain.
    const dir = tempDir();
    const helper = path.join(dir, "helper.sh");
    fs.writeFileSync(
      helper,
      '#!/bin/sh\ncase "$1 $2" in\n"--contacts ") echo \'{"status":"not_asked"}\';;\n"--calendars ") echo \'{"status":"granted"}\';;\n"--screen-recording ") echo \'{"status":"denied"}\';;\n"--request accessibility") echo \'{"status":"granted"}\';;\n"--automation Messages") echo \'{"status":"target_not_running"}\';;\n*) echo nonsense;;\nesac\n',
    );
    fs.chmodSync(helper, 0o755);
    const probes = nodeProbes({ helperPath: helper, ownerHome: dir });
    expect(await probes.requestPermission("accessibility")).toBe("granted");
    expect(await probes.permissionStatus("contacts")).toBe("not_asked");
    expect(await probes.permissionStatus("calendars")).toBe("granted");
    expect(await probes.permissionStatus("screen_recording")).toBe("denied");
    expect(await probes.automationStatus("Messages")).toBe("target_not_running");
    // An unparseable answer is unknown, never a guess.
    expect(await probes.permissionStatus("accessibility")).toBe("unknown");
  });

  it.skipIf(process.platform !== "darwin" || process.getuid?.() === 0)(
    "sees the locked flag on a chflags uchg file",
    async () => {
      const dir = tempDir();
      const file = path.join(dir, "locked.txt");
      fs.writeFileSync(file, "x");
      execFileSync("/usr/bin/chflags", ["uchg", file]);
      cleanups.push(() => execFileSync("/usr/bin/chflags", ["nouchg", file]));
      expect((await nodeProbes().inspect(file))?.flags).toContain("uchg");
    },
  );
});

describe("Windows gates — the CFA/ACL/system table and its verdicts", () => {
  // These pin the win32 platform explicitly, so they run on any host —
  // including macOS and Linux CI. The collectFacts battery itself stays
  // darwin-gated above (POSIX fixture paths); here it is exercised once
  // against real temp paths with scripted probes.
  const win = (overrides: Partial<HostFacts> = {}) => diagnose(facts(overrides), { platform: "win32" });

  it("maps user folders to their switches, OneDrive included, case-insensitively", () => {
    const profile = "C:\\Users\\x";
    expect(windowsGuardedPrefix(`${profile}\\Desktop\\a.txt`, profile)).toBe("files_desktop");
    expect(windowsGuardedPrefix(`${profile}\\Documents\\a.txt`, profile)).toBe("files_documents");
    expect(windowsGuardedPrefix(`${profile}\\Downloads\\a.txt`, profile)).toBe("files_downloads");
    expect(windowsGuardedPrefix(`${profile}\\OneDrive\\Desktop\\a.txt`, profile)).toBe("files_desktop");
    expect(windowsGuardedPrefix(`${profile}\\OneDrive\\Documents\\a.txt`, profile)).toBe("files_documents");
    expect(windowsGuardedPrefix(`${profile}\\DESKTOP\\a.txt`, profile)).toBe("files_desktop");
    expect(windowsGuardedPrefix(`${profile}\\Pictures\\a.txt`, profile)).toBeNull();
    expect(windowsGuardedPrefix("C:\\Windows\\x", profile)).toBeNull();
    expect(windowsGuardedPrefix(`${profile}\\Desktop`, "")).toBeNull();
  });

  it("seals the system locations against every process", () => {
    expect(windowsSystemProtected("C:\\Windows\\System32\\x")).toBe(true);
    expect(windowsSystemProtected("C:\\Program Files\\App\\x")).toBe(true);
    expect(windowsSystemProtected("C:\\Program Files (x86)\\App\\x")).toBe(true);
    expect(windowsSystemProtected("C:\\Users\\x\\Documents\\a.txt")).toBe(false);
  });

  it("confirms an os_permission refusal with the Controlled Folder Access sentence", () => {
    const d = win({
      errno: "EPERM",
      path: "C:\\Users\\x\\Documents\\a.txt",
      path_exists: true,
      app_process_open: "EPERM",
      tcc_guarded_prefix: "files_documents",
      full_disk_access_granted: false,
    });
    expect(d.cause).toBe("os_permission");
    expect(d.confidence).toBe("confirmed");
    expect(d.permission).toBe("files_documents");
    expect(d.retry).toBe("after_owner_grants");
    expect(d.owner_action).toMatch(/Controlled folder access/);
    expect(isHostGate(d.cause)).toBe(true);
  });

  it("names an unguarded Windows EPERM as an ACL, not Controlled Folder Access", () => {
    // Node maps ERROR_ACCESS_DENIED to EPERM. Off the CFA folders that is
    // an ACL, not a Windows Security switch — the icacls sentence, never
    // "allow the app through ransomware protection".
    const d = win({ errno: "EPERM", path_exists: true, app_process_open: "EPERM", tcc_guarded_prefix: null });
    expect(d.cause).toBe("posix_permissions");
    expect(d.owner_action).toMatch(/icacls/);
    expect(d.owner_action).not.toMatch(/Controlled folder access/);
  });

  it("reads a withheld Windows path as a likely os_permission", () => {
    const d = win({ errno: "EPERM", probe_withheld: true, tcc_guarded_prefix: "files_desktop" });
    expect(d.cause).toBe("os_permission");
    expect(d.confidence).toBe("likely");
  });

  it("words POSIX and system-location verdicts for Windows", () => {
    const perms = win({ errno: "EACCES", posix_readable: false, app_process_open: "EACCES" });
    expect(perms.cause).toBe("posix_permissions");
    expect(perms.owner_action).toMatch(/icacls/);
    // Node reports ACL deny as EPERM. Same sentence as chmod 000, not CFA.
    const acl = win({ errno: "EPERM", posix_readable: false, app_process_open: "EPERM" });
    expect(acl.cause).toBe("posix_permissions");
    expect(acl.owner_action).toMatch(/icacls/);
    const sys = win({ errno: "EPERM", sip_protected: true, app_process_open: "EPERM" });
    expect(sys.cause).toBe("sip_protected");
    expect(sys.owner_action).toMatch(/elevated/);
  });

  // A Job Object is a process cage, not a file cage: the bound verdicts must
  // name the approval, never a sandbox profile that does not exist — while
  // the seatbelt wording above stays untouched.
  it("names the approval bound under a Job Object, never a sandbox profile", () => {
    const d = win({
      op: "exec",
      errno: "EPERM",
      path: "C:\\Users\\x\\Documents\\a.txt",
      path_exists: true,
      ran_sandboxed: true,
      sandbox_kind: "job",
      app_process_open: "ok",
      sandbox_allows_read: true,
      sandbox_allows_write: false,
      path_approved: false,
    });
    expect(d.cause).toBe("outside_approved_bound");
    expect(d.confidence).toBe("confirmed");
    expect(d.retry).toBe("with_declared_path");
    const text = d.evidence.join("\n");
    expect(text).toMatch(/not among the paths approved for this run/);
    expect(text).not.toMatch(/sandbox profile/);
  });

  it("words a grants refusal as the approval under a Job Object", () => {
    const d = win({
      op: "exec",
      errno: "EPERM",
      path_exists: true,
      ran_sandboxed: true,
      sandbox_kind: "job",
      app_process_open: "ok",
      sandbox_allows_read: true,
      sandbox_allows_write: false,
    });
    expect(d.cause).toBe("outside_approved_bound");
    const text = d.evidence.join("\n");
    expect(text).toMatch(/the approval for this run allows no writes/);
    expect(text).not.toMatch(/sandbox profile/);
  });

  it("maps platform and cage to the kind, and carries it in the payload", () => {
    expect(sandboxKindFor("win32", true)).toBe("job");
    expect(sandboxKindFor("darwin", true)).toBe("seatbelt");
    expect(sandboxKindFor("darwin", false)).toBe("none");
    expect(sandboxKindFor("linux", true)).toBe("bwrap");
    expect(sandboxKindFor("linux", false)).toBe("none");
    // The kind rides beside ran_sandboxed into the tool result and the
    // audit line, so neither reader can mistake a Job for file confinement.
    const f = facts({ ran_sandboxed: true, sandbox_kind: "job" });
    const payload = diagnosisPayload(diagnose(f, { platform: "win32" }), f);
    expect((payload.probes as { sandbox_kind: unknown }).sandbox_kind).toBe("job");
  });

  it("reports missing guarded folders as ENOENT, never as refusals", async () => {
    const profile = path.join(tempDir(), "profile");
    const results = await probeWindowsFolderAccess(profile);
    expect(results).toHaveLength(6);
    expect(results.every((r) => r.outcome === "ENOENT")).toBe(true);
  });

  it.skipIf(process.platform !== "win32")("runs the battery on Windows paths without touching the disk it was not given", async () => {
    // TEMP is often 8.3 on GHA (`RUNNER~1`). Canonicalize so the scripted
    // probe key matches the path collectFacts actually opens.
    const dir = canonicalize(tempDir());
    const file = canonicalize(path.join(dir, "a.txt"));
    fs.writeFileSync(file, "x");
    const probes = scriptedProbes({ openAsApp: { [file]: "EPERM" } });
    const f = await collectFacts({ op: "read", paths: [file], ranSandboxed: false }, probes, dir);
    expect(f.app_process_open).toBe("EPERM");
    expect(f.tcc_guarded_prefix).toBeNull();
    // Off the CFA folders, in-process EPERM is an ACL (posix_permissions),
    // not "unknown" and not Controlled Folder Access.
    expect(diagnose(f, { platform: "win32" }).cause).toBe("posix_permissions");
  });
});

describe("Linux gates — bwrap kind and approval wording", () => {
  it("names the approval bound under bwrap, never a seatbelt profile", () => {
    const d = diagnose(
      facts({
        op: "exec",
        errno: "EPERM",
        path: "/home/x/Documents/a.txt",
        path_exists: true,
        ran_sandboxed: true,
        sandbox_kind: "bwrap",
        app_process_open: "ok",
        sandbox_allows_read: true,
        sandbox_allows_write: false,
        path_approved: false,
      }),
      { platform: "linux" },
    );
    expect(d.cause).toBe("outside_approved_bound");
    const text = d.evidence.join("\n");
    expect(text).toMatch(/not among the paths approved for this run/);
    expect(text).not.toMatch(/sandbox profile/);
  });

  it("maps XDG user folders and system roots on Linux", () => {
    const home = "/home/owner";
    expect(linuxGuardedPrefix(`${home}/Desktop/a.txt`, home)).toBe("files_desktop");
    expect(linuxGuardedPrefix(`${home}/Documents/a.txt`, home)).toBe("files_documents");
    expect(linuxGuardedPrefix(`${home}/Downloads/a.txt`, home)).toBe("files_downloads");
    expect(linuxGuardedPrefix(`${home}/Pictures/a.txt`, home)).toBeNull();
    expect(linuxSystemProtected("/etc/passwd")).toBe(true);
    expect(linuxSystemProtected("/usr/bin/true")).toBe(true);
    expect(linuxSystemProtected(`${home}/file.txt`)).toBe(false);
  });

  it("owner sentences name Linux fixes, never Windows CFA or macOS SIP", () => {
    const d = diagnose(
      facts({
        op: "write",
        errno: "EPERM",
        path: "/etc/hosts",
        path_exists: true,
        sip_protected: true,
        app_process_open: "EPERM",
      }),
      { platform: "linux" },
    );
    expect(d.cause).toBe("sip_protected");
    expect(d.owner_action).toMatch(/Linux system locations/);
    expect(d.owner_action).not.toMatch(/Controlled folder access|System Integrity Protection/);
  });
});
