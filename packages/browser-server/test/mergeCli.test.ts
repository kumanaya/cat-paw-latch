/**
 * The cookie merger, run as the executable BrowserHost spawns — including from a
 * path with a SPACE in it, which the shipping "Plow Latch.app" always has.
 *
 * The bug this guards: `import.meta.url === \`file://${argv[1]}\`` percent-encodes
 * the space on one side only, so the CLI block never ran, the process exited 0
 * having merged nothing, and the caller deleted the session clone on that false
 * success — losing every login made in the session. `isMain()` now compares
 * resolved filesystem paths, so a spaced path merges like any other.
 *
 * Runs against the built dist (compiled here if stale), because the merge is a
 * real subprocess (the WASM sqlite merge is synchronous).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import sqlite3 from "node-sqlite3-wasm";
const { Database } = sqlite3;
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));
const MERGE_JS = fileURLToPath(new URL("../dist/mergeCookies.js", import.meta.url));

const COLS =
  "CREATE TABLE IF NOT EXISTS moz_cookies (id INTEGER PRIMARY KEY, name TEXT, value TEXT," +
  " host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER," +
  " isHttpOnly INTEGER, inBrowserElement INTEGER, sameSite INTEGER, rawSameSite INTEGER, schemeMap INTEGER," +
  " originAttributes TEXT, CONSTRAINT moz_uniqueid UNIQUE (name, host, path, originAttributes))";

function store(file: string, hosts: string[], usedAt = 1): void {
  const db = new Database(file);
  db.exec(COLS);
  const ins = db.prepare(
    "INSERT OR REPLACE INTO moz_cookies (name,value,host,path,expiry,lastAccessed,creationTime," +
      "isSecure,isHttpOnly,inBrowserElement,sameSite,rawSameSite,schemeMap,originAttributes)" +
      " VALUES ('sid','v',?,'/',0,?,1,1,1,0,0,0,1,'')",
  );
  hosts.forEach((h, i) => ins.run([h, usedAt + i]));
  db.close();
}

function hosts(file: string): string[] {
  const db = new Database(file, { readOnly: true });
  const rows = db.prepare("SELECT host FROM moz_cookies ORDER BY host").all() as { host: string }[];
  db.close();
  return rows.map((r) => r.host);
}

let dir: string;

/** Whether this machine can make a file symlink (needs a privilege Windows
 *  does not grant by default). */
function canSymlink(): boolean {
  try {
    const probe = fs.mkdtempSync(path.join(os.tmpdir(), "merge-link-probe-"));
    try {
      const target = path.join(probe, "t");
      fs.writeFileSync(target, "x");
      const link = path.join(probe, "l");
      fs.symlinkSync(target, link);
      fs.unlinkSync(link);
      return true;
    } finally {
      fs.rmSync(probe, { recursive: true, force: true });
    }
  } catch {
    return false;
  }
}

beforeAll(() => {
  if (!fs.existsSync(MERGE_JS)) {
    execFileSync("npx", ["tsc", "-b", "packages/browser-server"], { cwd: repoRoot });
  }
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "merge-cli-"));
});
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

/** Run the merger the way BrowserHost does: node <script> into extra baseline. */
function runMerge(script: string, into: string, extra: string, baseline: string): void {
  execFileSync(process.execPath, [script, into, extra, baseline], { stdio: "pipe" });
}

describe("the cookie merger as a spawned executable", () => {
  it("merges a new sign-in from the session clone into the user's profile", () => {
    const into = path.join(dir, "into.sqlite");
    const extra = path.join(dir, "extra.sqlite");
    const baseline = path.join(dir, "base.sqlite");
    store(into, ["a.example"]);
    store(baseline, ["a.example"]);
    store(extra, ["a.example", "b.example"], 50); // b.example signed in this session
    runMerge(MERGE_JS, into, extra, baseline);
    expect(hosts(into)).toEqual(["a.example", "b.example"]);
  });

  // A file symlink needs a privilege Windows does not grant by default;
  // where none exists this spaced-path case cannot be built.
  it.skipIf(process.platform === "win32" && !canSymlink())("STILL merges when the script path contains a space (the Plow Latch.app case)", () => {
    // A directory with a space, and the merger reached through it. The old string
    // comparison made isMain() false here, so the merge silently did nothing.
    const spaced = path.join(dir, "Plow Latch");
    fs.mkdirSync(spaced, { recursive: true });
    const link = path.join(spaced, "merge cookies.js");
    fs.symlinkSync(MERGE_JS, link);

    const into = path.join(dir, "into2.sqlite");
    const extra = path.join(dir, "extra2.sqlite");
    const baseline = path.join(dir, "base2.sqlite");
    store(into, ["a.example"]);
    store(baseline, ["a.example"]);
    store(extra, ["a.example", "b.example"], 50);

    runMerge(link, into, extra, baseline);
    // The merge ran: b.example is now in the profile. Under the old bug the
    // subprocess exited 0 and into still held only a.example.
    expect(hosts(into)).toEqual(["a.example", "b.example"]);
  });

  // The branches the ATTACH-free rewrite must preserve exactly: sign-outs
  // delete only what the baseline still holds, a newer profile row wins over
  // the session's older one, and an untouched session changes nothing. These
  // run on every host — they are the cross-platform spec of the merge.
  function storeRows(file: string, rows: { host: string; value: string; lastAccessed: number }[]): void {
    const db = new Database(file);
    db.exec(COLS);
    const ins = db.prepare(
      "INSERT OR REPLACE INTO moz_cookies (name,value,host,path,expiry,lastAccessed,creationTime," +
        "isSecure,isHttpOnly,inBrowserElement,sameSite,rawSameSite,schemeMap,originAttributes)" +
        " VALUES ('sid',?,?,'/',0,?,1,1,1,0,0,0,1,'')",
    );
    for (const r of rows) ins.run([r.value, r.host, r.lastAccessed]);
    db.close();
  }

  function values(file: string): { host: string; value: string; lastAccessed: number }[] {
    const db = new Database(file, { readOnly: true });
    const rows = db.prepare("SELECT host, value, lastAccessed FROM moz_cookies ORDER BY host").all() as {
      host: string;
      value: string;
      lastAccessed: number;
    }[];
    db.close();
    return rows;
  }

  it("drops a sign-out the baseline still holds, and keeps the value it merges", () => {
    const into = path.join(dir, "so-into.sqlite");
    const extra = path.join(dir, "so-extra.sqlite");
    const baseline = path.join(dir, "so-base.sqlite");
    const start = [
      { host: "a.example", value: "v1", lastAccessed: 10 },
      { host: "b.example", value: "v2", lastAccessed: 10 },
    ];
    storeRows(into, start);
    storeRows(baseline, start);
    storeRows(extra, [{ host: "a.example", value: "v1", lastAccessed: 10 }]);
    runMerge(MERGE_JS, into, extra, baseline);
    expect(values(into)).toEqual([{ host: "a.example", value: "v1", lastAccessed: 10 }]);
  });

  it("keeps the profile's newer cookie over the session's older one", () => {
    const into = path.join(dir, "nw-into.sqlite");
    const extra = path.join(dir, "nw-extra.sqlite");
    const baseline = path.join(dir, "nw-base.sqlite");
    storeRows(into, [{ host: "b.example", value: "v-new", lastAccessed: 100 }]);
    storeRows(baseline, [{ host: "b.example", value: "v-old", lastAccessed: 1 }]);
    storeRows(extra, [{ host: "b.example", value: "v-old", lastAccessed: 1 }]);
    runMerge(MERGE_JS, into, extra, baseline);
    expect(values(into)).toEqual([{ host: "b.example", value: "v-new", lastAccessed: 100 }]);
  });

  it("leaves an untouched session alone", () => {
    const into = path.join(dir, "un-into.sqlite");
    const extra = path.join(dir, "un-extra.sqlite");
    const baseline = path.join(dir, "un-base.sqlite");
    const rows = [
      { host: "a.example", value: "v1", lastAccessed: 10 },
      { host: "b.example", value: "v2", lastAccessed: 20 },
    ];
    storeRows(into, rows);
    storeRows(baseline, rows);
    storeRows(extra, rows);
    runMerge(MERGE_JS, into, extra, baseline);
    expect(values(into)).toEqual(rows);
  });
});
