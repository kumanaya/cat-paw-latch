#!/usr/bin/env node
/**
 * Add what a browser session did to the user's cookies, and nothing else — the
 * TypeScript port of vendor/browser-server/merge_cookies.py. Called when a
 * session ends: it browsed on a clone of the user's profile, and what it did
 * there has to reach the profile itself without throwing away what another
 * browser did at the same time.
 *
 * The clone is compared against the baseline it started from, so the merge knows
 * what this session actually DID rather than what it looks like now:
 *   - a row whose columns differ from the baseline was changed here and is
 *     written back;
 *   - a row that is gone was signed out of, and is removed from the profile, but
 *     only while the profile still holds exactly what the baseline did;
 *   - everything else was merely read. Reading moves `lastAccessed`, which is
 *     why that column is not part of "changed".
 *
 * Columns are read from the table rather than written down here: Firefox adds
 * one every few releases, and a list that went stale would quietly drop whatever
 * it did not name. `id` is left out on purpose — it is the row number of the
 * store being written, not part of the cookie.
 *
 * node-sqlite3-wasm gives the same ATTACH-based multi-database merge Python's
 * sqlite3 did, so the SQL is line for line what it was. It is a WASM build with a
 * synchronous, file-backed API: no native binary, no ABI, no Electron rebuild —
 * one arch-neutral module loads identically under the tests' Node and the
 * packaged app's Electron runtime. (better-sqlite3 was ABI-locked and would have
 * had to be rebuilt per-arch for Electron; DESIGN.md §11a.)
 */
// node-sqlite3-wasm is CommonJS; a NAMED esm import (`import { Database }`)
// throws "Named export not found" when this file runs as a real ESM script under
// node (vitest's transform hides it, the packaged spawn does not). The default
// import is the interop-safe form.
import sqlite3 from "node-sqlite3-wasm";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const { Database } = sqlite3;

const KEY = ["name", "host", "path", "originAttributes"];
/** Moved by a read, so it says nothing about what the session changed. */
const READ_ONLY_COLUMN = "lastAccessed";

/**
 * `into` the user's profile, `extra` the session's clone, `baseline` what that
 * clone started from (absent only on a profile with no cookie store).
 */
export function mergeCookies(into: string, extra: string, baseline: string): void {
  // All three stores are read fully, the merge is computed in memory, and
  // only `into` is ever written — inside one transaction. No ATTACH: the
  // WASM sqlite VFS cannot commit a multi-database transaction on Windows
  // ("disk I/O error" on COMMIT even with nothing written), while a
  // single-database transaction commits fine there — and one implementation
  // runs identically on every host, so the suite below pins Windows behavior
  // on macOS too.
  //
  // The comparisons below are the SQL's, spelled out: `IS` is null-safe
  // equality (a NULL column matches a NULL column), and `mine.lastAccessed
  // >= theirs.lastAccessed` is false when either side is NULL. Cookie
  // stores are a few hundred rows; reading them whole is cheaper than the
  // browser launch that precedes this call.
  const mainDb = new Database(into);
  const extraDb = new Database(extra);
  const hasBaseline = fs.existsSync(baseline);
  const baseDb = hasBaseline ? new Database(baseline) : null;
  try {
    // A session closing must not stall on a store another browser is writing.
    mainDb.run("PRAGMA busy_timeout = 10000");
    const columns = (
      mainDb.all("PRAGMA main.table_info(moz_cookies)") as { name: string }[]
    )
      .map((r) => r.name)
      .filter((n) => n !== "id");
    if (columns.length === 0) throw new Error("no moz_cookies table to merge into");
    const keys = KEY.filter((k) => columns.includes(k));
    const state = columns.filter((c) => c !== READ_ONLY_COLUMN);
    const names = columns.join(",");

    const mains = readRows(mainDb, ["id", ...columns]);
    const theirs = readRows(extraDb, columns);
    const was = baseDb === null ? null : readRows(baseDb, columns);

    // A session that changed the same cookie more recently already won.
    const upserts = theirs.filter(
      (t) =>
        !mains.some((m) => sameKey(m, t, keys) && notBefore(m, t)) &&
        (was === null || !was.some((w) => sameKey(w, t, keys) && sameState(w, t, state))),
    );
    // Signed out here: gone from the clone, and the profile still holds
    // exactly what this session started from.
    const deletions =
      was === null
        ? []
        : mains.filter(
            (m) =>
              was.some((w) => sameKey(w, m, keys) && sameState(w, m, state)) &&
              !theirs.some((t) => sameKey(t, m, keys)),
          );

    // The delete (sign-outs) and the insert (changes) are one atomic write: a
    // crash or a lock timeout between them must not leave the profile with the
    // sign-outs applied but the new tokens missing — that is a half-merged
    // login. ROLLBACK on any failure leaves the profile exactly as it was.
    mainDb.run("BEGIN IMMEDIATE");
    try {
      for (const m of deletions) mainDb.run("DELETE FROM main.moz_cookies WHERE id = ?", [m.id]);
      for (const t of upserts) {
        mainDb.run(
          `INSERT OR REPLACE INTO main.moz_cookies (${names}) VALUES (${columns.map(() => "?").join(",")})`,
          columns.map((c) => t[c] ?? null),
        );
      }
      mainDb.run("COMMIT");
    } catch (err) {
      try {
        mainDb.run("ROLLBACK");
      } catch {
        /* the transaction was already undone by the failure */
      }
      throw err;
    }
  } finally {
    baseDb?.close();
    extraDb.close();
    mainDb.close();
  }
}

type Cell = number | bigint | string | Uint8Array | boolean | null;
type Row = Record<string, Cell>;

/** Every row of moz_cookies, with the given columns (plus `id` when asked). */
function readRows(db: { all: (sql: string) => unknown }, columns: string[]): Row[] {
  const quoted = columns.map((c) => `"${c.replace(/"/g, '""')}"`).join(",");
  return db.all(`SELECT ${quoted} FROM moz_cookies`) as Row[];
}

/** SQLite `IS`: null-safe equality, byte-wise for blobs. */
function isValue(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    return a.length === b.length && a.every((v, i) => v === b[i]);
  }
  return false;
}

function sameKey(a: Row, b: Row, keys: string[]): boolean {
  return keys.every((k) => isValue(a[k], b[k]));
}

function sameState(a: Row, b: Row, state: string[]): boolean {
  return state.every((c) => isValue(a[c], b[c]));
}

/** `mine.lastAccessed >= theirs.lastAccessed`: false when either side is
 *  NULL, exactly as the SQL comparison is. A session that changed the same
 *  cookie more recently already won. */
function notBefore(mine: Row, theirs: Row): boolean {
  const m = mine[READ_ONLY_COLUMN];
  const t = theirs[READ_ONLY_COLUMN];
  return typeof m === "number" && typeof t === "number" && m >= t;
}

// CLI: into, extra, baseline — the argv shape BrowserHost spawns.
//
// "am I the entry script" compared as RESOLVED FILESYSTEM PATHS, never as
// `import.meta.url === \`file://${argv[1]}\``: that string form fails whenever
// the path holds a character the URL escapes — a space in "Plow Latch.app" is
// the shipping case — and the block would then never run, the process would exit
// 0 having merged nothing, and the caller would delete the session clone on the
// strength of it, losing every login made in the session.
if (isMain()) {
  const [into, extra, baseline] = process.argv.slice(2);
  mergeCookies(into, extra, baseline);
}

function isMain(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  const self = fileURLToPath(import.meta.url);
  const real = (p: string): string => {
    try {
      return fs.realpathSync(p);
    } catch {
      return p;
    }
  };
  return real(self) === real(entry);
}
