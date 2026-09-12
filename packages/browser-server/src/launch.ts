/**
 * Launching the pinned Camoufox browser from a build-time fingerprint pool.
 *
 * The old server.py generated a fresh Camoufox fingerprint on every launch via
 * the Python `camoufox` package. We ship no Python and no fingerprint generator:
 * `scripts/build-browser-runtime.mjs` samples a POOL of macOS launch configs at
 * BUILD time (using camoufox-js, a build-only dependency) and freezes them as
 * `fingerprints.json` in the runtime. Here we pick ONE and drive the browser
 * with plain `playwright-core`.
 *
 * The pick is PINNED PER INSTALL, not random per launch: a persistent browser
 * that carries the owner's real profile and logins wants a STABLE Mac
 * fingerprint — a device whose screen size or GPU changes between sessions is a
 * bot signal, not a defense (DESIGN.md §11a). BrowserHost points
 * DOMO_FINGERPRINT_PIN at a per-install path; the first launch picks an entry
 * and records it there, every later launch reuses it.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { firefox } from "playwright-core";
import type { PageLike } from "./session.js";

/** One frozen launch config: everything `firefox.launch` needs except the
 * executable path and window mode, which are runtime facts. Whatever keys
 * camoufox-js's launchOptions sets (env with CAMOU_CONFIG chunks,
 * firefoxUserPrefs, args) ride along untouched. */
export interface FingerprintEntry {
  id: string;
  env?: Record<string, string>;
  firefoxUserPrefs?: Record<string, string | number | boolean>;
  args?: string[];
}

export interface FingerprintPool {
  /** The browser build these were sampled against — a mismatch is refused so a
   * stale pool never launches a browser it was not generated for. */
  browserVersion: string;
  entries: FingerprintEntry[];
}

export interface LaunchOptions {
  /** Camoufox executable (the app's --executable). */
  executablePath: string;
  /** Directory holding fingerprints.json (the server dir). */
  poolDir: string;
  headed: boolean;
  /** Persistent profile dir; undefined for an ephemeral context. */
  profileDir?: string;
  /** Where the per-install pin is stored (DOMO_FINGERPRINT_PIN). Undefined
   * falls back to a random pick per launch — dev only. */
  pinPath?: string;
}

/** A live browser + its first page. Structural so tests need no real browser. */
export interface LaunchedBrowser {
  page: PageLike;
  version: string;
  close(): Promise<void>;
}

export function loadPool(poolDir: string): FingerprintPool {
  const file = path.join(poolDir, "fingerprints.json");
  const pool = JSON.parse(fs.readFileSync(file, "utf8")) as FingerprintPool;
  if (!Array.isArray(pool.entries) || pool.entries.length === 0) {
    throw new Error(`fingerprint pool ${file} is empty`);
  }
  return pool;
}

/**
 * The entry pinned for this install. The pin stores the WHOLE entry plus the
 * browser version it was chosen for, and is reused for as long as that version
 * matches — NOT keyed on the id still being in the pool. The pool is resampled on
 * every package build, so an id-keyed pin would be invalidated by every ordinary
 * app update and present a new fingerprint; storing the entry itself keeps it
 * stable until the browser version actually changes. With no pinPath the pick is
 * per launch, for dev runs that do not care about stability.
 */
export function pinnedEntry(pool: FingerprintPool, pinPath?: string): FingerprintEntry {
  /** The pinned entry, if the pin was chosen for the CURRENT browser version;
   * undefined when the pin is absent, corrupt, or for another browser build. */
  const readPinned = (): FingerprintEntry | undefined => {
    try {
      const data = JSON.parse(fs.readFileSync(pinPath!, "utf8")) as {
        browserVersion?: string;
        entry?: FingerprintEntry;
      };
      return data.browserVersion === pool.browserVersion && data.entry?.id ? data.entry : undefined;
    } catch {
      return undefined;
    }
  };
  if (!pinPath) return pool.entries[crypto.randomInt(pool.entries.length)];

  const existing = readPinned();
  if (existing) return existing;

  // No usable pin (absent, corrupt, or for another browser version). Choose one
  // and publish {browserVersion, entry} through the LOCK, never a `wx` fast path:
  // `writeFileSync(..., {flag:"wx"})` creates the file EMPTY before it writes the
  // payload, so a concurrent first launch could read the empty file, call it
  // corrupt, and publish a different entry — two simultaneous first opens would
  // diverge. repairPin elects one writer under a lock and publishes the complete
  // JSON atomically (temp file + rename), so every concurrent caller returns the
  // SAME entry and no one ever sees a partial file.
  fs.mkdirSync(path.dirname(pinPath), { recursive: true });
  const chosen = pool.entries[crypto.randomInt(pool.entries.length)];
  const payload = JSON.stringify({ browserVersion: pool.browserVersion, entry: chosen });
  return repairPin(pinPath, chosen, payload, readPinned);
}

/** Block this thread briefly. pinnedEntry is synchronous and runs ONCE per
 * launch in a dedicated process that is about to block on browser startup, so a
 * bounded busy-wait during the rare repair race is fine. */
function sleepSync(ms: number): void {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {
    /* SharedArrayBuffer disabled — skip the wait; still correct, just spins */
  }
}

/** Publish a pin under a lock so concurrent callers all adopt one pick — the sole
 *  writer of the pin (first launch, and replacing a stale/corrupt one alike). The
 *  winner of an exclusive-create on `<pin>.lock` writes the pin via a temp file +
 *  atomic rename (so no caller ever reads a partial file); the losers wait and
 *  read the winner's entry.
 *
 *  The lock carries a heartbeat, not a fixed steal deadline: the holder
 *  refreshes its mtime through the critical section, and a waiter steals only
 *  a lock older than `LOCK_STALE_MS` — a crashed holder's, never a live but
 *  slow one's. A fixed "wait this long, then take it" deadline diverges on a
 *  slow host (two holders publish two pins); mtime converges, because only a
 *  holder that stopped touching can be stolen from. A lock a crashed writer
 *  left still self-heals once it goes stale.
 *
 *  Windows needs both halves of this: process startup there is slow enough
 *  that forty racers span seconds, and rename-over-open fails transiently
 *  (a concurrent reader, a scanner), so the publish retries briefly and a
 *  republisher adopts whatever is on disk rather than failing a launch. */
const LOCK_STALE_MS = 5000;

/** Temporary race tracing (DOMO_DEBUG_PIN=1): pid-stamped lock events on stderr. */
function pinTrace(...args: unknown[]): void {
  if (process.env.DOMO_DEBUG_PIN === "1") {
    process.stderr.write(`[pin:${process.pid}] ${args.join(" ")}\n`);
  }
}

/** Refresh the lock's mtime: proof this holder is alive. Best effort — a
 *  stolen lock is already someone else's to touch. */
function touchLock(lock: string): void {
  try {
    const now = new Date();
    fs.utimesSync(lock, now, now);
  } catch {
    /* stolen or gone; the waiter logic sorts it out */
  }
}

/** Whether this process still owns the lock: its content is our pid. A
 *  thief that stole a stale-looking lock replaces the file, so publishing
 *  under a stolen lock would fork the pin — check before the rename. */
function ownsLock(lock: string): boolean {
  try {
    return fs.readFileSync(lock, "utf8") === String(process.pid);
  } catch {
    return false;
  }
}

/** Drop a temp file that a failed publish left behind. */
function dropTmp(tmp: string): void {
  try {
    fs.rmSync(tmp, { force: true });
  } catch {
    /* still theirs to clean, or already gone */
  }
}

/** Adopt the winner's pin if one lands, bounded — then last-resort our own
 *  pick, which matches the cannot-lock branch. Unpublished picks never leave
 *  silently: every path through here prefers a pin that is on disk.
 *
 *  Releases the lock on entry: an adopter publishes nothing, so holding it
 *  only starves the process that would. (The holder's finally unlinks again
 *  harmlessly.) */
function adoptPinned(
  readPinned: () => FingerprintEntry | undefined,
  chosen: FingerprintEntry,
  tmp: string,
  lock: string,
): FingerprintEntry {
  try {
    fs.unlinkSync(lock);
  } catch {
    /* already gone */
  }
  const adoptUntil = Date.now() + LOCK_STALE_MS;
  for (;;) {
    const adopted = readPinned();
    if (adopted) {
      dropTmp(tmp);
      return adopted;
    }
    if (Date.now() > adoptUntil) {
      dropTmp(tmp);
      return chosen;
    }
    touchLock(lock);
    sleepSync(50);
  }
}

function repairPin(
  pinPath: string,
  chosen: FingerprintEntry,
  payload: string,
  readPinned: () => FingerprintEntry | undefined,
): FingerprintEntry {
  const lock = `${pinPath}.lock`;
  for (;;) {
    const valid = readPinned();
    if (valid) {
      pinTrace("adopt-loop", valid.id);
      return valid; // the winner already published — adopt it
    }
    try {
      fs.writeFileSync(lock, String(process.pid), { flag: "wx", mode: 0o600 });
      pinTrace("acquired-lock");
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      // EEXIST is the lock held; EPERM/EBUSY/EACCES on the create itself is
      // contention with a scanner, not a verdict — wait it out like a held
      // lock, because returning our own pick here forks the pin. Anything
      // else (a directory that will never take a file) cannot lock, ever.
      if (code !== "EEXIST" && code !== "EPERM" && code !== "EBUSY" && code !== "EACCES") {
        return chosen; // cannot lock
      }
      // Another process holds the lock. Steal only a STALE one — a live
      // holder's heartbeat keeps its mtime fresh no matter how slow the
      // host is. A missing mtime means the lock vanished mid-read: retry.
      let stale = false;
      try {
        stale = Date.now() - fs.statSync(lock).mtimeMs > LOCK_STALE_MS;
      } catch {
        continue;
      }
      if (stale) {
        pinTrace("stealing-lock");
        try {
          fs.unlinkSync(lock);
        } catch {
          /* someone else reclaimed it first */
        }
      }
      sleepSync(50);
      continue;
    }
    // We hold the lock: repair once, unless a prior holder already did.
    touchLock(lock);
    try {
      const again = readPinned();
      if (again) {
        pinTrace("again-adopt", again.id);
        return again;
      }
      const tmp = `${pinPath}.${process.pid}.${crypto.randomInt(1_000_000_000)}`;
      // The temp write can meet the same transient contention as the lock
      // create (a scanner holding the name): retry it rather than crash a
      // launch. Persistent failure adopts — someone else may still publish.
      const writeUntil = Date.now() + LOCK_STALE_MS;
      let written = false;
      while (!written) {
        try {
          fs.writeFileSync(tmp, payload, { mode: 0o600 });
          written = true;
        } catch (e) {
          const code = (e as NodeJS.ErrnoException).code;
          pinTrace("tmp-write-fail", code);
          if ((code !== "EPERM" && code !== "EBUSY" && code !== "EACCES") || Date.now() > writeUntil) {
            return adoptPinned(readPinned, chosen, tmp, lock);
          }
          touchLock(lock);
          sleepSync(50);
        }
      }
      touchLock(lock);
      // Fencing: a waiter may have stolen the lock while a syscall stalled
      // (Windows stalls one for seconds under load). Publishing under a
      // stolen lock forks the pin — two holders, two ids — so a holder
      // that lost its name adopts instead of publishing.
      if (!ownsLock(lock)) {
        pinTrace("lost-ownership-adopting");
        return adoptPinned(readPinned, chosen, tmp, lock);
      }
      const publishUntil = Date.now() + LOCK_STALE_MS;
      let published = false;
      while (!published) {
        try {
          fs.renameSync(tmp, pinPath);
          published = true;
        } catch (e) {
          const code = (e as NodeJS.ErrnoException).code;
          const retryable = code === "EPERM" || code === "EBUSY" || code === "EACCES";
          // A republisher may have landed one while this rename failed:
          // converge on it rather than overwrite it a moment later.
          const adopted = readPinned();
          if (adopted) {
            dropTmp(tmp);
            return adopted;
          }
          if (!ownsLock(lock)) return adoptPinned(readPinned, chosen, tmp, lock);
          if (!retryable || Date.now() > publishUntil) break;
          touchLock(lock);
          sleepSync(50);
        }
      }
      if (published) {
        // Converge on what is actually on disk: a thief that won a heartbeat
        // race publishes a microsecond later, and last-writer is the one
        // every later reader adopts.
        dropTmp(tmp);
        const settled = readPinned() ?? chosen;
        pinTrace("published-returning", settled.id);
        return settled;
      }
      // The disk would not take the publish: adopt the winner's pin if one
      // lands, bounded — then last-resort our own pick, which matches the
      // cannot-lock branch above. Unpublished picks never leave silently:
      // every path through here prefers a pin that is on disk.
      return adoptPinned(readPinned, chosen, tmp, lock);
    } finally {
      try {
        fs.unlinkSync(lock);
      } catch {
        /* already gone */
      }
    }
  }
}

/** The browser build a pool was generated for, comparable to Playwright's
 * `browser.version()`: `runtime.lock.json` names it "official/152.0.4-beta.28",
 * playwright reports "152.0.4-beta.28", so drop the repo prefix. */
export function poolBrowserBuild(poolVersion: string): string {
  return poolVersion.split("/").pop() ?? poolVersion;
}

/** Whether a pool may drive a browser reporting `version`. Unknown (empty)
 * versions are permitted — refusing on a version we could not read would be a
 * worse failure than the mismatch it guards against. */
export function poolMatchesBrowser(pool: FingerprintPool, version: string): boolean {
  if (!version) return true;
  return poolBrowserBuild(pool.browserVersion) === version;
}

/** Launch the browser and hand back its first page. Camoufox yields a Browser
 * normally and a BrowserContext when persistent; a persistent context arrives
 * with a page ALREADY open, so we take pages()[0] there rather than opening a
 * second the owner cannot tell apart.
 *
 * The pool's configs were validated (at generation time) against ONE browser
 * build, so a stale pool or an overridden binary is refused rather than run with
 * fingerprint data meant for a different version. */
export async function launchBrowser(opts: LaunchOptions): Promise<LaunchedBrowser> {
  const pool = loadPool(opts.poolDir);
  const entry = pinnedEntry(pool, opts.pinPath);
  const common = {
    executablePath: opts.executablePath,
    headless: !opts.headed,
    args: entry.args ?? [],
    env: { ...process.env, ...(entry.env ?? {}) } as Record<string, string>,
    firefoxUserPrefs: entry.firefoxUserPrefs,
  };

  const context = opts.profileDir
    ? await firefox.launchPersistentContext(opts.profileDir, common)
    : null;
  const browser = context ? context.browser() : await firefox.launch(common);
  const close = context ? (): Promise<void> => context.close() : (): Promise<void> => browser!.close();
  const version = browserVersionOf(browser);

  if (!poolMatchesBrowser(pool, version)) {
    await close();
    throw new Error(
      `fingerprint pool is for browser ${poolBrowserBuild(pool.browserVersion)} but launched ` +
        `${version}; regenerate the pool (just fetch-browser) or fix DOMO_CAMOUFOX`,
    );
  }

  const page = (
    context ? (context.pages()[0] ?? (await context.newPage())) : await browser!.newPage()
  ) as unknown as PageLike;
  return { page, version, close };
}

function browserVersionOf(browser: { version(): string } | null): string {
  try {
    return browser?.version() ?? "";
  } catch {
    return "";
  }
}
