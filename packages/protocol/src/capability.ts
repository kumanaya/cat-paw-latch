/**
 * Capability, RuleKey, PathUtil — twin of DomoProtocol/Capability.swift.
 */
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import nodePath from "node:path";
import { canonicalBytes, canonicalJSON, JSONValue } from "./json.js";
import { Hashing } from "./identity.js";
import { normalizeOrigin } from "./origins.js";

export type CapabilityKind =
  | "fs.read"
  | "fs.write"
  | "process.exec"
  | "network"
  | "apple_events"
  | "tool"
  | "browser"
  | "credential"
  | "applescript";

export interface Capability {
  kind: CapabilityKind;
  paths?: string[]; // fs.read / fs.write
  argv?: string[]; // process.exec (argv[0] is the executable)
  cwd?: string; // process.exec
  allowed?: boolean; // network, apple_events
  tool?: string; // tool
  origins?: string[]; // browser: host patterns ("dominos.com", "*.dominos.com")
  access?: "fill"; // credential: type values into pages
  items?: string[]; // credential(fill): vault item ids
  app?: string; // applescript: the app as the agent named it ("Mail")
  bundleId?: string; // applescript: that app's bundle id, resolved on this Mac
  script?: string; // applescript: the whole script, verbatim
  args?: string[]; // applescript: values handed to its `on run argv`, not pasted into its text
  reason?: string; // display-only justification
}

/**
 * Normalized form used for rule keys: display-only fields stripped, paths
 * canonicalized and sorted so equivalent requests hash identically.
 *
 * On Windows the paths also fold case: NTFS is case-insensitive, so two
 * spellings of one place must hash to one rule or the owner gets asked twice
 * for the same grant. Folding cannot widen an approval — two different files
 * never fold equal in the Win32 namespace. POSIX stays bytewise (APFS can be
 * case-sensitive), and the frozen rule-key vectors assert those bytes.
 */
export function normalizedCapability(c: Capability): Capability {
  const out: Capability = { ...c };
  delete out.reason;
  if (out.paths) out.paths = out.paths.map((p) => foldGrantPath(canonicalize(p))).sort();
  if (out.cwd !== undefined) out.cwd = foldGrantPath(canonicalize(out.cwd));
  if (out.origins) out.origins = out.origins.map((o) => normalizeOrigin(o)).sort();
  if (out.items) out.items = [...out.items].sort();
  return out;
}

/** Win32-only case fold for grant paths (see normalizedCapability). */
function foldGrantPath(p: string): string {
  return process.platform === "win32" ? foldPath(p) : p;
}

/** Human-readable one-liner for approval UIs and audit logs. */
export function capabilityDisplay(c: Capability): string {
  switch (c.kind) {
    case "fs.read":
      return `Read: ${(c.paths ?? []).join(", ")}`;
    case "fs.write":
      return `Write: ${(c.paths ?? []).join(", ")}`;
    case "process.exec": {
      const cmd = (c.argv ?? []).join(" ");
      return `Run: ${cmd}` + (c.cwd !== undefined ? ` (in ${c.cwd})` : "");
    }
    case "network":
      return c.allowed ? "Network: allowed" : "Network: denied";
    case "apple_events":
      return c.allowed
        ? "Apple events: may control this Desktop's apps"
        : "Apple events: denied";
    case "tool":
      return `Tool: ${c.tool ?? "?"}`;
    case "browser":
      return `Browse: ${(c.origins ?? []).join(", ")}`;
    case "credential":
      return `Credentials: fill ${(c.items ?? []).join(", ")} into approved sites (typed on this Desktop; the agent can see the page it types into)`;
    case "applescript":
      return (
        `Script ${c.app ?? "?"} (${c.bundleId ?? "?"}): ${c.script ?? ""}` +
        (c.args?.length ? `\nargs: ${JSON.stringify(c.args)}` : "")
      );
  }
}

export const RuleKey = {
  /**
   * Exact-capability-match rule key (DESIGN.md §5): SHA-256 over the canonical
   * JSON of agent + device + normalized capabilities. Goal text is
   * deliberately excluded — it is unverifiable.
   */
  compute(agentId: string, deviceId: string, capabilities: Capability[]): string {
    const normalized = capabilities
      .map(normalizedCapability)
      .sort((a, b) => {
        const ea = canonicalJSON(a as unknown as JSONValue);
        const eb = canonicalJSON(b as unknown as JSONValue);
        return ea < eb ? -1 : ea > eb ? 1 : 0;
      });
    const payload = { agent: agentId, device: deviceId, caps: normalized };
    return Hashing.sha256Hex(canonicalBytes(payload as unknown as JSONValue));
  },
};

/**
 * Canonicalize to a TRUE physical path: expand ~, make absolute, collapse
 * "." / "..", and resolve symlinks via realpath() on the longest existing
 * prefix (appending any not-yet-existing remainder).
 *
 * This must return the real path the kernel sees (e.g. /private/var/…, not
 * /var/…) because seatbelt enforces against physical paths. Node's
 * fs.realpathSync is realpath(3) and preserves /private — do not swap in
 * anything that normalizes differently.
 *
 * On Windows the same contract holds in native form: `~` expands to the
 * profile, relative paths join the cwd, separators fold to `\`, and the
 * longest existing prefix resolves through Win32 realpath (drive-letter
 * and UNC roots included). POSIX behavior below is byte-identical to
 * before — the frozen vectors assert it.
 */
export function canonicalize(path: string): string {
  if (process.platform === "win32") return canonicalizeWin(path, (c) => fs.realpathSync(c));
  const stack = lexicalComponents(path);

  // Walk from the leaf up to find the longest existing prefix, realpath it,
  // then re-append the components below it.
  const remainder: string[] = [];
  const prefix = [...stack];
  while (prefix.length > 0) {
    const candidate = "/" + prefix.join("/");
    let resolved: string | null = null;
    try {
      resolved = fs.realpathSync(candidate);
    } catch {
      resolved = null;
    }
    if (resolved !== null) {
      return [resolved, ...remainder.reverse()].join("/");
    }
    remainder.push(prefix.pop()!);
  }
  return "/" + remainder.reverse().join("/");
}

/**
 * The lexical half of canonicalization, shared by both variants so they cannot
 * drift: `~` expansion, making the path absolute, and collapsing "." / "..".
 * Returns the path components, leaf last.
 */
function lexicalComponents(path: string): string[] {
  let p = path;
  if (p === "~") p = os.homedir();
  else if (p.startsWith("~/")) p = os.homedir() + p.slice(1);
  if (!p.startsWith("/")) p = process.cwd() + "/" + p;

  const stack: string[] = [];
  for (const component of p.split("/")) {
    if (component === "" || component === ".") continue;
    if (component === "..") {
      if (stack.length > 0) stack.pop();
      continue;
    }
    stack.push(component);
  }
  return stack;
}

/**
 * The Windows twin of the lexical half + prefix walk: native separators,
 * drive-letter and UNC roots, `~` to the profile. The walk is the same
 * longest-existing-prefix shape, so the sync/async pair cannot drift from
 * each other here either — only from POSIX, which they never meet, because
 * every caller on Windows hands Windows paths.
 */
function winLexical(path: string): { root: string; parts: string[] } {
  let p = path.replace(/\//g, "\\");
  // The long-path prefix names the same file as the unprefixed form, but the
  // two realpaths disagree on it (sync throws, async resolves) — strip it so
  // the pair converges before the walk. `\\?\UNC\server\share` is the UNC
  // form. This introduces no new alias class: after stripping, the path gets
  // exactly the treatment its unprefixed spelling always had. `\\.\`
  // (device namespace) is NOT stripped — it names another namespace and
  // keeps failing closed below.
  const uncLong = p.match(/^\\\\\?\\UNC\\([^\\]+)\\([^\\]+)\\?/i);
  if (uncLong) p = `\\\\${uncLong[1]}\\${uncLong[2]}` + p.slice(uncLong[0].length);
  else if (/^\\\\\?\\[A-Za-z]:\\/i.test(p)) p = p.slice(4);
  if (p === "~") p = os.homedir();
  else if (p.startsWith("~\\")) p = os.homedir() + p.slice(1);
  // Always through win32.resolve: it is idempotent for absolutes, joins the
  // cwd for relatives, and supplies the current drive for rooted-but-drivoless
  // `\x` (which isAbsolute reports as absolute) — the same rule path.resolve,
  // which callers also use, applies.
  p = nodePath.win32.resolve(p);
  const normalized = nodePath.win32.normalize(p);
  const unc = normalized.match(/^\\\\[^\\]+\\[^\\]+\\?/);
  if (unc) return { root: unc[0], parts: normalized.slice(unc[0].length).split("\\").filter((c) => c !== "") };
  const drive = normalized.match(/^[A-Za-z]:\\/);
  if (drive) return { root: drive[0], parts: normalized.slice(drive[0].length).split("\\").filter((c) => c !== "") };
  return { root: "\\", parts: normalized.replace(/^\\+/, "").split("\\").filter((c) => c !== "") };
}

function canonicalizeWin(path: string, realpath: (candidate: string) => string): string {
  const { root, parts } = winLexical(path);
  const remainder: string[] = [];
  const prefix = [...parts];
  while (prefix.length > 0) {
    const candidate = root + prefix.join("\\");
    try {
      const resolved = realpath(candidate);
      return remainder.length === 0 ? resolved : resolved + "\\" + remainder.reverse().join("\\");
    } catch {
      // Not existing (yet) — walk up.
    }
    remainder.push(prefix.pop()!);
  }
  // Nothing under the root exists: the lexical path is the answer.
  return root + remainder.reverse().join("\\");
}

/**
 * `canonicalize` without blocking the event loop.
 *
 * Byte-identical to the synchronous one — `fs.promises.realpath` is the same
 * realpath(3), and the lexical half is literally the same code — and asserted
 * against the same golden vectors. It exists because resolution is filesystem
 * I/O: on a slow or unresponsive mounted volume the synchronous version blocks
 * the loop, which stops a call budget's timer from ever firing. Anything
 * running under a budget must use this one.
 */
export async function canonicalizeAsync(path: string): Promise<string> {
  if (process.platform === "win32") {
    const { root, parts } = winLexical(path);
    const remainder: string[] = [];
    const prefix = [...parts];
    while (prefix.length > 0) {
      const candidate = root + prefix.join("\\");
      try {
        const resolved = await fsp.realpath(candidate);
        // Node's async Win32 realpath keeps the long spelling while the sync
        // implementation returns the physical 8.3 spelling on some volumes.
        // Canonical paths are signature-critical, so normalize the existing
        // prefix through the sync primitive before appending lexical leaves.
        const physical = fs.realpathSync(resolved);
        return remainder.length === 0 ? physical : physical + "\\" + remainder.reverse().join("\\");
      } catch {
        // Not existing (yet) — walk up.
      }
      remainder.push(prefix.pop()!);
    }
    return root + remainder.reverse().join("\\");
  }
  const stack = lexicalComponents(path);
  const remainder: string[] = [];
  const prefix = [...stack];
  while (prefix.length > 0) {
    const candidate = "/" + prefix.join("/");
    let resolved: string | null = null;
    try {
      resolved = await fsp.realpath(candidate);
    } catch {
      resolved = null;
    }
    if (resolved !== null) {
      return [resolved, ...remainder.reverse()].join("/");
    }
    remainder.push(prefix.pop()!);
  }
  return "/" + remainder.reverse().join("/");
}

/**
 * True when `path` is `root` or lexically inside it — a string test, no
 * disk. Both arguments must already be in the same form (canonical, or both
 * as named); the caller decides which, since resolving a root again after
 * something else has had a turn on the disk is how a swapped symlink walks
 * an approval somewhere it never pointed. The one root predicate shared by
 * the sandbox profile, the gate table, and the diagnosis.
 *
 * Bytewise on every platform, including Windows: grants and rule keys are
 * computed from these roots, and a fold here would widen an approval. The
 * Windows branch differs in the separator only — canonical Windows paths
 * are backslash-joined, so the join is too. Case- and separator-insensitive
 * comparison lives one layer up, in `overlapsRoot` (holds) and in `isWithin`
 * / `normalizedCapability` (grants, Windows-only fold) — never bare, and
 * never in a profile root.
 */
export function isLexicallyWithin(path: string, root: string): boolean {
  if (process.platform === "win32") {
    // Separators fold, case does not: `C:\Users\x` vs `c:/users/x` stay two
    // strings here (grants are bytewise), while POSIX-shaped inputs keep
    // matching the way they do on every other platform.
    const sep = (s: string) => s.replace(/\//g, "\\");
    const p = sep(path);
    const r = sep(root);
    return p === r || p.startsWith(r.endsWith("\\") ? r : r + "\\");
  }
  return path === root || path.startsWith(root.endsWith("/") ? root : root + "/");
}

/**
 * `isLexicallyWithin` for the question "could a writer of `root` reach
 * `path`?" — the hold that keeps a diagnostic probe off anything a live run
 * can rewrite. The default macOS filesystem is case-insensitive and
 * Unicode-normalization-insensitive, and a component that does not exist
 * yet keeps the spelling its caller gave it, so `~/Documents/Out` and
 * `~/documents/out` are one place to APFS and two strings to `===`.
 * Compared folded, which can only find MORE overlap: a hold that is too
 * wide withholds a probe, and a probe withheld is a fact, never a leak.
 * Never used for a grant — a profile root or a rule key stays bytewise.
 *
 * On Windows the fold also straightens separators, for the same reason:
 * NTFS is case-insensitive, and `C:\Users\x` vs `c:/users/x` are one place
 * a live run can rewrite either spelling of.
 */
export function overlapsRoot(path: string, root: string): boolean {
  return isLexicallyWithin(foldPath(path), foldPath(root));
}

function foldPath(p: string): string {
  const separators = process.platform === "win32" ? p.replace(/\//g, "\\") : p;
  return separators.normalize("NFC").toLowerCase();
}

/** True when `path` is `root` or inside it, after canonicalization.
 *
 * On Windows both canonicals fold case before the lexical test: realpath
 * preserves the caller's spelling, so without the fold one place approved as
 * `C:\Dir` refuses a later `c:\dir\file` — a false refusal, never an escape
 * (check and use resolve to the same file either way). The fold cannot widen
 * the grant: two different files never fold equal in the Win32 namespace, and
 * the separator boundary still holds (`c:\dir-evil` is not `c:\dir\`).
 */
export function isWithin(path: string, root: string): boolean {
  if (process.platform === "win32") {
    return isLexicallyWithin(foldPath(canonicalize(path)), foldPath(canonicalize(root)));
  }
  return isLexicallyWithin(canonicalize(path), canonicalize(root));
}

export function isWithinRoots(path: string, roots: string[]): boolean {
  return roots.some((root) => isWithin(path, root));
}

/**
 * `isWithin` / `isWithinRoots` without blocking the event loop. Same predicate,
 * same canonical bytes — see `canonicalizeAsync`. Anything running under a call
 * budget must use these, because scope-checking resolves paths and resolution
 * is filesystem I/O.
 */
export async function isWithinAsync(path: string, root: string): Promise<boolean> {
  const p = await canonicalizeAsync(path);
  const r = await canonicalizeAsync(root);
  if (process.platform === "win32") return isLexicallyWithin(foldPath(p), foldPath(r));
  return isLexicallyWithin(p, r);
}

export async function isWithinRootsAsync(path: string, roots: string[]): Promise<boolean> {
  const results = await Promise.all(roots.map((root) => isWithinAsync(path, root)));
  return results.some(Boolean);
}

export const PathUtil = { canonicalize, isWithin, isWithinRoots };
