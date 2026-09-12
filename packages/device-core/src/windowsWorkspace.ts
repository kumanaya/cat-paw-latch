/**
 * The only filesystem view given to a Windows AppContainer command.
 *
 * The command never receives an ACL to a real owner path.  Inputs and output
 * roots are copied into this directory before launch, then outputs are copied
 * back after the AppContainer tree is dead.  Every walk rejects links,
 * junctions, device names and NTFS alternate-data-stream spelling; copying
 * file bytes (rather than moving/linking) ensures a hard link made inside the
 * workspace cannot turn into a link to an owner file on reconciliation.
 */
import fs from "node:fs";
import path from "node:path";
import { canonicalize, isLexicallyWithin } from "@domo/protocol";

export class WindowsWorkspaceError extends Error {}

interface Mapping {
  readonly host: string;
  readonly staged: string;
  readonly writable: boolean;
}

function fail(message: string): never {
  throw new WindowsWorkspaceError(message);
}

function isDevicePath(value: string): boolean {
  const normalized = value.replace(/\//g, "\\");
  return normalized.startsWith("\\\\?\\") || normalized.startsWith("\\\\.\\");
}

function hasAdsComponent(value: string): boolean {
  const parsed = path.win32.parse(value);
  const relative = value.slice(parsed.root.length).replace(/\//g, "\\");
  return relative.split("\\").some((part) => part.includes(":"));
}

function assertSafePath(value: string, what: string): void {
  if (isDevicePath(value) || hasAdsComponent(value)) fail(`${what} is a device path or alternate data stream`);
}

function assertPlain(stat: fs.Stats, what: string): void {
  if (stat.isSymbolicLink()) fail(`${what} is a reparse point`);
  if (!stat.isDirectory() && !stat.isFile()) fail(`${what} is not a regular file or directory`);
}

function lstatPlain(target: string, what: string): fs.Stats {
  assertSafePath(target, what);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    fail(`${what} cannot be inspected: ${error instanceof Error ? error.message : String(error)}`);
  }
  assertPlain(stat!, what);
  return stat!;
}

/** Ensure every existing component is a real directory, never a junction. */
function mkdirPlain(target: string, what: string): void {
  assertSafePath(target, what);
  const parsed = path.parse(target);
  const parts = target.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  for (const part of parts) {
    if (part.includes(":")) fail(`${what} contains an alternate data stream`);
    current = path.join(current, part);
    try {
      const stat = fs.lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${what} crosses a reparse point`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      fs.mkdirSync(current);
    }
  }
}

/** Copy a tree without following, preserving or accepting any link. */
function copyPlain(source: string, destination: string, destinationLabel: string): void {
  const stat = lstatPlain(source, "workspace source");
  if (stat.isFile()) {
    mkdirPlain(path.dirname(destination), destinationLabel);
    try {
      const existing = fs.lstatSync(destination);
      if (!existing.isFile() || existing.isSymbolicLink()) fail(`${destinationLabel} is a reparse point or non-file`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    fs.copyFileSync(source, destination);
    return;
  }
  mkdirPlain(destination, destinationLabel);
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    if (entry.name.includes(":")) fail("workspace tree contains an alternate data stream");
    const child = path.join(source, entry.name);
    // Dirent is a fast early refusal; lstat inside the recursive call remains
    // authoritative because a process can swap an entry between these calls.
    if (entry.isSymbolicLink()) fail("workspace tree contains a reparse point");
    copyPlain(child, path.join(destination, entry.name), destinationLabel);
  }
}

function inside(candidate: string, root: string): boolean {
  return isLexicallyWithin(candidate.toLowerCase(), root.toLowerCase());
}

function mappedPath(candidate: string, mapping: Mapping): string | null {
  if (!inside(candidate, mapping.host)) return null;
  const relative = path.relative(mapping.host, candidate);
  // `inside` already checks a component boundary; `relative` is only used to
  // construct the staged spelling and must never name an upward escape.
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return null;
  return relative === "" ? mapping.staged : path.join(mapping.staged, relative);
}

export class WindowsWorkspace {
  readonly root: string;
  private readonly mappings: readonly Mapping[];

  private constructor(root: string, mappings: readonly Mapping[]) {
    this.root = root;
    this.mappings = mappings;
  }

  static create(args: { scratch: string; readPaths: readonly string[]; writePaths: readonly string[] }): WindowsWorkspace {
    const root = path.join(args.scratch, "appcontainer-workspace");
    // `scratch` is created by Executor, but making the primitive usable in a
    // direct test does not widen the trusted boundary: the unique run handle
    // still supplies this directory and no caller controls its parent.
    fs.mkdirSync(root, { recursive: true });
    const mappings: Mapping[] = [];
    const seen = new Set<string>();
    const add = (hostPath: string, writable: boolean) => {
      const host = canonicalize(hostPath);
      assertSafePath(host, "approved root");
      const key = host.toLowerCase();
      if (seen.has(key)) return;
      if (mappings.some((mapping) => inside(host, mapping.host) || inside(mapping.host, host))) {
        fail("approved workspace roots overlap; use one explicit root instead");
      }
      seen.add(key);
      lstatPlain(host, "approved root");
      const staged = path.join(root, writable ? "write" : "read", String(mappings.length));
      copyPlain(host, staged, "workspace");
      mappings.push({ host, staged, writable });
    };
    // Writable roots take precedence when a capability redundantly lists the
    // same root for reading: the command must observe its own staged changes.
    for (const rootPath of args.writePaths) add(rootPath, true);
    for (const rootPath of args.readPaths) add(rootPath, false);
    return new WindowsWorkspace(root, mappings);
  }

  /** Rewrite only a complete approved path. Opaque shell strings stay opaque. */
  rewrite(value: string): string {
    const canonical = canonicalize(value);
    for (const mapping of this.mappings) {
      const mapped = mappedPath(canonical, mapping);
      if (mapped !== null) return mapped;
    }
    return value;
  }

  rewriteCwd(cwd: string): string {
    const rewritten = this.rewrite(cwd);
    if (rewritten === cwd) fail("working directory is outside the staged workspace");
    return rewritten;
  }

  /**
   * Copy staged output back only once the launcher has killed/reaped every
   * descendant. No delete propagation yet: treating absence as deletion would
   * make an interrupted command destructive. A future manifest protocol can
   * add explicit deletes under the same checks.
   */
  reconcile(): void {
    for (const mapping of this.mappings) {
      if (!mapping.writable) continue;
      copyPlain(mapping.staged, mapping.host, "approved output root");
    }
  }
}
