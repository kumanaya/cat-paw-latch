/**
 * The only filesystem view given to a Linux bubblewrap command.
 *
 * The command never receives a live bind of a real owner path. Inputs and
 * output roots are copied into this directory before launch, then outputs are
 * copied back after the bwrap tree is dead. Every walk rejects symlinks;
 * copying file bytes (rather than moving/linking) ensures a hard link made
 * inside the workspace cannot turn into a link to an owner file on
 * reconciliation.
 *
 * Shebang scripts: the interpreter is staged under `.interp/` and the shebang
 * is rewritten so the child does not need a live `/usr/bin` bind (the launcher
 * deliberately omits host bin directories).
 *
 * Writable reconcile: files present in the staged tree are copied out; files
 * that were inventoried at create-time and are missing from the stage are
 * deleted on the host (delete propagation). Interrupted runs that never reach
 * reconcile do not delete.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalize, isLexicallyWithin } from "@domo/protocol";

export class LinuxWorkspaceError extends Error {}

interface Mapping {
  readonly host: string;
  readonly staged: string;
  readonly writable: boolean;
  /** Relative paths inventoried at create-time (writable roots only). */
  readonly inventory: ReadonlySet<string>;
}

function fail(message: string): never {
  throw new LinuxWorkspaceError(message);
}

function assertPlain(stat: fs.Stats, what: string): void {
  if (stat.isSymbolicLink()) fail(`${what} is a symbolic link`);
  if (!stat.isDirectory() && !stat.isFile()) fail(`${what} is not a regular file or directory`);
}

function lstatPlain(target: string, what: string): fs.Stats {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    fail(`${what} cannot be inspected: ${error instanceof Error ? error.message : String(error)}`);
  }
  assertPlain(stat, what);
  return stat;
}

function assertNotSymlinkRoot(hostPath: string): void {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(hostPath);
  } catch (error) {
    fail(`approved root cannot be inspected: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (stat.isSymbolicLink()) fail("approved root is a symbolic link");
}

/** Ensure every existing component is a real directory, never a symlink. */
function mkdirPlain(target: string, what: string): void {
  const parsed = path.parse(target);
  const parts = target.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  for (const part of parts) {
    current = path.join(current, part);
    try {
      const stat = fs.lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${what} crosses a symbolic link`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      fs.mkdirSync(current);
    }
  }
}

function listFiles(root: string): Set<string> {
  const out = new Set<string>();
  const walk = (dir: string, rel: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) fail("workspace tree contains a symbolic link");
      const childRel = rel ? path.join(rel, entry.name) : entry.name;
      const child = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(child, childRel);
      else if (entry.isFile()) out.add(childRel);
      else fail("workspace tree contains a non-file entry");
    }
  };
  const stat = lstatPlain(root, "inventory root");
  if (stat.isFile()) out.add("");
  else walk(root, "");
  return out;
}

/**
 * Stage a shebang interpreter into `interpRoot` and return the rewritten
 * script bytes, or null when the file is not a shebang script.
 */
function rewriteShebang(source: string, interpRoot: string): Buffer | null {
  const fd = fs.openSync(source, "r");
  try {
    const head = Buffer.alloc(2);
    if (fs.readSync(fd, head, 0, 2, 0) < 2 || head.toString("ascii") !== "#!") return null;
  } finally {
    fs.closeSync(fd);
  }
  const text = fs.readFileSync(source);
  const nl = text.indexOf(0x0a);
  const line = text.subarray(0, nl === -1 ? text.length : nl).toString("utf8");
  const match = /^#!\s*([^\s]+)(.*)$/.exec(line);
  if (!match) return null;
  let interpreter = match[1];
  let rest = match[2] ?? "";
  // `#!/usr/bin/env foo` would need a live PATH of host bins. Resolve `foo`
  // on the host at stage time and rewrite to that absolute binary instead.
  if (path.basename(interpreter) === "env") {
    const envArgs = rest.trim().split(/\s+/).filter(Boolean);
    if (envArgs.length === 0) fail("script shebang env has no command");
    const wanted = envArgs[0]!;
    const found = findOnPath(wanted);
    if (!found) fail(`script shebang env command not found on PATH: ${wanted}`);
    interpreter = found;
    rest = envArgs.length > 1 ? ` ${envArgs.slice(1).join(" ")}` : "";
  }
  if (!path.isAbsolute(interpreter)) fail(`script shebang interpreter is not absolute: ${interpreter}`);
  // Host interpreters are commonly symlinks (/usr/bin/python3 → 3.x). Resolve
  // once on the host and stage the real file; never follow links inside the
  // staged workspace later.
  let resolvedInterp: string;
  try {
    resolvedInterp = canonicalize(interpreter);
  } catch (error) {
    fail(`shebang interpreter cannot be resolved: ${error instanceof Error ? error.message : String(error)}`);
  }
  const interpStat = lstatPlain(resolvedInterp, "shebang interpreter");
  if (!interpStat.isFile()) fail("shebang interpreter is not a regular file");
  mkdirPlain(interpRoot, "interpreter stage");
  const stagedInterp = path.join(interpRoot, crypto.createHash("sha256").update(resolvedInterp).digest("hex"));
  if (!fs.existsSync(stagedInterp)) {
    fs.copyFileSync(resolvedInterp, stagedInterp);
    fs.chmodSync(stagedInterp, interpStat.mode & 0o777);
  }
  const body = nl === -1 ? Buffer.alloc(0) : text.subarray(nl);
  return Buffer.concat([Buffer.from(`#!${stagedInterp}${rest}\n`, "utf8"), body]);
}

function findOnPath(name: string): string | null {
  if (path.isAbsolute(name) && fs.existsSync(name)) return name;
  const pathEnv = process.env.PATH ?? "";
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, name);
    try {
      const st = fs.lstatSync(candidate);
      if (st.isFile() && !st.isSymbolicLink() && (st.mode & 0o111) !== 0) return candidate;
      // Follow a single symlink only when the target is a plain file under an
      // absolute path (common for /usr/bin/python → python3.x).
      if (st.isSymbolicLink()) {
        const real = canonicalize(candidate);
        const rst = fs.lstatSync(real);
        if (rst.isFile() && !rst.isSymbolicLink()) return real;
      }
    } catch {
      /* try next */
    }
  }
  return null;
}

function underScratch(candidate: string, scratch: string): boolean {
  let real: string;
  try {
    real = canonicalize(candidate);
  } catch {
    real = candidate;
  }
  return inside(real, scratch) || real === scratch;
}

/** Copy a tree without following links; rewrite shebang scripts. */
function copyPlain(
  source: string,
  destination: string,
  destinationLabel: string,
  interpRoot: string | null,
  scratch: string | null = null,
): void {
  if (scratch !== null && underScratch(source, scratch)) return;
  const stat = lstatPlain(source, "workspace source");
  if (stat.isFile()) {
    mkdirPlain(path.dirname(destination), destinationLabel);
    try {
      const existing = fs.lstatSync(destination);
      if (!existing.isFile() || existing.isSymbolicLink()) fail(`${destinationLabel} is a symbolic link or non-file`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const rewritten = interpRoot !== null ? rewriteShebang(source, interpRoot) : null;
    if (rewritten !== null) fs.writeFileSync(destination, rewritten, { mode: stat.mode & 0o777 });
    else {
      fs.copyFileSync(source, destination);
      fs.chmodSync(destination, stat.mode & 0o777);
    }
    return;
  }
  mkdirPlain(destination, destinationLabel);
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const child = path.join(source, entry.name);
    if (entry.isSymbolicLink()) fail("workspace tree contains a symbolic link");
    if (scratch !== null && underScratch(child, scratch)) continue;
    copyPlain(child, path.join(destination, entry.name), destinationLabel, interpRoot, scratch);
  }
}

function inside(candidate: string, root: string): boolean {
  return isLexicallyWithin(candidate, root);
}

function mappedPath(candidate: string, mapping: Mapping): string | null {
  if (!inside(candidate, mapping.host)) return null;
  const relative = path.relative(mapping.host, candidate);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return null;
  return relative === "" ? mapping.staged : path.join(mapping.staged, relative);
}

export class LinuxWorkspace {
  readonly root: string;
  private readonly mappings: readonly Mapping[];
  private readonly interpRoot: string;

  private constructor(root: string, mappings: readonly Mapping[], interpRoot: string) {
    this.root = root;
    this.mappings = mappings;
    this.interpRoot = interpRoot;
  }

  static create(args: { scratch: string; readPaths: readonly string[]; writePaths: readonly string[] }): LinuxWorkspace {
    // `/var` is a symlink to `/private/var` on macOS. Resolve the scratch
    // root before walking it so the anti-symlink guard protects user input,
    // not an OS-owned compatibility alias.
    fs.mkdirSync(args.scratch, { recursive: true });
    const scratch = canonicalize(args.scratch);
    const root = path.join(scratch, "bwrap-workspace");
    fs.mkdirSync(root, { recursive: true });
    const interpRoot = path.join(root, ".interp");
    fs.mkdirSync(interpRoot, { recursive: true });
    const mappings: Mapping[] = [];
    const seen = new Set<string>();
    const add = (hostPath: string, writable: boolean) => {
      assertNotSymlinkRoot(hostPath);
      const host = canonicalize(hostPath);
      if (seen.has(host)) return;
      if (mappings.some((mapping) => inside(host, mapping.host) || inside(mapping.host, host))) {
        fail("approved workspace roots overlap; use one explicit root instead");
      }
      seen.add(host);
      lstatPlain(host, "approved root");
      const inventory = writable ? listFiles(host) : new Set<string>();
      const staged = path.join(root, writable ? "write" : "read", String(mappings.length));
      copyPlain(host, staged, "workspace", interpRoot, scratch);
      mappings.push({ host, staged, writable, inventory });
    };
    for (const rootPath of args.writePaths) add(rootPath, true);
    for (const rootPath of args.readPaths) add(rootPath, false);
    return new LinuxWorkspace(root, mappings, interpRoot);
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
   * Copy staged output back and delete host files that vanished from the
   * stage but were inventoried at create-time. Symlinks on either side refuse.
   */
  reconcile(): void {
    for (const mapping of this.mappings) {
      if (!mapping.writable) continue;
      copyPlain(mapping.staged, mapping.host, "approved output root", null);
      const stagedNow = listFiles(mapping.staged);
      for (const rel of mapping.inventory) {
        if (stagedNow.has(rel)) continue;
        const hostFile = rel === "" ? mapping.host : path.join(mapping.host, rel);
        try {
          const st = fs.lstatSync(hostFile);
          if (st.isSymbolicLink()) fail("refuse to delete a symbolic link on reconcile");
          if (st.isFile()) fs.unlinkSync(hostFile);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
          throw error;
        }
      }
    }
  }
}
