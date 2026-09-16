/**
 * Sandbox profile generation + sandboxed execution — twin of
 * DomoDeviceCore/Executor.swift. The SBPL profile is never authored; it is
 * mechanically derived from the approved capability set (DESIGN.md §6) and
 * must be BYTE-IDENTICAL to the Swift generator (fixtures/sbpl.json).
 */
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { canonicalize, isLexicallyWithin, overlapsRoot } from "@domo/protocol";
import { unpackedPath } from "./asarPath.js";
import { WindowsWorkspace } from "./windowsWorkspace.js";
import { writeWindowsLaunchConfig } from "./windowsLaunchConfig.js";
import { LinuxWorkspace } from "./linuxWorkspace.js";
import { writeLinuxLaunchConfig } from "./linuxLaunchConfig.js";

const READ_BOILERPLATE = [
  "/usr",
  "/bin",
  "/sbin",
  "/System",
  "/Library",
  "/opt",
  "/private/etc",
  "/private/var/db",
  "/private/var/select",
];

function quote(p: string): string {
  return '"' + p.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

export const SandboxProfile = {
  generate(args: {
    readPaths: string[];
    writePaths: string[];
    network: boolean;
    appleEvents: boolean;
    scratch: string;
    /** Home override for golden tests; defaults to the real home. */
    home?: string;
  }): string {
    const lines: string[] = [
      "(version 1)",
      "(deny default)",
      "(allow process-fork)",
      "(allow process-exec)",
      "(allow process-info*)",
      "(allow signal (target children))",
      "(allow sysctl-read)",
      // TODO(v1.x): tighten to the specific services processes need.
      //
      // Before you do: the MCP manifest names specific macOS tools it promises
      // an agent can run, and every one of them resolves a service through
      // THIS line. `MACOS_TOOLING` in mcp-server/src/tools.ts is the single
      // list — the sole source of truth for which tools are named, each
      // verified to exit 0 under this profile as written. An allowlist that misses what
      // they need turns that copy into a guaranteed denial — the exact bug the
      // copy was rewritten to remove — so tightening here means re-running them
      // under the new profile and editing that constant in the same commit.
      "(allow mach-lookup)",
      // Launching apps through LaunchServices (`open -a Mail`, `open file.pdf`).
      // Without it LS refuses with -54 (permErr). The launched app runs
      // outside this profile. Note this does NOT make AppleScript work:
      // some apps refuse commands from any seatbelt-sandboxed sender
      // (-10004, Mail's compose among them), whatever the profile says —
      // even `(allow default)`. Scripting those needs `runAppleScript`.
      "(allow lsopen)",
      "(allow file-read-metadata)",
      "(allow file-ioctl)",
      "(allow file-read* " +
        [
          ...READ_BOILERPLATE.map((p) => `(subpath ${quote(p)})`),
          '(literal "/")',
          '(literal "/private")',
          '(literal "/private/var")',
          '(literal "/private/tmp")',
          '(literal "/tmp")',
          '(literal "/var")',
          '(literal "/etc")',
          '(literal "/Users")',
          '(literal "/dev/null")',
          '(literal "/dev/urandom")',
          '(literal "/dev/random")',
          '(literal "/dev/zero")',
          '(literal "/dev/tty")',
          '(subpath "/dev/fd")',
        ].join(" ") +
        ")",
      '(allow file-write-data (literal "/dev/null") (literal "/dev/tty") (subpath "/dev/fd"))',
    ];
    const home = canonicalize(args.home ?? os.homedir());
    // Broad READ of the user's home so tools installed under it and their
    // configs/libraries resolve. Writes stay scoped below — reads are the safe
    // capability here, and network is off unless approved.
    lines.push(`(allow file-read* (subpath ${quote(home)}))`);
    const housekeeping = ["Library/Caches", ".cache", ".config", ".local/state", ".npm"].map(
      (p) => home + "/" + p,
    );
    // A run that may be killed for going silent gets nothing persistent to
    // write, because it can be shot mid-write and nobody rolls that back. The
    // reads it loses with them are covered by the broad home grant above,
    // wherever those five resolve under home.
    const writable = [args.scratch, ...args.writePaths].concat(
      isReapable(args) ? [] : housekeeping,
    );
    for (const p of writable.map((p) => canonicalize(p))) {
      lines.push(`(allow file-write* (subpath ${quote(p)}))`);
      lines.push(`(allow file-read* (subpath ${quote(p)}))`);
    }
    for (const p of args.readPaths.map((p) => canonicalize(p))) {
      lines.push(`(allow file-read* (subpath ${quote(p)}))`);
    }
    if (args.network) {
      lines.push("(allow network*)");
      lines.push("(allow system-socket)");
    } else {
      lines.push("(deny network*)");
    }
    if (args.appleEvents) lines.push("(allow appleevent-send)");
    return lines.join("\n");
  },
};

/**
 * What the profile `SandboxProfile.generate` would build from these arguments
 * allows at one path — the same decision, asked after the fact.
 *
 * This is how a diagnosis (hostGate/diagnose.ts) tells "our seatbelt said no"
 * from "macOS said no": the app can open the path itself, and this says the
 * profile the run had would not have. Kept beside the generator so the two
 * cannot drift; it reads the same lists, in the same order, with the same
 * `isReapable` housekeeping rule. Paths in and out are canonical — the
 * roots exactly as the generator saw them when the profile was made, never
 * resolved again here (a run that has since replaced an approved path with
 * a symlink would otherwise widen its own approval to the link's target),
 * and a caller passes the path it already resolved.
 *
 * Reads are deliberately the generator's own over-approximation: broad home,
 * the boilerplate roots, and the literal directory entries the profile lists
 * one by one. Anything not named is denied, which is the profile's
 * `(deny default)`.
 */
export function sandboxGrants(
  args: {
    readPaths: string[];
    writePaths: string[];
    network: boolean;
    appleEvents: boolean;
    scratch: string;
    home?: string;
  },
  target: string,
  opts: { platform?: NodeJS.Platform } = {},
): { read: boolean; write: boolean } {
  const under = isLexicallyWithin;
  const platform = opts.platform ?? process.platform;
  if (platform === "win32") {
    // Answer the APPROVAL with Windows path rules even when this suite runs
    // on a POSIX host (injected `platform: "win32"`). Do not posix-canonicalize
    // synthetic `C:\…` strings — that would turn them into cwd-relative junk.
    const fold = (s: string) => s.replace(/\//g, "\\").normalize("NFC").toLowerCase();
    const within = (candidate: string, root: string) => {
      const p = fold(candidate);
      const r = fold(root);
      return p === r || p.startsWith(r.endsWith("\\") ? r : r + "\\");
    };
    const home = process.platform === "win32"
      ? canonicalize(args.home ?? os.homedir())
      : (args.home ?? "C:\\Users");
    const writeRoots = process.platform === "win32"
      ? writableRoots(args)
      : [args.scratch, ...args.writePaths];
    const readRoots = [home, ...writeRoots, ...args.readPaths];
    return {
      read: readRoots.some((root) => within(target, root)),
      write: writeRoots.some((root) => within(target, root)),
    };
  }
  const home = canonicalize(args.home ?? os.homedir());
  const writable = writableRoots(args);
  const write = writable.some((root) => under(target, root));
  if (platform === "linux") {
    // Linux bwrap+workspace answers the APPROVAL against host paths (the
    // child never opens them live). Bytewise, like seatbelt path roots.
    const readRoots = [home, ...writable, ...args.readPaths];
    return {
      read: write || readRoots.some((root) => under(target, root)),
      write,
    };
  }
  const readRoots = [...READ_BOILERPLATE, home, ...writable, ...args.readPaths, "/dev/fd"];
  const literals = new Set([
    "/", "/private", "/private/var", "/private/tmp", "/tmp", "/var", "/etc", "/Users",
    "/dev/null", "/dev/urandom", "/dev/random", "/dev/zero", "/dev/tty",
  ]);
  const read = write || literals.has(target) || readRoots.some((root) => under(target, root));
  return { read, write };
}

/**
 * The roots a profile lets a run write — and so everything a run, or a job
 * it left behind, could replace with a symlink while nobody is looking.
 * The diagnosis (hostGate/diagnose.ts) never opens a path under one by
 * name while the run that owns it may still be alive.
 */
export function writableRoots(args: {
  writePaths: string[];
  network: boolean;
  appleEvents: boolean;
  scratch: string;
  home?: string;
}): string[] {
  const home = canonicalize(args.home ?? os.homedir());
  const housekeeping = ["Library/Caches", ".cache", ".config", ".local/state", ".npm"].map(
    (p) => home + "/" + p,
  );
  return [args.scratch, ...args.writePaths].concat(isReapable(args) ? [] : housekeeping);
}

export class ExecutorError extends Error {}

/**
 * The Windows Job Object cage (@domo/native-winsandbox), when it is built
 * and we are on Windows, else null. Absent is not a fallback to uncaged
 * execution: `run` fails closed, because an approved command with no cage
 * is the guarantee this class exists to keep.
 */
interface WinSandbox {
  create(): number;
  assign(job: number, pid: number): void;
  close(job: number): void;
  appContainerAvailable(): boolean;
}

function winSandbox(): WinSandbox | null {
  try {
    const require_ = createRequire(import.meta.url);
    return require_("@domo/native-winsandbox") as WinSandbox | null;
  } catch {
    return null;
  }
}

/** The trusted helper shipped beside the native addon, never an agent path. */
function winLauncher(): string | null {
  try {
    const require_ = createRequire(import.meta.url);
    const addon = require_.resolve("@domo/native-winsandbox");
    // `unpackedPath`: a spawned .exe cannot live inside app.asar — asarPath.ts.
    const launcher = unpackedPath(
      path.join(path.dirname(addon), "build", "Release", "winsandbox_launcher.exe"),
    );
    return fs.existsSync(launcher) ? launcher : null;
  } catch {
    return null;
  }
}

/**
 * The Linux bubblewrap + cgroup cage (@domo/native-linuxsandbox), when it is
 * built and we are on Linux, else null. Absent is not a fallback to uncaged
 * execution: `run` fails closed.
 */
interface LinuxSandbox {
  available(): boolean;
}

function linuxSandbox(): LinuxSandbox | null {
  try {
    const require_ = createRequire(import.meta.url);
    return require_("@domo/native-linuxsandbox") as LinuxSandbox | null;
  } catch {
    return null;
  }
}

/** The trusted helper shipped beside the native addon, never an agent path. */
function linuxLauncher(): string | null {
  try {
    const require_ = createRequire(import.meta.url);
    const addon = require_.resolve("@domo/native-linuxsandbox");
    // `unpackedPath`: in a packaged app this resolves inside app.asar, and a
    // spawned executable cannot live there — see asarPath.ts. The real bytes
    // are the `.unpacked` sibling electron-builder's asarUnpack creates.
    const launcher = unpackedPath(
      path.join(path.dirname(addon), "build", "Release", "linuxsandbox_launcher"),
    );
    return fs.existsSync(launcher) ? launcher : null;
  } catch {
    return null;
  }
}

/**
 * Whether a run may be killed for going silent — and, because it is the same
 * question, whether it may be given anywhere persistent to write.
 *
 * Both callers derive it from the run's own capabilities rather than being
 * told: a profile that could be built "reapable" for a run the timer will
 * never touch, or the reverse, is a contradiction neither could detect.
 */
function isReapable(args: {
  writePaths: string[];
  network: boolean;
  appleEvents: boolean;
}): boolean {
  // `appleEvents` joins writes and network as a side-effect capability: an
  // osascript send changes another app's state, so a silent run must not be
  // SIGKILLed at 15 minutes and reported failed after it has already sent.
  return args.writePaths.length === 0 && !args.network && !args.appleEvents;
}

/**
 * How long a run that has produced NOTHING may stay alive before it is killed.
 *
 * macOS blocks — it does not refuse — an unconsented open of another app's
 * data: the child parks in `__guarded_open_np` waiting on a consent decision,
 * and on a Mac whose owner is not sitting in front of it nobody ever answers.
 * Nothing here used to end such a run, so the job answered `running` for the
 * life of the app while an agent polled it, and the process leaked with it.
 *
 * The bound has three halves and needs all of them. A ceiling alone would kill
 * honest long work: output handles never expire, so a build still running
 * after an hour is retrievable and must survive. `has produced no output`
 * separates those — a child that has written nothing at all by now is not
 * about to start. And the run must have been approved for neither writes nor
 * network, because those are the runs that can be silently mid-work here, and
 * a truncated copy or a half-applied remote call is worse than the wait.
 *
 * Nothing here reads CPU or idle time: this Mac legitimately runs
 * near-zero-CPU silent commands (an `ssh` waiting on a remote host), so
 * idleness is not evidence of anything.
 *
 * Fifteen minutes is a chosen literal, not a number computed from another:
 * long enough that a slow-but-real command is never the one being killed,
 * short enough that a wedged one is reported rather than waited on forever.
 */
const REAP_AFTER_MS = 15 * 60_000;

/**
 * How long output already in flight has to arrive once the command has exited.
 *
 * Normally `close` follows `exit` immediately and this never fires. It exists
 * for the run whose backgrounded job inherited the stdout pipe and is still
 * holding it: the command is over, so the job settles on this instead of
 * waiting on a pipe nobody is going to close. Settling closes the pipes, so a
 * background job still writing to them is broken by that — which is why
 * `plow_run_command` tells an agent to redirect anything meant to outlive its
 * command.
 */
const STDIO_DRAIN_MS = 250;

/**
 * What the agent is told about a run this Mac killed. It leads with the fact,
 * and names the cause that produces this shape — a permission prompt nobody
 * answered — as the likely one rather than the certain one, because from here
 * a blocked open and a genuinely mute command look identical.
 */
export const REAPED_MESSAGE =
  "killed by this Mac: the command produced no output and never exited. " +
  "The usual cause is a macOS permission prompt waiting for the Mac's owner to " +
  "answer it — reading another app's data needs a grant this app may not have " +
  "yet. Tell the user; re-running will block the same way until they grant it.";

export interface ExecResult {
  handle: string;
  running: boolean;
  exitCode: number | null;
  output: Buffer;
  outputLength: number;
  /** Just what the command wrote to stderr, whole — the diagnosis reads
   *  this and never `output`, where a program's own words could pass for
   *  this Mac's refusal. */
  stderr: Buffer;
  /** True when this Mac killed the run rather than the command ending. */
  reaped: boolean;
}

class OutputBuffer {
  /** Every chunk in arrival order, tagged by stream, so one list serves both views. */
  private chunks: { buf: Buffer; stdout: boolean }[] = [];
  private length = 0;
  exitCode: number | null = null;
  reaped = false;
  private waiters: ((exitCode: number) => void)[] = [];

  append(buf: Buffer, stdout: boolean): void {
    this.chunks.push({ buf, stdout });
    this.length += buf.length;
  }

  /** Just what the command wrote to stdout, whole. */
  stdout(): Buffer {
    return Buffer.concat(this.chunks.filter((c) => c.stdout).map((c) => c.buf));
  }

  /** Whether the command has written anything at all — the reaper's guard. */
  get produced(): boolean {
    return this.length > 0;
  }

  finish(exitCode: number): void {
    // Once only. The reaper settles a run without waiting for `close`, so a
    // straggler's later `close` must not rewrite an outcome already reported
    // to the agent and written to the audit log.
    if (this.exitCode !== null) return;
    this.exitCode = exitCode;
    // The outcome is handed to each waiter rather than read back off the
    // buffer, so no branch of this seam is in a position to invent one.
    const waiters = this.waiters;
    this.waiters = [];
    for (const w of waiters) w(exitCode);
  }

  snapshot(since: number): {
    output: Buffer;
    stderr: Buffer;
    total: number;
    running: boolean;
    exitCode: number | null;
    reaped: boolean;
  } {
    const all = Buffer.concat(this.chunks.map((c) => c.buf));
    const start = Math.min(Math.max(since, 0), all.length);
    return {
      output: all.subarray(start),
      stderr: Buffer.concat(this.chunks.filter((c) => !c.stdout).map((c) => c.buf)),
      total: all.length,
      running: this.exitCode === null,
      exitCode: this.exitCode,
      reaped: this.reaped,
    };
  }

  waitForExit(timeoutMs: number): Promise<boolean> {
    if (this.exitCode !== null) return Promise.resolve(true);
    if (timeoutMs <= 0) return Promise.resolve(false);
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), timeoutMs);
      timer.unref?.();
      this.waiters.push(() => {
        clearTimeout(timer);
        resolve(true);
      });
    });
  }

  onExit(cb: (exitCode: number, reaped: boolean) => void): void {
    if (this.exitCode !== null) {
      cb(this.exitCode, this.reaped);
      return;
    }
    this.waiters.push((code) => cb(code, this.reaped));
  }
}

/** The one place a buffer snapshot becomes the result callers see. */
function shape(snap: ReturnType<OutputBuffer["snapshot"]>): Omit<ExecResult, "handle"> {
  return {
    running: snap.running,
    exitCode: snap.exitCode,
    output: snap.output,
    outputLength: snap.total,
    stderr: snap.stderr,
    reaped: snap.reaped,
  };
}

/**
 * Runs approved commands caged per run — under /usr/bin/sandbox-exec with a
 * generated profile on macOS, in a Windows Job Object (kill-on-close plus a
 * process cap) on Windows — buffering merged stdout+stderr for the
 * plow_get_output streaming path.
 *
 * The cage differs per OS and says so: seatbelt confines files and (when
 * approved) network; the Job Object ends the whole tree with the run and
 * caps its process count, and does NOT confine files or network. File
 * writes stay approval-scoped through the in-process tools and the
 * diagnosis, which is why `grants` answers the approval on Windows rather
 * than a cage that is not there.
 */
export class Executor {
  private buffers = new Map<string, OutputBuffer>();
  /** What each run's profile was built from, kept so a diagnosis can ask
   *  after the fact what that profile allowed (`grants`). */
  private profiles = new Map<string, Parameters<typeof sandboxGrants>[0]>();
  /** Each run's Job Object id on Windows: closing it ends the run's whole
   *  tree (kill-on-close), which is the reaper's guarantee there. */
  private jobs = new Map<string, number>();
  /** Each run's process group (it is spawned as a session leader, so the
   *  group is its pid): what `mutableRoots` asks about after the command
   *  itself has exited, since a job it backgrounded lives on in it. */
  private groups = new Map<string, number>();
  /**
   * Holds: the paths a diagnosis's probes, or a file operation, are about
   * (hostGate/diagnose.ts `hold`, DeviceAgent.guardedFileOp). A run whose
   * profile could write one of them registers — its writable roots become
   * known — only once the hold is gone: a probe decides by the roots it can
   * see at that moment, and a run that appeared in between would be one it
   * never saw, free to rewrite the path it is about to open. Any other
   * run — read-only, or writing somewhere unrelated — registers at once;
   * a stalled read must not stop every command on the Mac. Registration
   * waits, never the hold: a run is delayed by a probe's timeout at most.
   */
  private holds = new Map<number, readonly string[]>();
  private nextHold = 0;
  private holdWaiters: (() => void)[] = [];

  /** Run `fn` with registration of any run that could write `paths` held off. */
  async holdProbes<T>(paths: readonly string[], fn: () => Promise<T>): Promise<T> {
    const id = ++this.nextHold;
    this.holds.set(id, [...paths]);
    try {
      return await fn();
    } finally {
      this.holds.delete(id);
      const waiters = this.holdWaiters;
      this.holdWaiters = [];
      for (const wake of waiters) wake();
    }
  }

  /** Whether a run with these writable roots could touch what a hold is about. */
  private conflicts(writable: readonly string[]): boolean {
    for (const paths of this.holds.values()) {
      for (const p of paths) {
        for (const w of writable) if (overlapsRoot(p, w) || overlapsRoot(w, p)) return true;
      }
    }
    return false;
  }

  constructor(
    public readonly scratchRoot: string,
    /** Overridden only by tests, which cannot wait out the real window. */
    private readonly reapAfterMs: number = REAP_AFTER_MS,
  ) {
    fs.mkdirSync(scratchRoot, { recursive: true });
  }

  async run(args: {
    argv: string[];
    cwd?: string;
    readPaths: string[];
    writePaths: string[];
    network: boolean;
    appleEvents: boolean;
    waitMs: number;
    /**
     * Extra environment for the child, merged over the curated set below.
     *
     * This is how a provider's CLI receives its token: in the child's
     * environment and nowhere else. A token on the command line lands in the
     * calling agent's captured output and from there in a persisted
     * transcript, where it outlives the token by a long way — and unlike argv,
     * a process environment is not readable through `ps`.
     *
     * Merged OVER the curated set, so a provider cannot be given a PATH or a
     * HOME of its choosing by way of this parameter — those are set after it.
     */
    env?: Readonly<Record<string, string>>;
  }): Promise<ExecResult> {
    if (args.argv.length === 0) throw new ExecutorError("launch failed: empty argv");
    const handle = crypto.randomUUID().toUpperCase();
    const scratch = path.join(this.scratchRoot, handle);
    fs.mkdirSync(scratch, { recursive: true });

    // cwd must be readable for the process to even start; it was part of the
    // approved exec capability, so allowing it matches the approval.
    const workingDir = args.cwd !== undefined ? canonicalize(args.cwd) : scratch;
    const reads = [...args.readPaths, workingDir];

    // Frozen as the generator saw them: canonical now, and never resolved
    // again. A later `grants()` asks what THIS profile allowed, and a run
    // that has since swapped an approved path for a symlink must not have
    // the answer follow the link (sandboxGrants).
    const profileArgs = {
      readPaths: reads.map((p) => canonicalize(p)),
      writePaths: args.writePaths.map((p) => canonicalize(p)),
      network: args.network,
      appleEvents: args.appleEvents,
      scratch: canonicalize(scratch),
    };
    // No new writer over what a hold is about, while it is out.
    while (this.conflicts(writableRoots(profileArgs))) await new Promise<void>((wake) => this.holdWaiters.push(wake));
    this.profiles.set(handle, profileArgs);
    // The cage is per-OS: seatbelt on macOS, Job Object + AppContainer on
    // Windows, bubblewrap + staged workspace on Linux. The approval bound in
    // `profiles` is recorded on all three, so the diagnosis asks one question.
    //
    // A provider's CLI reaches here with an absolute argv[0] under its staged
    // plugin's bin dir (the owner approved `plow-gog`; DeviceAgent resolves the
    // staged bytes), and the bin dir rides in `readPaths` so the Windows/Linux
    // workspace stages it like any other approved root.
    const argv = args.argv;
    if (process.platform === "win32") {
      return this.runWindows(handle, scratch, {
        argv,
        cwd: args.cwd === undefined ? undefined : workingDir,
        // `profileArgs` also contains this run's scratch.  It is not an
        // owner input and staging it would recursively copy the workspace
        // into itself, so feed only real approved/runtime roots here.
        readPaths: [...args.readPaths, ...(args.cwd === undefined ? [] : [workingDir])]
          .map((p) => canonicalize(p)),
        writePaths: args.writePaths.map((p) => canonicalize(p)),
        network: args.network,
        env: args.env,
        waitMs: args.waitMs,
        reapable: isReapable(args),
      });
    }
    if (process.platform === "linux") {
      return this.runLinux(handle, scratch, {
        argv,
        cwd: args.cwd === undefined ? undefined : workingDir,
        readPaths: [...args.readPaths, ...(args.cwd === undefined ? [] : [workingDir])]
          .map((p) => canonicalize(p)),
        writePaths: args.writePaths.map((p) => canonicalize(p)),
        network: args.network,
        env: args.env,
        waitMs: args.waitMs,
        reapable: isReapable(args),
      });
    }
    const profile = SandboxProfile.generate(profileArgs);
    if (process.env.DOMO_DEBUG_SANDBOX) {
      process.stderr.write(`=== PROFILE ===\n${profile}\n=== ARGV ===\n${args.argv.join(" ")}\n`);
    }

    return this.launch(handle, scratch, "/usr/bin/sandbox-exec", ["-p", profile, ...args.argv], {
      cwd: workingDir,
      env: args.env,
      waitMs: args.waitMs,
      reapable: isReapable(args),
    });
  }

  /**
   * Run an approved command on Windows: argv directly (no shell, no
   * sandbox-exec), caged in a Job Object. Fail CLOSED when the cage is not
   * here — an uncaged command is not a degraded command.
   */
  private runWindows(
    handle: string,
    scratch: string,
    args: {
      argv: string[];
      cwd?: string;
      readPaths: readonly string[];
      writePaths: readonly string[];
      network: boolean;
      env?: Readonly<Record<string, string>>;
      waitMs: number;
      reapable: boolean;
    },
  ): Promise<ExecResult> {
    const sandbox = winSandbox();
    if (!sandbox) {
      throw new ExecutorError(
        "command execution needs the Windows sandbox (@domo/native-winsandbox), which is not built on this host — " +
          "install the VS Build Tools and `npm rebuild @domo/native-winsandbox`",
      );
    }
    if (!sandbox.appContainerAvailable()) {
      throw new ExecutorError(
        "Windows command execution needs AppContainer, which this Windows installation does not provide; refusing an uncaged command",
      );
    }
    const launcher = winLauncher();
    if (!launcher) {
      throw new ExecutorError("Windows command execution needs the packaged AppContainer launcher; refusing an uncaged command");
    }
    const workspace = WindowsWorkspace.create({ scratch, readPaths: args.readPaths, writePaths: args.writePaths });
    const argv = args.argv.map((value) => workspace.rewrite(value));
    // An AppContainer must execute only a staged executable.  Keeping a host
    // executable in argv[0] would quietly recreate the broad runtime grant
    // this workspace boundary exists to remove.
    if (argv[0] === args.argv[0]) {
      throw new ExecutorError("Windows command executable is outside the approved staged workspace");
    }
    const cwd = args.cwd === undefined ? workspace.root : workspace.rewriteCwd(args.cwd);
    const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
    let config: string | null = null;
    try {
      config = writeWindowsLaunchConfig(scratch, {
        workspace: workspace.root,
        cwd,
        argv,
        network: args.network,
        env: {
          ...args.env,
          ComSpec: `${systemRoot}\\System32\\cmd.exe`,
          LOCALAPPDATA: workspace.root,
          OS: "Windows_NT",
          PATHEXT: ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL",
          Path: `${systemRoot}\\System32;${systemRoot}`,
          SystemDrive: path.parse(systemRoot).root.slice(0, -1),
          SystemRoot: systemRoot,
          TEMP: workspace.root,
          TMP: workspace.root,
          windir: systemRoot,
        },
      });
      return this.launch(handle, scratch, launcher, ["--config", config], {
        cwd: scratch,
        waitMs: args.waitMs,
        reapable: args.reapable,
        windowsAppContainerHelper: true,
        onCommandExited: () => workspace.reconcile(),
      });
    } catch (error) {
      if (config !== null) {
        try { fs.rmSync(config, { force: true }); } catch {}
      }
      throw error;
    }
  }

  /**
   * Run an approved command on Linux: argv directly (no shell), staged into
   * a bubblewrap workspace and caged with systemd-run TasksMax. Fail CLOSED
   * when the cage is not here — an uncaged command is not a degraded command.
   */
  private runLinux(
    handle: string,
    scratch: string,
    args: {
      argv: string[];
      cwd?: string;
      readPaths: readonly string[];
      writePaths: readonly string[];
      network: boolean;
      env?: Readonly<Record<string, string>>;
      waitMs: number;
      reapable: boolean;
    },
  ): Promise<ExecResult> {
    const sandbox = linuxSandbox();
    if (!sandbox) {
      throw new ExecutorError(
        "command execution needs the Linux sandbox (@domo/native-linuxsandbox), which is not built on this host — " +
          "install a C++ toolchain, bubblewrap, and `npm rebuild @domo/native-linuxsandbox`",
      );
    }
    if (!sandbox.available()) {
      throw new ExecutorError(
        "Linux command execution needs bubblewrap and a systemd user session with TasksMax; " +
          "refusing an uncaged command",
      );
    }
    const launcher = linuxLauncher();
    if (!launcher) {
      throw new ExecutorError("Linux command execution needs the packaged bubblewrap launcher; refusing an uncaged command");
    }
    const workspace = LinuxWorkspace.create({ scratch, readPaths: args.readPaths, writePaths: args.writePaths });
    const argv = args.argv.map((value) => workspace.rewrite(value));
    if (argv[0] === args.argv[0]) {
      throw new ExecutorError("Linux command executable is outside the approved staged workspace");
    }
    const cwd = args.cwd === undefined ? workspace.root : workspace.rewriteCwd(args.cwd);
    let config: string | null = null;
    try {
      config = writeLinuxLaunchConfig(scratch, {
        workspace: workspace.root,
        cwd,
        argv,
        network: args.network,
        env: {
          ...args.env,
          HOME: workspace.root,
          TMPDIR: workspace.root,
          TMP: workspace.root,
          TEMP: workspace.root,
          PATH: ["/usr/bin", "/bin", "/usr/sbin", "/sbin"].join(":"),
          LANG: "en_US.UTF-8",
        },
      });
      return this.launch(handle, scratch, launcher, ["--config", config], {
        cwd: scratch,
        waitMs: args.waitMs,
        reapable: args.reapable,
        linuxBwrapHelper: true,
        onCommandExited: () => workspace.reconcile(),
      });
    } catch (error) {
      if (config !== null) {
        try { fs.rmSync(config, { force: true }); } catch {}
      }
      throw error;
    }
  }

  /**
   * Run an AppleScript with /usr/bin/osascript, NOT under sandbox-exec.
   *
   * Deliberate, and the only unsandboxed execution in this process: some
   * apps refuse commands from any seatbelt-sandboxed sender whose own code
   * signature lacks an apple-events entitlement (-10004, whatever the profile
   * says — verified with `(allow default)`), and osascript is Apple's binary,
   * so no profile can admit it. The gates are the decision this intent
   * carried (under Ask or the AI Reviewer, someone read the whole script;
   * Approve allows it unread) and TCC's Automation grant for the responsible
   * process — the app bundle, or the terminal that ran it
   * from source. The script is written to this run's scratch dir, 0600,
   * rather than passed as an argument, so it never shows up in `ps` output or
   * a too-long-argv failure. Its `args` do: they follow the file, which ends
   * osascript's option parsing, so each reaches `on run argv` as a value
   * (one starting with `-` included), never pasted into the source.
   *
   * Never reapable: a script that has sent an event has changed another
   * app's state, the same reason an `apple_events` command is exempt.
   */
  async runAppleScript(run: { script: string; args: readonly string[]; waitMs: number }): Promise<ExecResult> {
    // osascript is macOS-only, and so is the unsandboxed-AppleScript tool
    // built on it (mcp-server registers `plow_run_applescript` on darwin
    // only). Refusing here as well as there keeps a direct caller from
    // reaching a binary that does not exist.
    if (process.platform !== "darwin") {
      throw new ExecutorError("AppleScript runs on macOS only; this host has no osascript");
    }
    const handle = crypto.randomUUID().toUpperCase();
    const scratch = path.join(this.scratchRoot, handle);
    fs.mkdirSync(scratch, { recursive: true });
    const file = path.join(scratch, "script.applescript");
    fs.writeFileSync(file, run.script, { mode: 0o600 });
    // By its bare name, from the scratch dir: osascript prefixes every error
    // with the script's path as given, and the agent's output should read
    // `script.applescript:6:56: execution error: …`, not this Mac's
    // application-support path.
    return this.launch(handle, scratch, "/usr/bin/osascript", [path.basename(file), ...run.args], {
      cwd: scratch,
      waitMs: run.waitMs,
      reapable: false,
    });
  }

  /**
   * Spawn `command`, buffer its merged output under `handle`, wait up to
   * `waitMs`, and answer with a snapshot. Everything a run needs once its
   * profile (if any) is decided: the curated environment, the process group,
   * the settle/abandon/reaper bookkeeping.
   */
  private async launch(
    handle: string,
    scratch: string,
    command: string,
    argv: string[],
    opts: {
      cwd: string;
      env?: Readonly<Record<string, string>>;
      waitMs: number;
      reapable: boolean;
      /** Helper owns the inner AppContainer Job; do not add a second one. */
      windowsAppContainerHelper?: boolean;
      /** Helper owns the bwrap + systemd-run cage; do not add a second one. */
      linuxBwrapHelper?: boolean;
      /** Runs only after the helper waited for its caged tree. */
      onCommandExited?: () => void;
    },
  ): Promise<ExecResult> {
    const realHome = os.homedir();
    const buffer = new OutputBuffer();
    this.buffers.set(handle, buffer);

    // The Linux helper talks to the user's systemd bus; stripping
    // DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR from its environment makes
    // every cage launch fail closed for the wrong reason.
    const linuxHelperEnv = opts.linuxBwrapHelper
      ? {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          HOME: realHome,
          ...(process.env.DBUS_SESSION_BUS_ADDRESS
            ? { DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS }
            : {}),
          ...(process.env.XDG_RUNTIME_DIR
            ? { XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR }
            : {}),
          ...(process.env.XDG_SESSION_TYPE
            ? { XDG_SESSION_TYPE: process.env.XDG_SESSION_TYPE }
            : {}),
        }
      : null;

    const child = spawn(command, argv, {
      cwd: opts.cwd,
      env:
        process.platform === "win32"
          ? {
              ...opts.env,
              // Curated: the system directories a console tool needs. A
              // provider's CLI does not ride on PATH — it reaches the child
              // as an absolute argv[0] under its staged plugin's bin dir, so
              // which binary a name reaches is never a PATH question here.
              // TEMP/TMP stay in the disposable scratch dir. No HOME
              // override — Windows tools read USERPROFILE, which is the
              // owner's real one. PATHEXT/SYSTEMROOT-shape variables are the
              // world, not secrets: without PATHEXT even `where` cannot
              // resolve an extension.
              Path: [
                `${process.env.SystemRoot ?? "C:\\Windows"}\\System32`,
                process.env.SystemRoot ?? "C:\\Windows",
                `${process.env.SystemRoot ?? "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0`,
              ].join(";"),
              TEMP: scratch,
              TMP: scratch,
              SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
              windir: process.env.SystemRoot ?? "C:\\Windows",
              OS: "Windows_NT",
              PATHEXT: ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL",
            }
          : linuxHelperEnv ?? {
              ...opts.env,
        // Real home so tools and their configs resolve; TMPDIR stays in the
        // (writable, disposable) scratch dir; PATH includes the user bin dirs.
        // These come AFTER the caller's env deliberately: a provider supplies
        // its token, never the shape of the world its child runs in.
        PATH:
          [
            `${realHome}/.local/bin`,
            `${realHome}/bin`,
            `${realHome}/.cargo/bin`,
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
          ].join(":"),
        HOME: realHome,
        TMPDIR: scratch,
        LANG: "en_US.UTF-8",
      },
      stdio: ["ignore", "pipe", "pipe"],
      // Its own process group, purely so the reaper below can take the whole
      // run. `sandbox-exec` execs into the approved argv, and that argv is
      // routinely a shell: `/bin/sh -c 'a && b'` does NOT exec, so signalling
      // one pid kills the shell and leaves the wedged descendant holding the
      // stdout pipe — which is the bug, not the fix.
      //
      // This is `setsid`, so a run also leaves the app's session and stops
      // receiving its terminal signals — a Ctrl-C on `just app` no longer
      // reaches one. Accepted knowingly: nothing here has ever killed live
      // children at quit (the packaged app has no terminal to signal it), so
      // the sweep that would is its own change, not a side effect of this one.
      //
      // Windows is the exception: `detached` there means DETACHED_PROCESS
      // (no console), under which console tools exit at once having done
      // nothing — measured with powershell, 0.15s and exit 0. The Job Object
      // is already the run's grouping there, so the child spawns attached
      // and windowless instead (no console flash under the GUI app either).
      detached: process.platform !== "win32",
      windowsHide: process.platform === "win32",
    });
    if (child.pid !== undefined) this.groups.set(handle, child.pid);
    // On Windows the cage is a Job Object, attached the moment the child
    // exists: closing it ends the run's whole tree (kill-on-close), which
    // is what the reaper's guarantee rests on there. `runWindows` already
    // refused to launch without the addon, so a null here is unreachable —
    // and still fails closed rather than running uncaged.
    if (process.platform === "win32" && child.pid !== undefined && !opts.windowsAppContainerHelper) {
      const cage = winSandbox();
      if (!cage) throw new ExecutorError("lost the Windows sandbox between check and launch");
      try {
        const job = cage.create();
        cage.assign(job, child.pid);
        this.jobs.set(handle, job);
      } catch (error) {
        throw new ExecutorError(
          `could not cage the run in a Job Object: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    // A run ends when its COMMAND ends. `close` says something else — every
    // stdio pipe closed too — and a job the command backgrounded inherits
    // those pipes and can hold them open forever. Settling on `exit` is what
    // keeps "the command finished" from meaning "and nothing it started is
    // still around", which is not this Mac's promise to keep and was three
    // rounds of holes in one predicate when the reaper tried to keep it.
    let reaper: ReturnType<typeof setTimeout> | undefined;
    let abandoned = false;
    // Settling CLOSES the capture, on every path into it. A run that has been
    // answered must stop growing, and the read ends of its pipes must not stay
    // attached for the life of the app because something the command left
    // behind is still holding the write ends. That the capture closes is why
    // nothing downstream needs a guard against late output.
    const settle = (code: number) => {
      clearTimeout(reaper);
      // The cage closes with the capture, on every path: on Windows that
      // ends the run's whole tree (kill-on-close), including anything the
      // command backgrounded. That differs from macOS, where a backgrounded
      // job outlives the run — a Windows run's tree ends with the run, and
      // long-lived servers belong in a service, not a background job.
      // Answered first, closed second, both in one synchronous breath: nothing
      // can append between the two statements, and everything downstream that
      // asks "is this run still open?" — `abandon`'s kill above all — gets the
      // right answer for anything the destroys themselves emit. `finally`
      // because `finish` runs the `onExit` waiters: closing the capture is not
      // theirs to skip by throwing.
      try {
        buffer.finish(code);
      } finally {
        child.stdout?.destroy();
        child.stderr?.destroy();
        this.closeJob(handle);
      }
    };
    child.on("error", () => settle(-1));
    child.on("exit", (code, signal) => {
      let outcome = code ?? (signal ? -1 : 0);
      // The helper does not exit until its own Job has no descendants. This
      // is the sole point at which staged output may safely meet owner paths.
      if (!abandoned && opts.onCommandExited) {
        try {
          opts.onCommandExited();
        } catch {
          outcome = -1;
        }
      }
      // Output already written may still be in flight, so the usual `close`
      // remains the settling event — with a deadline, because a straggler
      // holding a pipe must not hold the agent with it. Output not delivered
      // by then is dropped: this deadline is the end of the run.
      const drain = setTimeout(() => settle(outcome), STDIO_DRAIN_MS);
      drain.unref?.();
      child.on("close", () => {
        clearTimeout(drain);
        settle(outcome);
      });
    });

    // Ending a run early ends its PROCESS too. Both paths that do it — the
    // reaper, and a capture that broke — answer the caller and disarm the
    // reaper as they go, so a run left alive on either would be alive,
    // unkillable and untracked: exactly what this whole change is against.
    //
    // The kill applies only while the run is still open, which makes this as
    // idempotent as the `settle` it ends with. After a run is answered its
    // group is not ours to signal: the pid may have been reaped and its pgid
    // reused, and a job that redirected both streams is one this Mac has
    // promised will outlive the run that started it.
    //
    // That guard shares the stream-error handler's untested status — the only
    // caller that reaches here after a run is answered — so the survivor test
    // in `executorReap.test.ts` pins the promise, not this line.
    const abandon = (code: number) => {
      abandoned = true;
      if (buffer.exitCode === null && child.pid !== undefined) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          // Already gone, or a group that no longer exists. Settling is what
          // the caller is owed either way.
        }
      }
      settle(code);
    };

    // What is left for the reaper is the one case `exit` cannot answer: a
    // command that never ends at all — and only where killing it can cost
    // nothing. A run that was approved to write or to reach the network can
    // be silently mid-work at the deadline: killing a large copy truncates
    // its destination, and killing a series of remote calls leaves them half
    // applied, neither of which anyone rolls back.
    //
    // What makes the other runs safe to kill is NOT that they declared no
    // writes — that alone was never enough, since every profile used to hand
    // out the housekeeping grant. It is that `isReapable` decided the profile
    // too: a run this timer can fire on was given nowhere persistent to write,
    // and the scratch it does have is deleted below. The two must stay one
    // decision. It is also the shape the observed failure had — a
    // `sqlite3 -readonly` blocked on a consent prompt.
    //
    // Say plainly what that costs, because there is no cancel affordance to
    // soften it: a wedged run with side-effect capability stays alive and
    // untracked, its `exec_start` unpaired, until someone kills the process
    // from a terminal. Issue #178 is the owner-facing way to end a run.
    //
    // SIGKILL rather than a polite SIGTERM —
    // it is wedged in a kernel call with nothing to clean up, and a handler
    // that never gets scheduled would only leave the same process on the
    // table. The group, not the pid, because `sandbox-exec` execs into the
    // approved argv and that argv is routinely a shell: `/bin/sh -c 'a && b'`
    // does NOT exec, so one signal kills the shell and leaves the wedged
    // descendant alive.
    if (opts.reapable) {
      reaper = setTimeout(() => {
        if (buffer.exitCode !== null || buffer.produced) return;
        buffer.reaped = true;
        // `abandon` can only throw through an `onExit` waiter and the sole
        // registrant catches its own, so the `finally` is here to make the
        // deletion unskippable rather than because a throw is expected.
        try {
          abandon(-1);
        } finally {
          // The run is dead and its output is already in memory. Its scratch is
          // the one place it could have left half of something — `TMPDIR` points
          // there and it is the only writable path a reapable run has — so the
          // half goes with it.
          //
          // Async, and with retries. Scratch holds whatever the run was
          // writing, which is unbounded (the WhatsApp fallback copies an entire
          // archive through here), and a synchronous walk over that would stall
          // every other run's budget timer, the relay socket and the approval
          // window — the same reason file operations in this codebase are async
          // and size-capped. `maxRetries` is for the descendant still writing
          // as we walk: `kill` returns before the group is gone, and `force`
          // covers ENOENT, not the ENOTEMPTY of a file created mid-walk. The
          // empty callback is the last resort — a scratch that outlives its run
          // is issue #153's standing state, and nothing here waits on it.
          fs.rm(scratch, { recursive: true, force: true, maxRetries: 3 }, () => {});
        }
      }, this.reapAfterMs);
      reaper.unref?.();
    }

    // Optional throughout: a spawn that never got as far as its stdio — the
    // fd exhaustion this reaper exists to make rarer — leaves these null and
    // emits `error` on the next tick, where a throw is nobody's to catch.
    for (const stream of [child.stdout, child.stderr]) {
      stream?.on("data", (chunk: Buffer) => buffer.append(chunk, stream === child.stdout));
      // A pipe error ENDS the run rather than being swallowed: the stream is
      // auto-destroyed either way, so capture has stopped, and reporting the
      // command's own `exit 0` over a silently truncated answer is the worse
      // of the two. It goes through `abandon` because answering the caller
      // disarms the reaper, and a wedged command that outlived its own
      // capture is precisely what must not survive that.
      //
      // Deliberately untested: reaching it needs a seam for injecting a
      // stream error, and this is not worth an injectable spawn.
      stream?.on("error", () => abandon(-1));
    }

    await buffer.waitForExit(Math.max(opts.waitMs, 0));
    return { handle, ...shape(buffer.snapshot(0)) };
  }

  /**
   * What the profile this run had would allow at `path` — the question a
   * diagnosis asks to tell our own seatbelt's refusal from macOS's. Answered
   * from the arguments the profile was generated from, so the two agree by
   * construction.
   */
  grants(handle: string, path: string): { read: boolean; write: boolean } {
    const args = this.profiles.get(handle);
    if (!args) throw new ExecutorError(`unknown output handle: ${handle}`);
    return sandboxGrants(args, path);
  }

  /** What one run's profile lets it write (see `writableRoots`). */
  writableRoots(handle: string): string[] {
    const args = this.profiles.get(handle);
    return args ? writableRoots(args) : [];
  }

  /**
   * What every run that is still going — or anything a run left behind —
   * could write right now: the roots a diagnosis of anything, a file op
   * included, must not open by name. A command's exit is not the end of
   * its run's hands on the disk: a job it backgrounded keeps its process
   * group alive, and the group is asked (a signal 0 to it) rather than the
   * command's exit code.
   */
  mutableRoots(): string[] {
    const roots: string[] = [];
    for (const [handle, buffer] of this.buffers) {
      if (buffer.exitCode === null || this.groupAlive(handle)) roots.push(...this.writableRoots(handle));
    }
    return roots;
  }

  /** Whether any process of the run's group still exists. */
  private groupAlive(handle: string): boolean {
    const pid = this.groups.get(handle);
    if (pid === undefined) return false;
    try {
      // Negative pids signal groups, which Windows does not have: a signal
      // 0 to the pid itself asks the only question that matters there.
      if (process.platform === "win32") {
        process.kill(pid, 0);
        return true;
      }
      process.kill(-pid, 0);
      return true;
    } catch (error: unknown) {
      // ESRCH: no such group — every member is gone. Anything else (EPERM,
      // a member no longer ours) means something is still there.
      return (error as { code?: unknown })?.code !== "ESRCH";
    }
  }

  /** Close one run's Job Object, exactly once. Closing the last handle ends
   *  the run's whole tree; settling already answered the caller, so nothing
   *  here can throw it off. */
  private closeJob(handle: string): void {
    const job = this.jobs.get(handle);
    if (job === undefined) return;
    this.jobs.delete(handle);
    try {
      winSandbox()?.close(job);
    } catch {
      // The run is answered and its pipes are destroyed; a job that will
      // not close is the OS's to reap with the process, not the caller's.
    }
  }

  /** Invoke cb when the run exits — immediately if it already has. */
  onExit(handle: string, cb: (exitCode: number, reaped: boolean) => void): void {
    this.buffer(handle).onExit(cb);
  }

  output(handle: string, since: number): ExecResult {
    return { handle, ...shape(this.buffer(handle).snapshot(since)) };
  }

  /**
   * A run's stdout alone, whole — for the callers that PARSE a command's
   * answer (the gog fan-out, the calendar conflict probe) rather than show
   * it. `output` merges stderr in because the `plow_get_output` stream needs
   * one ordered transcript, and is sliced from `since`; a stdout slice at
   * that offset would mean nothing, so this is an accessor, not a field.
   */
  stdout(handle: string): Buffer {
    return this.buffer(handle).stdout();
  }

  private buffer(handle: string): OutputBuffer {
    const buffer = this.buffers.get(handle);
    if (!buffer) throw new ExecutorError(`unknown output handle: ${handle}`);
    return buffer;
  }
}
