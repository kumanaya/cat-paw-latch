/**
 * What this host actually lets a command reach — one skill, per host.
 *
 * The Mac answers "act on this machine" with `plow_run_applescript`. The other
 * two hosts answer it with a cage, and each cage has an edge the agent keeps
 * walking into:
 *
 * - Windows runs every command in an AppContainer that stages only the owner's
 *   approved roots. A host executable in argv[0] is REFUSED by name
 *   (`executor.ts`) — and it is refused on purpose: staging `powershell.exe`
 *   would hand the container the System32 runtime, which is exactly the broad
 *   grant the workspace exists to withhold.
 * - Linux runs commands from the standard system paths, but withholds the
 *   desktop SESSION: `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` go to
 *   the cage launcher, never to the agent's child. So a notification, the
 *   clipboard and a screenshot are unreachable, and wiring them through would
 *   hand a caged agent the owner's desktop.
 *
 * This is a SKILL and not a plugin because there is nothing new to stage: the
 * capability is `plow_run_command` and `plow_read_file`/`plow_write_file`,
 * already there. What was missing was the agent knowing which of them reach
 * anything here — without it, every attempt costs a run and then a second one
 * guessing.
 *
 * Each boundary below was exercised on the host it names. Nothing is listed
 * that was not run, because a skill that teaches a spelling nobody checked is
 * worse than no skill.
 */
import { SkillRegistry, type Skill } from "./skills.js";
import { hostNoun } from "./host.js";

/** What any host can do, whatever its cage. */
const COMMON = `## What works on every host

- \`plow_read_file\` and \`plow_write_file\`, inside the owner's Plow folder
  (\`plow-folder\` names it) — approved without a dialog.
- \`plow_run_command\` for commands the owner's approval covers.
- The browser (\`plow_browser_open\`), in its own isolated session.
- The owner's own integrations, which arrive as commands of their own — Gmail
  and Calendar today (\`plow-gog\`), each listed in the Plugins tab.

## Ground rules

- Never claim you did something before the owner approved it. Approval is the
  card; the run is after it.
- If a command is refused, say what the refusal said. Do not try a second
  spelling: a refused one that turns out to be allowed the next time acts
  twice.`;

const DARWIN = `The Mac has a tool for this: \`plow_run_applescript\`. AppleScript drives
any app on the desktop — Mail, Messages, Finder, Shortcuts, System Events —
in one approved call, which no shell command comes close to. Use it; do not
improvise a shell command for something it covers.`;

const WINDOWS = `## You cannot run a program on this PC

Every command runs inside an AppContainer that holds only the owner's approved
folders. A host program — \`powershell\`, \`msg\`, \`notepad\`, anything under
System32 — is refused by name before it starts, and this is deliberate: giving
the container a system executable would hand it the whole runtime it is built
to withhold.

So there is no command here that notifies the owner, opens an app, reads the
clipboard or takes a screenshot. Do not spend runs discovering that, and do
not tell the owner the app is broken.

What reaches this PC instead: files in the Plow folder, and the browser in its
own isolated session.

If the owner asks for something only a desktop program can do, say so and let
them do it — do not try to route around the container.`;

const LINUX = `## What the cage withholds here

Commands run from the standard system paths, so ordinary shell work is fine.
What is NOT reachable is the desktop session: the session bus and the
Wayland/X11 socket are given to the cage launcher, never to your command.

So a desktop notification, the clipboard and a screenshot are not available,
and no amount of retrying will change that. It is a boundary, not a bug: do
not try to route around it, and do not report the app as broken.

## Opening a link for the owner

Ask first, then hand them the link. Opening it yourself needs a desktop
session this cage does not give you.`;

const HOSTS: Record<string, string> = { darwin: DARWIN, win32: WINDOWS, linux: LINUX };

/** The skill for one host. */
export function sysSkillFor(platform: NodeJS.Platform = process.platform): Skill {
  const own = HOSTS[platform];
  const host = hostNoun(platform);
  return {
    name: "sys",
    description:
      platform === "darwin"
        ? "Act on this Mac itself: plow_run_applescript reaches every app on the desktop."
        : `What a command on this ${host} can and cannot reach — the cage's edges, and what to ` +
          `use instead. Read this before trying to run a program here.`,
    body:
      `# Running things on this ${host}\n\n` +
      (own ?? "Commands run under the owner's approval, with no desktop access beyond it.") +
      `\n\n${COMMON}`,
  };
}

/** Register it. One host's skill, always — the fork's three hosts each get theirs. */
export function registerSysSkill(skills: SkillRegistry, platform: NodeJS.Platform = process.platform): void {
  skills.register(sysSkillFor(platform));
}
