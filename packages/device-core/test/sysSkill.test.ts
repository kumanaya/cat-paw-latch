/**
 * The host's own boundary, as one skill per host.
 *
 * What is pinned is each cage's edge, because that is the fact an agent gets
 * wrong: it is told "run a program", spends a run being refused, and spends a
 * second guessing. The three hosts are named explicitly, so this runs on any
 * CI leg and asserts all three at once.
 */
import { describe, expect, it } from "vitest";
import { hostNoun, sysSkillFor } from "@domo/device-core";

describe("hostNoun", () => {
  it("names the host the fork actually ships", () => {
    expect(hostNoun("darwin")).toBe("Mac");
    expect(hostNoun("win32")).toBe("Windows PC");
    expect(hostNoun("linux")).toBe("Linux PC");
  });

  it("reads as a sentence after 'this'", () => {
    for (const platform of ["darwin", "win32", "linux"] as const) {
      expect(`on this ${hostNoun(platform)}`).toMatch(/this (Mac|Windows PC|Linux PC)$/);
    }
  });
});

describe("the sys skill", () => {
  it("gives the Mac its own tool rather than a shell command to replace it", () => {
    const mac = sysSkillFor("darwin");
    expect(mac.name).toBe("sys");
    expect(mac.body).toContain("plow_run_applescript");
    // The point of that tool is that no shell command reaches those apps; a
    // list beside it would read as an equal alternative.
    expect(mac.body).not.toMatch(/osascript|powershell|xdg-open/);
  });

  it("tells a Windows agent up front that no host program runs here", () => {
    const win = sysSkillFor("win32");
    expect(win.description).toContain("this Windows PC");
    // The refusal is real and by name (executor.ts), so the skill has to name
    // the same programs the agent would otherwise try first — and refuse them
    // in prose rather than in a run.
    for (const refused of ["powershell", "msg", "notepad"]) expect(win.body).toContain(refused);
    expect(win.body).toMatch(/refused by name/i);
    // Prose wraps; the assertion is about the sentence, not where it broke.
    expect(win.body).toMatch(/do\s+not tell the owner the app is broken/i);
  });

  it("never teaches a Windows spelling that the AppContainer refuses", () => {
    // The commands a Windows agent would reach for, each of which cannot run.
    // One of them in a code fence is an instruction, not a warning.
    const win = sysSkillFor("win32").body;
    expect(win).not.toMatch(/^\s*(msg|powershell|notepad|start)\b.*$/m);
    expect(win).not.toMatch(/Get-Clipboard|Set-Clipboard|CopyFromScreen|Start-Process/);
  });

  it("names the desktop session as the Linux edge, without promising a tool", () => {
    const linux = sysSkillFor("linux").body;
    expect(linux).toMatch(/session bus|Wayland\/X11/);
    // None of these are guaranteed to be installed on a Linux host, and the
    // session they need is withheld either way — so the skill names the
    // boundary, not a command whose presence it cannot know.
    for (const tool of ["notify-send", "wl-paste", "xclip", "grim", "spectacle"]) {
      expect(linux).not.toContain(tool);
    }
  });

  it("points every host at what does work here", () => {
    for (const platform of ["darwin", "win32", "linux"] as const) {
      const body = sysSkillFor(platform).body;
      expect(body).toContain("plow_read_file");
      expect(body).toContain("plow-gog");
      // Approval comes first, always: the run is after the card.
      expect(body).toMatch(/before the owner approved/i);
    }
  });
});
