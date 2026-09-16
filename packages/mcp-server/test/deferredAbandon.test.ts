/**
 * A deferred handle when the app that minted it closes.
 *
 * The store is in memory; the note on disk is what keeps a call whose app was
 * quit, crashed or updated out of the `unknown` bucket — the agent cannot tell
 * "never existed" from "may have run" otherwise, and those need different
 * next moves.
 */
import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { jv } from "@domo/protocol";
import { DeferredResults } from "@domo/mcp-server";

const dirs: string[] = [];
const tmp = (): string => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "latch-deferred-"));
  dirs.push(d);
  return d;
};
afterEach(() => {
  while (dirs.length) fs.rmSync(dirs.pop()!, { recursive: true, force: true });
});

/** A call that never settles: the budget expires and a handle is minted. */
const neverSettles = (): Promise<never> => new Promise(() => {});

describe("a handle whose app closed", () => {
  it("answers abandoned once on the next start, then unknown", async () => {
    const state = tmp();
    const first = new DeferredResults(10, undefined, undefined, state);
    const pending = jv(await first.run("agent-1", neverSettles));
    const handle = pending.get("handle").str!;
    expect(pending.get("status").str).toBe("pending");
    // The note exists while the call is in flight, and names its owner.
    expect(fs.readdirSync(state)).toEqual([`${handle}.json`]);

    // The app closes under it; the next process opens the same directory.
    const second = new DeferredResults(10, undefined, undefined, state);
    const answer = jv(second.get("agent-1", handle));
    expect(answer.get("status").str).toBe("abandoned");
    expect(answer.get("reason").str).toContain("may or may not have run");
    // Answered once: the note is consumed, and a second poll is a handle that
    // no longer exists anywhere.
    expect(jv(second.get("agent-1", handle)).get("status").str).toBe("unknown");
  });

  it("never hands another agent the abandoned answer", async () => {
    const state = tmp();
    const first = new DeferredResults(10, undefined, undefined, state);
    const handle = jv(await first.run("agent-1", neverSettles)).get("handle").str!;
    const second = new DeferredResults(10, undefined, undefined, state);
    expect(jv(second.get("agent-2", handle)).get("status").str).toBe("unknown");
    // ...and the owner can still retrieve it afterwards.
    expect(jv(second.get("agent-1", handle)).get("status").str).toBe("abandoned");
  });

  it("leaves nothing on disk once the work settles", async () => {
    const state = tmp();
    const store = new DeferredResults(10, undefined, undefined, state);
    // A result that lands inside the budget mints no handle and writes nothing.
    const fast = jv(await store.run("agent-1", async () => ({ ok: true })));
    expect(fast.get("status").str).toBe("completed");
    expect(fs.existsSync(state) ? fs.readdirSync(state) : []).toEqual([]);

    // A handle that outlives the budget writes its note, and the terminal
    // landing removes it — so the next start has nothing to report orphaned.
    let settle!: (value: { status: string }) => void;
    const work = new Promise<{ status: string }>((resolve) => {
      settle = resolve;
    });
    const pending = jv(await store.run("agent-1", () => work));
    const handle = pending.get("handle").str!;
    expect(fs.readdirSync(state)).toEqual([`${handle}.json`]);
    settle({ status: "completed" });
    await new Promise((resolve) => setImmediate(resolve));
    expect(fs.readdirSync(state)).toEqual([]);
    expect(jv(store.get("agent-1", handle)).get("status").str).toBe("ready");
  });
});
