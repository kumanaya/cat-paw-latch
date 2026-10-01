/**
 * What this host is called, in the sentences the owner and the agent read.
 *
 * "this Mac" was the app's only phrasing while the Mac was the only host. The
 * fork ships Windows and Linux, and an agent told "plow-gog is not installed
 * on this Mac" while it is running on a Windows PC is reading a sentence about
 * a machine it is not on — the refusal names the wrong host, which is the one
 * fact in it that has to be right.
 *
 * ONE owner for the noun, so a fix lands everywhere at once: the browser
 * skill already rewrote its prose per host (`browser/browsingSkill.ts`), and
 * it reads its noun from here rather than keeping a second spelling of the
 * same two words.
 */

/** The host as a sentence names it: "Mac", "Windows PC", "Linux PC". */
export const hostNoun = (platform: NodeJS.Platform = process.platform): string =>
  platform === "darwin" ? "Mac" : platform === "linux" ? "Linux PC" : platform === "win32" ? "Windows PC" : "PC";
