// Give electronmon one stable file change after a development rebuild.
//
// Renderer assets are copied as a directory, which can produce many file-system
// events. The renderer signal collapses those into one window reload. TypeScript
// uses the real main entry as its signal so electronmon restarts the Electron
// process after every successful compilation, including changes to ESM imports
// that its CommonJS dependency hook cannot discover.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const mode = process.argv[2];
const dir = path.dirname(fileURLToPath(import.meta.url));
const dist = path.resolve(dir, "../dist");

if (mode === "main") {
  const main = path.join(dist, "main.js");
  fs.utimesSync(main, new Date(), new Date());
} else if (mode === "renderer") {
  fs.writeFileSync(path.join(dist, "renderer.reload"), `${Date.now()}\n`, "utf8");
} else {
  throw new Error("usage: signal-dev-reload.mjs <main|renderer>");
}
