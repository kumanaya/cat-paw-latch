/**
 * A packaged renderer is not TypeScript output: its HTML, CSS and plain JS
 * have to be copied from src/renderer.  electron-builder can be invoked
 * directly by CI or a local release engineer, so this belongs at the pack
 * boundary instead of relying on a preceding convenience recipe.
 */
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

module.exports = async function beforePack() {
  const desktop = path.join(__dirname, "..");
  execFileSync(process.execPath, [path.join(desktop, "scripts", "copy-renderer.mjs")], {
    cwd: desktop,
    stdio: "inherit",
  });
  for (const file of ["index.html", "main.js", "styles.css"]) {
    const rendered = path.join(desktop, "dist", "renderer", file);
    if (!fs.existsSync(rendered) || fs.statSync(rendered).size === 0) {
      throw new Error(`[beforePack] renderer asset is missing: ${file}`);
    }
  }
};
