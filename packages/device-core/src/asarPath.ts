/**
 * A path resolved from a dependency inside a packaged app.
 *
 * In a packaged app Electron's resolver returns paths INSIDE `app.asar` —
 * even for entries electron-builder unpacked (verified: `require.resolve`
 * returns `<...>/app.asar/node_modules/@domo/native-linuxsandbox/index.cjs`
 * in the AppImage). The app's own `fs` reads work, because Electron's asar
 * wrapper redirects unpacked entries to the real tree. A SPAWNED executable
 * is different: `child_process.spawn` is not asar-aware, so the kernel walks
 * `<...>/app.asar/node_modules/...` and finds `app.asar` is a FILE where a
 * directory was expected — `spawn ENOTDIR`, on every run, in a packaged
 * build only (the from-source path is real, which is why the suite passes).
 *
 * `electron-builder.yml`'s `asarUnpack` is what puts the real bytes under
 * `<...>/app.asar.unpacked/...`, so that is where an executable or a
 * spawned script path must point. This is only for things handed to
 * `spawn`: reads made by the app itself are already asar-aware, and
 * rewriting them would turn a working read into a wrong path.
 */
export function unpackedPath(p: string): string {
  // A full path component only: `/app.asar.backup/` is a different directory
  // and must not be rewritten. Both separators, because the Windows launcher
  // is resolved by this same function.
  return p.replace(/([\\/])app\.asar\1/, "$1app.asar.unpacked$1");
}
