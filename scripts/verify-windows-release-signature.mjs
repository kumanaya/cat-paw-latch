#!/usr/bin/env node
/**
 * Refuse a Windows release artifact unless Authenticode validates now, names
 * Plow's publisher, and carries an RFC-3161 timestamp.  electron-updater does
 * the corresponding verification before applying a future update; this gate
 * prevents publishing an installer that could never pass that check.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The installer is not the only code Windows will execute.  Require an
// Authenticode signature for every PE payload that electron-builder is told to
// sign: app executables, browser/provider DLLs and our N-API addons.  Do not
// follow links while walking a candidate release directory.
function signedCodeUnder(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const candidate = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) files.push(...signedCodeUnder(candidate));
    else if (entry.isFile() && /\.(?:exe|dll|node)$/i.test(entry.name)) files.push(candidate);
  }
  return files;
}

export function windowsCodePayloads(releaseDir) {
  return [...new Set(signedCodeUnder(path.resolve(releaseDir)))];
}

export function verifyWindowsReleaseSignature(releaseDir, publisher) {
  if (!releaseDir || !publisher) throw new Error("usage: verify-windows-release-signature.mjs <release-dir> <publisher>");
  const resolved = path.resolve(releaseDir);
  if (!fs.existsSync(resolved)) throw new Error(`release directory does not exist: ${resolved}`);

  const installers = fs.readdirSync(resolved)
    .filter((name) => /^Plow-Latch-.*\.exe$/i.test(name))
    .map((name) => path.join(resolved, name));
  if (installers.length === 0) throw new Error(`no Plow Latch Windows installer exists in ${resolved}`);
  const signedCode = windowsCodePayloads(resolved);

const script = [
  "param([string]$FilesJson, [string]$Publisher)",
  "$ErrorActionPreference = 'Stop'",
  "$Files = ConvertFrom-Json -InputObject $FilesJson",
  "foreach ($File in $Files) {",
  "  $sig = Get-AuthenticodeSignature -LiteralPath $File",
  "  if ($sig.Status -ne 'Valid') { throw \"invalid Authenticode signature: $File ($($sig.Status))\" }",
  "  if ($null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notlike \"*CN=$Publisher*\") { throw \"unexpected Authenticode publisher: $File\" }",
  "  if ($null -eq $sig.TimeStamperCertificate) { throw \"missing Authenticode timestamp: $File\" }",
  "}",
].join("\n");

  const tempDir = fs.mkdtempSync(path.join(resolved, ".signature-check-"));
  const scriptPath = path.join(tempDir, "verify.ps1");
  try {
    fs.writeFileSync(scriptPath, script, { encoding: "utf8", mode: 0o600 });
    execFileSync(
      "powershell.exe",
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath, JSON.stringify(signedCode), publisher],
      { stdio: "inherit" },
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
  console.log(`[windows-signature] validated ${installers.length} installer(s) and ${signedCode.length} executable payload(s) for ${publisher}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    verifyWindowsReleaseSignature(...process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
