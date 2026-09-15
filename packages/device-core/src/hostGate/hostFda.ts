/**
 * The Full Disk Access row's live probe, per host. macOS still opens
 * TCC-protected files; Windows and Linux list the guarded user folders.
 * One function so the inventory, `capabilities:get`, and the grant-flow
 * poll cannot disagree about which probe this process should run.
 */
import { fullDiskProbePaths, probeFullDiskAccessDetail } from "./fullDiskAccess.js";
import { probeLinuxFolderAccessDetail } from "./linux.js";
import { probeWindowsFolderAccessDetail } from "./windows.js";

export async function probeHostFullDiskAccessDetail(
  ownerHome: string,
  platform: NodeJS.Platform = process.platform,
): Promise<{ granted: boolean; results: { path: string; outcome: string }[] }> {
  if (platform === "win32") return probeWindowsFolderAccessDetail(ownerHome);
  if (platform === "linux") return probeLinuxFolderAccessDetail(ownerHome);
  return probeFullDiskAccessDetail(fullDiskProbePaths(ownerHome));
}

export async function probeHostFullDiskAccess(
  ownerHome: string,
  platform: NodeJS.Platform = process.platform,
): Promise<boolean> {
  return (await probeHostFullDiskAccessDetail(ownerHome, platform)).granted;
}
