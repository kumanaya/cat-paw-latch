#!/usr/bin/env bash
# Upload a packaged Linux AppImage release candidate to versioned S3 keys.
#
# Reads apps/desktop/release/ (the electron-builder output that
# `just package-linux` produced) and uploads everything an update or a
# download needs to
#   s3://<bucket>/<prefix>/releases/<version>-<build>/linux/<arch>/
# Stable keys are NOT touched — installed apps keep updating from whatever
# was last promoted. `just promote-linux` is the human-gated step.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: release-upload-linux.sh --version <value> --build <number> [options]

Options:
  --version <value>   The stamped version `just package-linux` minted
  --build <value>     The UTC stamp from the same package run
  --arch <arch>       AppImage arch (default: x64)
  --bucket <name>     S3 bucket (default: releases.plow.co)
  --prefix <path>     Key prefix inside the bucket (default: domo)
  --profile <name>    AWS profile; pass "" for ambient credentials (CI OIDC)
                      (default: plow)
  -h, --help          Show this help
EOF
}

version=""
build=""
arch="x64"
bucket="releases.plow.co"
prefix="domo"
profile="plow"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --build) build="${2:-}"; shift 2 ;;
    --arch) arch="${2:-}"; shift 2 ;;
    --bucket) bucket="${2:-}"; shift 2 ;;
    --prefix) prefix="${2:-}"; shift 2 ;;
    --profile) profile="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[[ -n "$version" && -n "$build" ]] || { echo "error: --version and --build are required" >&2; usage >&2; exit 1; }

root="$(cd "$(dirname "$0")/.." && pwd)"
release_dir="$root/apps/desktop/release"

aws_args=()
[[ -n "$profile" ]] && aws_args+=(--profile "$profile")

appimage_name="Plow-Latch-${version}-${arch}.AppImage"
feed=""
for candidate in "latest-linux.yml" "latest-linux-${arch}.yml"; do
  if [[ -f "$release_dir/$candidate" ]]; then
    feed="$candidate"
    break
  fi
done

[[ -f "$release_dir/$appimage_name" ]] || {
  echo "error: expected artifact missing: $release_dir/$appimage_name" >&2
  echo "hint: run 'just package-linux' first" >&2
  exit 1
}
[[ -n "$feed" ]] || {
  echo "error: no latest-linux.yml (or latest-linux-${arch}.yml) in $release_dir" >&2
  exit 1
}

grep -q "version: ${version}$" "$release_dir/$feed" || {
  echo "error: $feed does not carry version ${version} — stale release/ dir?" >&2
  exit 1
}
grep -q "$appimage_name" "$release_dir/$feed" || {
  echo "error: $feed does not reference $appimage_name" >&2
  exit 1
}

# Same digest electron-updater will check: refuse a YAML without sha512, or
# one that does not match the AppImage bytes. There is no Authenticode
# publisher check on Linux; this is the install-time trust.
node "$root/scripts/verify-linux-release-feed.mjs" "$release_dir" --arch "$arch"

sha256sum "$release_dir/$appimage_name" | awk '{print $1}' > "$release_dir/$appimage_name.sha256"

dest="s3://${bucket}/${prefix}/releases/${version}-${build}/linux/${arch}"
for f in "$appimage_name" "$appimage_name.sha256" "$feed"; do
  aws ${aws_args[@]+"${aws_args[@]}"} s3 cp "$release_dir/$f" "$dest/$f"
done

echo "Uploaded Linux release candidate ${version} (${build}, ${arch}):"
echo "  AppImage: https://s3.us-west-2.amazonaws.com/${bucket}/${prefix}/releases/${version}-${build}/linux/${arch}/${appimage_name}"
echo "To ship it to existing installs: just promote-linux ${version} ${build}"
