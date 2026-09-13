#!/usr/bin/env bash
# Promote a Linux AppImage release candidate to the stable keys that
# installed apps poll (`platformUpdateFeed("linux", arch)`).
#
# Copies s3://<bucket>/<prefix>/releases/<version>-<build>/linux/<arch>/*
# onto:
#   <prefix>/linux/<arch>/<AppImage> + .sha256
#   <prefix>/linux/<arch>/latest-linux.yml   — copied LAST
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: release-promote-linux.sh --version <value> --build <number> [options]

Options:
  --version <value>   Marketing version, e.g. 0.1.202609130000
  --build <value>     Build number the candidate was uploaded under
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

aws_args=()
[[ -n "$profile" ]] && aws_args+=(--profile "$profile")

src="${prefix}/releases/${version}-${build}/linux/${arch}"
appimage_name="Plow-Latch-${version}-${arch}.AppImage"
feed="latest-linux.yml"
alt_feed="latest-linux-${arch}.yml"

feed_key=""
for key in "$feed" "$alt_feed"; do
  if aws ${aws_args[@]+"${aws_args[@]}"} s3api head-object --bucket "$bucket" --key "$src/$key" >/dev/null 2>&1; then
    feed_key="$key"
    break
  fi
done

for key in "$appimage_name" "$appimage_name.sha256"; do
  aws ${aws_args[@]+"${aws_args[@]}"} s3api head-object --bucket "$bucket" --key "$src/$key" >/dev/null 2>&1 || {
    echo "error: candidate artifact missing: s3://${bucket}/${src}/${key}" >&2
    echo "hint: was this version+build uploaded by 'just release-linux'?" >&2
    exit 1
  }
done
[[ -n "$feed_key" ]] || {
  echo "error: candidate feed missing under s3://${bucket}/${src}/" >&2
  exit 1
}

copy() {
  aws ${aws_args[@]+"${aws_args[@]}"} s3 cp "s3://${bucket}/${src}/$1" "s3://${bucket}/${prefix}/linux/${arch}/$2"
}

copy "$appimage_name" "$appimage_name"
copy "$appimage_name.sha256" "$appimage_name.sha256"
copy "$appimage_name" "Plow-Latch.AppImage"
copy "$appimage_name.sha256" "Plow-Latch.AppImage.sha256"
# Feed last: writing it is the moment existing installs see the update.
copy "$feed_key" "latest-linux.yml"

echo "Promoted Linux ${version} (${build}, ${arch}) to stable:"
echo "  feed:     https://s3.us-west-2.amazonaws.com/${bucket}/${prefix}/linux/${arch}/latest-linux.yml"
echo "  download: https://s3.us-west-2.amazonaws.com/${bucket}/${prefix}/linux/${arch}/Plow-Latch.AppImage"
