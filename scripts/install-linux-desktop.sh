#!/usr/bin/env bash
# Copy the packaged Linux AppImage into a stable user path and register a
# desktop entry so it appears in the host app launcher. On Omarchy that is
# the Apps tab. Safe to re-run: it replaces the previous install.
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "install-linux-desktop: Linux only (this host is $(uname -s))" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE="$ROOT/apps/desktop/release"
APPIMAGE="$(ls -t "$RELEASE"/Plow-Latch-*.AppImage 2>/dev/null | head -n 1 || true)"
if [[ -z "$APPIMAGE" || ! -f "$APPIMAGE" ]]; then
  echo "install-linux-desktop: no AppImage in $RELEASE — run \`just package-linux\` first" >&2
  exit 1
fi

DEST_DIR="${XDG_APPLICATIONS_DIR:-$HOME/Applications}"
DEST="$DEST_DIR/Plow-Latch.AppImage"
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
SCALABLE_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP="$DESKTOP_DIR/cat-paw-latch.desktop"
ICON_SRC_PNG="$ROOT/artwork/domo-desktop-icon.png"
ICON_SRC_SVG="$ROOT/artwork/domo-desktop-icon.svg"

mkdir -p "$DEST_DIR" "$ICON_DIR" "$SCALABLE_DIR" "$DESKTOP_DIR"
cp -f "$APPIMAGE" "$DEST"
chmod 0755 "$DEST"

if [[ -f "$ICON_SRC_PNG" ]]; then
  cp -f "$ICON_SRC_PNG" "$ICON_DIR/cat-paw-latch.png"
fi
if [[ -f "$ICON_SRC_SVG" ]]; then
  cp -f "$ICON_SRC_SVG" "$SCALABLE_DIR/cat-paw-latch.svg"
fi
gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" &>/dev/null || true

# Replace the AppImage auto-integration entry so Apps does not list the app twice.
if [[ -f "$DESKTOP_DIR/plow-latch.desktop" ]]; then
  rm -f "$DESKTOP_DIR/plow-latch.desktop"
fi

cat > "$DESKTOP" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Plow Latch
Comment=Approve what a remote AI agent does on this computer
Exec=$DEST %U
Icon=cat-paw-latch
Terminal=false
Categories=Development;
StartupWMClass=PlowLatch
StartupNotify=true
EOF
chmod 0644 "$DESKTOP"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
fi

echo "Installed $(basename "$APPIMAGE")"
echo "  app:  $DEST"
echo "  menu: $DESKTOP"

if command -v omarchy >/dev/null 2>&1 || [[ -d /usr/share/omarchy ]]; then
  echo
  echo "Omarchy: open the Apps tab and look for Plow Latch."
  echo "If it is missing, run: omarchy restart shell"
fi
