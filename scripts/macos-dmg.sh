#!/bin/bash
# Build the macOS LanClip.app and package it into a distributable DMG.
#
# Usage: scripts/macos-dmg.sh [version]
#
# Produces dist/LanClip-<version>-universal.dmg (or -arm64 when the x86_64
# toolchain is unavailable). The app is an LSUIElement agent: double-click to
# start the sync daemon with the menu-bar icon; logs go to
# ~/.config/lanclip/lanclip.log.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-0.3.0}"
GO=${GO:-go}
DIST=dist
APP_NAME=LanClip
BUNDLE_ID=io.lhg-projects.lanclip

rm -rf "$DIST/dmgroot"
mkdir -p "$DIST/dmgroot"

build() { # arch out
  CGO_ENABLED=1 GOARCH=$1 GOOS=darwin "$GO" build -trimpath \
    -ldflags "-s -w" -o "$2" ./cmd/lanclip
}

echo "== building darwin/arm64"
build arm64 "$DIST/lanclip-arm64"
UNIVERSAL=1
echo "== building darwin/amd64"
if ! build amd64 "$DIST/lanclip-amd64"; then
  echo "(amd64 build unavailable; shipping arm64-only)"
  UNIVERSAL=0
  BIN="$DIST/lanclip-arm64"
else
  lipo -create -output "$DIST/lanclip-universal" "$DIST/lanclip-arm64" "$DIST/lanclip-amd64"
  BIN="$DIST/lanclip-universal"
fi

APP="$DIST/dmgroot/$APP_NAME.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/lanclip"
chmod +x "$APP/Contents/MacOS/lanclip"
cp packaging/LanClip.icns "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>              <string>LanClip</string>
    <key>CFBundleDisplayName</key>       <string>LanClip</string>
    <key>CFBundleIdentifier</key>        <string>${BUNDLE_ID}</string>
    <key>CFBundleVersion</key>           <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundlePackageType</key>       <string>APPL</string>
    <key>CFBundleExecutable</key>        <string>lanclip</string>
    <key>CFBundleIconFile</key>          <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>    <string>11.0</string>
    <key>LSUIElement</key>               <true/>
    <key>NSHighResolutionCapable</key>   <true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>LanClip 在局域网内与你的其他设备同步剪贴板、截图和文件。</string>
    <key>NSBonjourServices</key>
    <array><string>_lanclip._tcp</string></array>
    <key>NSSupportsAutomaticTermination</key><false/>
    <key>NSSupportsSuddenTermination</key><false/>
</dict>
</plist>
PLIST

# drag-to-Applications shortcut
ln -sfn /Applications "$DIST/dmgroot/Applications"

SUFFIX=universal; [ "$UNIVERSAL" = 0 ] && SUFFIX=arm64
DMG="$DIST/LanClip-${VERSION}-${SUFFIX}.dmg"
echo "== creating $DMG"
rm -f "$DMG"
hdiutil create -volname "$APP_NAME" -srcfolder "$DIST/dmgroot" -ov -format UDZO "$DMG" >/dev/null

echo "done: $DMG"
hdiutil imageinfo "$DMG" | grep -E "Format:|Size" | head -3
