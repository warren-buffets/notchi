#!/usr/bin/env bash
set -euo pipefail

# Build local signé ad hoc, installé dans /Applications.
# Usage: ./scripts/build-local.sh [--no-install]

SCHEME="notchi"
PROJECT_PATH="notchi/notchi.xcodeproj"
APP_NAME="Notchi"
PRODUCT_NAME="notchi"
BUILD_DIR="build"
BUILT_APP="${BUILD_DIR}/Build/Products/Release/${PRODUCT_NAME}.app"
INSTALL_PATH="/Applications/${APP_NAME}.app"

cd "$(dirname "$0")/.."

# Sans xcode-select (pas de sudo), viser Xcode.app directement
if [[ "$(xcode-select -p)" == *CommandLineTools* ]]; then
    export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
fi

if ! xcodebuild -version >/dev/null 2>&1; then
    echo "ERREUR: Xcode complet requis. Installer Xcode depuis l'App Store, puis :" >&2
    echo "  sudo xcode-select -s /Applications/Xcode.app/Contents/Developer" >&2
    exit 1
fi

# Signature ad hoc sans Team ID : hardened runtime off, sinon dyld refuse de charger Sparkle.
xcodebuild -project "$PROJECT_PATH" -scheme "$SCHEME" -configuration Release \
    -derivedDataPath "$BUILD_DIR" \
    CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= \
    ENABLE_HARDENED_RUNTIME=NO build

[[ -d "$BUILT_APP" ]] || { echo "ERREUR: $BUILT_APP introuvable" >&2; exit 1; }

if [[ "${1:-}" == "--no-install" ]]; then
    echo "Build OK : $BUILT_APP (installation ignorée)"
    exit 0
fi

osascript -e "quit app \"${APP_NAME}\"" 2>/dev/null || true
sleep 1
pkill -x "$PRODUCT_NAME" 2>/dev/null || true
# Ancienne version mise à la corbeille plutôt que supprimée
[[ -d "$INSTALL_PATH" ]] && mv "$INSTALL_PATH" "$HOME/.Trash/${APP_NAME}-$(date +%s).app"
ditto "$BUILT_APP" "$INSTALL_PATH"
xattr -dr com.apple.quarantine "$INSTALL_PATH" 2>/dev/null || true
open "$INSTALL_PATH"
echo "Installé : $INSTALL_PATH"
