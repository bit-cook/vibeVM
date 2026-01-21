#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$ROOT_DIR/target/release/vibebox"
ENTITLEMENTS="$ROOT_DIR/entitlements.plist"

cargo build --release

codesign --entitlements "$ENTITLEMENTS" --force --sign - "$BINARY"

"$BINARY"
