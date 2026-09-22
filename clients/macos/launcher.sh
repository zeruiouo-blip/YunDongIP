#!/bin/bash
set -e

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$APP_DIR/Resources/YunDongIP-core"
DATA_DIR="$HOME/Library/Application Support/YunDongIP"

mkdir -p "$DATA_DIR"
cd "$DATA_DIR"

exec "$CORE" -host 127.0.0.1 -port 13335 -open-browser=true
