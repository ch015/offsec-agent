#!/bin/bash
set -euo pipefail
DEMO_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
DEMO_NODE="${DEMO_NODE:-$HOME/.nvm/versions/node/v22.18.0/bin/node}"
if [ ! -x "$DEMO_NODE" ]; then DEMO_NODE="$(command -v node)"; fi
export PATH="$(dirname -- "$DEMO_NODE"):$PATH"
if [ "$#" -eq 0 ]; then set -- help; fi
exec "$DEMO_NODE" "$DEMO_DIR/demo.mjs" "$@"
