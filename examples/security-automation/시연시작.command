#!/bin/bash
set -e
DEMO_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
exec bash "$DEMO_DIR/demo.sh" serve --open
