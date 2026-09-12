#!/bin/bash
# Build the upstream-radar Web settings client bundle (src/client → lib/client.js).
#
# upstream-radar's own devDeps are intentionally minimal (typescript + @types/node),
# so the client bundler (tsdown) is resolved from this package first, then from
# PATH. When tsdown lives somewhere else (e.g. a sibling client plugin's
# node_modules that already carries tsdown plus the dsh client externals), point
# TSDOWN_BIN at it.
#
# The module loader banner in tsdown.config.ts matches the harness's
# `window.__ModuleLoader__` contract. If a bundler step probes the dsh client
# externals (react, ui-slots, client-runtime), export NODE_PATH to a node_modules
# tree that carries them; it is not needed otherwise.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TSCONFIG="./tsdown.config.ts"

TSCLI="${TSDOWN_BIN:-}"
if [ -n "$TSCLI" ] && [ ! -x "$TSCLI" ]; then
  echo "build-client: TSDOWN_BIN is not executable: $TSCLI" >&2
  exit 1
fi
if [ -z "$TSCLI" ] && [ -x "$ROOT/node_modules/.bin/tsdown" ]; then
  TSCLI="$ROOT/node_modules/.bin/tsdown"
fi
if [ -z "$TSCLI" ] && command -v tsdown >/dev/null 2>&1; then
  TSCLI="$(command -v tsdown)"
fi
if [ -z "$TSCLI" ]; then
  echo "build-client: no tsdown found (looked at TSDOWN_BIN, ./node_modules/.bin/tsdown, PATH)" >&2
  exit 1
fi

echo "build-client: using tsdown at $TSCLI"
"$TSCLI" --config "$TSCONFIG"
echo "build-client: wrote lib/client.js"
