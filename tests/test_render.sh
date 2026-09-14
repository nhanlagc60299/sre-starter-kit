#!/usr/bin/env bash
# Self-check for scripts/render.sh. Run from repo root.
set -euo pipefail
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/core/sub"
echo 'name=${PROJECT_NAME}' > "$tmp/core/sub/a.yml.tpl"
echo 'static: 1' > "$tmp/core/sub/b.yml"
echo 'PROJECT_NAME=demo' > "$tmp/.env"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" )
[ "$(cat "$tmp/build/sub/a.yml")" = "name=demo" ] || { echo "FAIL: tpl not rendered"; exit 1; }
[ "$(cat "$tmp/build/sub/b.yml")" = "static: 1" ] || { echo "FAIL: static not copied"; exit 1; }
[ ! -e "$tmp/build/sub/a.yml.tpl" ] || { echo "FAIL: tpl copied verbatim"; exit 1; }
rm "$tmp/.env"
if ( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" 2>/dev/null ); then echo "FAIL: should exit when .env missing"; exit 1; fi
echo "test_render OK"
