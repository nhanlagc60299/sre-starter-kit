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
# In-place refresh: a second render must keep the inode of every rendered file (compose bind-mounts
# them; a new inode strands the running container on the old copy) and drop files with no source.
ino1=$(stat -f %i "$tmp/build/sub/a.yml" 2>/dev/null || stat -c %i "$tmp/build/sub/a.yml")
echo 'gone: 1' > "$tmp/build/sub/stale.yml"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
ino2=$(stat -f %i "$tmp/build/sub/a.yml" 2>/dev/null || stat -c %i "$tmp/build/sub/a.yml")
[ "$ino1" = "$ino2" ] || { echo "FAIL: render replaced build/sub/a.yml instead of rewriting it in place (inode $ino1 -> $ino2)"; exit 1; }
[ ! -e "$tmp/build/sub/stale.yml" ] || { echo "FAIL: stale file survived a re-render"; exit 1; }
# A .env written before NODE_EXPORTER_TARGET existed has no such key. render.sh only substitutes
# variables it finds in .env, so without the default an unsubstituted ${NODE_EXPORTER_TARGET} would
# survive into prometheus.yml as a literal and Prometheus would never scrape the host.
echo 'targets: [${NODE_EXPORTER_TARGET}]' > "$tmp/core/sub/c.yml.tpl"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
[ "$(cat "$tmp/build/sub/c.yml")" = "targets: [node-exporter:9100]" ] || {
  echo "FAIL: NODE_EXPORTER_TARGET did not default for a .env without the key: $(cat "$tmp/build/sub/c.yml")"; exit 1; }
echo 'NODE_EXPORTER_TARGET=10.88.0.1:9100' >> "$tmp/.env"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
[ "$(cat "$tmp/build/sub/c.yml")" = "targets: [10.88.0.1:9100]" ] || {
  echo "FAIL: NODE_EXPORTER_TARGET from .env was not honoured: $(cat "$tmp/build/sub/c.yml")"; exit 1; }

rm "$tmp/.env"
if ( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" 2>/dev/null ); then echo "FAIL: should exit when .env missing"; exit 1; fi
echo "test_render OK"
