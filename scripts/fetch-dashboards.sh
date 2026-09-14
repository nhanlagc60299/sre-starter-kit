#!/usr/bin/env bash
# Download community dashboards and pin the datasource uid. Re-run to upgrade.
set -euo pipefail
cd "$(dirname "$0")/.."
fetch() { # id uid title outfile
  curl -sfL "https://grafana.com/api/dashboards/$1/revisions/latest/download" \
    | python3 -c "
import sys,json
d=json.load(sys.stdin); d['uid']='$2'; d['title']='$3'; d['id']=None
s=json.dumps(d).replace('\${DS_PROMETHEUS}','prometheus').replace('\"\${datasource}\"','\"prometheus\"').replace('\${ds_prometheus}','prometheus')
print(s)
" > "$4.tmp"
  mv "$4.tmp" "$4"
  if grep -q '\${' "$4"; then echo "ERROR: unpinned placeholder remains in $4"; grep -o '\${[^}]*}' "$4" | sort -u; exit 1; fi
}
fetch 1860 sre-node "SRE Kit / Node" core/grafana/dashboards/node.json
echo "fetched"
