#!/usr/bin/env bash
# docs/FEATURES.md repeats the Pro alert count that README.md's "## Pro" paragraph states, and the
# two have drifted apart before. Fail when they disagree.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import re
readme = open("README.md").read()
feat = open("docs/FEATURES.md").read()
m = re.search(r"runbook\s+for\s+all\s+(\d+)\s+alerts\s+\((\d+)\s+from\s+Prometheus", readme)
assert m, "README.md's ## Pro paragraph no longer says 'runbook for all N alerts (M from Prometheus': update this test"
total, prom = m.groups()
runbooks = re.search(r"`runbooks/<Alert>\.md`: (\d+) files", feat)
max_prom = re.search(r"to (\d+) Prometheus depending on modules", feat)
assert runbooks and max_prom, "docs/FEATURES.md no longer states the runbook or Prometheus alert count: update this test"
assert runbooks.group(1) == total, "docs/FEATURES.md says %s runbooks, README.md says %s alerts" % (runbooks.group(1), total)
assert max_prom.group(1) == prom, "docs/FEATURES.md says up to %s Prometheus alerts, README.md says %s" % (max_prom.group(1), prom)
PY
echo "test_features_counts OK"
