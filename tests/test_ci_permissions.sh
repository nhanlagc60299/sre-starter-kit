#!/usr/bin/env bash
# .github/workflows/ci.yml runs on `pull_request` with no branch filter, so a PR author's own
# checked-out code executes as `make test` / `make smoke` before anything else. Two defaults have
# to be narrowed or that code can read a live GITHUB_TOKEN out of .git/config:
#   - an explicit top-level `permissions: contents: read` block (the repo-settings default is
#     otherwise a hosted, unobservable fact that source cannot show);
#   - `persist-credentials: false` on every `actions/checkout` step, so the (now read-only) token
#     is never even written to .git/config for that PR-controlled code to find.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - .github/workflows/ci.yml <<'PY'
import sys
import yaml

path = sys.argv[1]
doc = yaml.safe_load(open(path))

perms = doc.get("permissions")
if perms != {"contents": "read"}:
    sys.exit(
        f"FAIL: {path} top-level `permissions:` must be exactly "
        f"{{'contents': 'read'}}, got {perms!r}"
    )

checkouts = 0
for job_name, job in doc.get("jobs", {}).items():
    for step in job.get("steps", []):
        uses = step.get("uses", "")
        if not uses.startswith("actions/checkout@"):
            continue
        checkouts += 1
        persist = (step.get("with") or {}).get("persist-credentials")
        if persist is not False:
            sys.exit(
                f"FAIL: {path} job '{job_name}' checkout step must set "
                f"persist-credentials: false, got {persist!r}"
            )

if checkouts < 1:
    sys.exit(f"FAIL: {path} has no actions/checkout steps -- nothing to check")

print(f"OK: permissions: contents: read, {checkouts} checkout step(s) all persist-credentials: false")
PY
