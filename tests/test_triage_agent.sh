#!/usr/bin/env bash
# Unit tests for the triage agent: fake upstreams, real shapes. No containers needed.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1   # M1: a same-second recompile can reuse a stale __pycache__/*.pyc and hide a caught mutation
cd "$(dirname "$0")/.."
python3 -m unittest -q tests/test_triage_agent.py && echo "test_triage_agent OK"
