#!/usr/bin/env bash
# Unit tests for the triage agent: fake upstreams, real shapes. No containers needed.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m unittest -q tests/test_triage_agent.py && echo "test_triage_agent OK"
