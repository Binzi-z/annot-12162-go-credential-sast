#!/usr/bin/env bash
# One-click verification: build fixtures -> unit tests -> labeled metrics ->
# demo repo SARIF smoke -> performance gate (optional, pass --perf).
set -euo pipefail
cd "$(dirname "$0")"

echo "== [1/4] build synthetic fixtures and 50-case dataset =="
python eval/builder.py $([[ "${1:-}" == "--perf" ]] && echo "--perf")

echo "== [2/4] primitive unit tests =="
python eval/test_units.py

echo "== [3/4] labeled dataset metrics (recall >=85%, FPR <=15%) =="
python eval/evaluate.py

echo "== [4/4] integration repo SARIF smoke =="
python -m credscan scan fixtures/demo-go --sarif fixtures/demo-go.sarif
python -m credscan explain fixtures/demo-go.sarif | head -40

if [[ "${1:-}" == "--perf" ]]; then
  echo "== performance gate =="
  python eval/perf.py
fi

echo "all verification steps completed"
