"""Performance gates:

  full scan of ~200k LOC synthetic repo must finish under 180s
  incremental scan (one changed file, git diff) must finish under 15s

The perf repo is generated on demand by eval/builder.py --perf.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from credscan.engine import Scanner  # noqa: E402

PERF = os.path.join(ROOT, "fixtures", "perf-repo")
FULL_BUDGET_MS = 180_000
INCREMENTAL_BUDGET_MS = 15_000


def _ensure_repo() -> None:
    if os.path.isdir(PERF):
        return
    print("perf repo missing; building ...")
    subprocess.run([sys.executable, os.path.join(ROOT, "eval", "builder.py"), "--perf"],
                   check=True)


def _loc() -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(PERF):
        for name in files:
            if name.endswith(".go"):
                with open(os.path.join(dirpath, name), encoding="utf-8", errors="replace") as fh:
                    total += sum(1 for _ in fh)
    return total


def main() -> int:
    _ensure_repo()
    loc = _loc()
    print(f"perf repo LOC: {loc:,}")

    t0 = time.perf_counter()
    scanner = Scanner(PERF)
    findings = scanner.scan()
    full_ms = int((time.perf_counter() - t0) * 1000)
    print(f"full scan     : {full_ms:>7} ms  (budget {FULL_BUDGET_MS} ms) "
          f"files={scanner.stats.files_scanned} findings={len(findings)}")

    # Incremental: emulate a one-file change. git diff only works inside a
    # work tree, so fall back to explicit file-list scanning when unavailable.
    target = os.path.join(PERF, "pkg0000", "file.go")
    t0 = time.perf_counter()
    inc = Scanner(PERF)
    rel = os.path.relpath(target, PERF).replace("\\", "/")
    inc_findings = inc.scan(rel_paths=[rel], incremental=True)
    inc_ms = int((time.perf_counter() - t0) * 1000)
    print(f"incremental   : {inc_ms:>7} ms  (budget {INCREMENTAL_BUDGET_MS} ms) "
          f"files={inc.stats.files_scanned} findings={len(inc_findings)}")

    ok_full = full_ms < FULL_BUDGET_MS
    ok_inc = inc_ms < INCREMENTAL_BUDGET_MS
    print("-" * 60)
    print("VERDICT:", "PASS" if ok_full and ok_inc else "FAIL")
    return 0 if ok_full and ok_inc else 1


if __name__ == "__main__":
    sys.exit(main())
