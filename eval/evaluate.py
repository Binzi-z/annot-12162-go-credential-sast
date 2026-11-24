"""Evaluation harness for the 50-case labeled dataset.

Metrics (matching the incident's acceptance bar):
  recall     real-labeled cases whose prediction contains a blocking/real
             finding (suppressed reals do not count as recalled)
  false-positive-rate  non-real cases (example/placeholder/none) that produced
             an un-suppressed 'real' prediction, divided by real-case count;
             the <=15% budget therefore tolerates a small absolute number
  suppression-accuracy  case 28 style: weak evidence in fixture paths must be
             suppressed while structurally valid keys in fixtures stay real

Also validates SARIF well-formedness and prints per-case diagnostics.
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from credscan.engine import Scanner  # noqa: E402
from credscan.sarif import build_sarif  # noqa: E402

DATASET = os.path.join(ROOT, "fixtures", "dataset")
CASES_ROOT = os.path.join(DATASET, "cases")


def _load_labels() -> list[dict]:
    with open(os.path.join(DATASET, "labels.json"), encoding="utf-8") as fh:
        return json.load(fh)["labels"]


def _scan_dataset():
    scanner = Scanner(DATASET)
    findings = scanner.scan()
    by_case: dict[str, list] = {}
    for f in findings:
        # paths are relative to the scan root (DATASET); case id is first dir
        parts = f.file.replace("\\", "/").split("/")
        case_id = parts[1] if parts and parts[0] == "cases" else parts[0]
        by_case.setdefault(case_id, []).append(f)
    return findings, by_case, scanner


def evaluate() -> int:
    labels = _load_labels()
    findings, by_case, scanner = _scan_dataset()

    # SARIF well-formedness: schema/version present, every result has the
    # required location and fingerprint fields.
    sarif = build_sarif(findings, scanner.repo_root)
    assert sarif["version"] == "2.1.0"
    for result in sarif["runs"][0]["results"]:
        assert "ruleId" in result and "locations" in result
        assert "credscan/v1" in result.get("partialFingerprints", {})

    rows = []
    true_real = 0
    recalled = 0
    false_positives = 0
    suppression_ok = 0
    suppression_total = 0
    class_mismatches = []

    for label in labels:
        cid = label["case"]
        expected = label["expect"]
        preds = by_case.get(cid, [])
        blocking = [p for p in preds if p.blocking()]
        any_real = any(p.confidence == "real" for p in preds)
        classes = sorted({p.confidence for p in preds})

        ok = True
        detail = ""
        if expected == "real":
            true_real += 1
            if label["suppressed"]:
                suppression_total += 1
                if any_real and all(p.suppressed for p in preds if p.confidence == "real"):
                    suppression_ok += 1
                    detail = "suppressed as designed"
                else:
                    ok = False
                    detail = f"expected suppression, got {classes}"
            elif blocking:
                recalled += 1
                detail = "recalled"
            else:
                ok = False
                detail = f"MISS ({classes or 'no finding'})"
        else:
            if blocking:
                false_positives += 1
                ok = False
                detail = f"FALSE POSITIVE: {[p.symbol for p in blocking]}"
            else:
                # exact-class audit (non-blocking regardless)
                if expected != "none" and expected not in classes:
                    class_mismatches.append((cid, expected, classes))
                    detail = f"class drift (expected {expected}, got {classes})"
                elif expected == "none" and not preds:
                    detail = "clean"
                else:
                    detail = f"ok ({classes})"
        rows.append((cid, expected, "PASS" if ok else "FAIL", detail))

    recall = recalled / max(true_real - suppression_total, 1)
    fpr = false_positives / max(true_real, 1)
    fixture_precision = (
        suppression_ok / suppression_total if suppression_total else 1.0
    )

    print("=" * 78)
    print("credscan labeled-dataset evaluation")
    print("=" * 78)
    for cid, expected, status, detail in rows:
        print(f"{cid:<30} expect={expected:<11} {status:<5} {detail}")
    print("-" * 78)
    print(f"cases                 : {len(labels)}")
    print(f"real cases (blocking) : {true_real - suppression_total}")
    print(f"recalled              : {recalled}")
    print(f"RECALL                : {recall:.2%}  (bar >= 85%)")
    print(f"false positives       : {false_positives}")
    print(f"FALSE POSITIVE RATE   : {fpr:.2%}  (bar <= 15%)")
    print(f"fixture suppression   : {suppression_ok}/{suppression_total} "
          f"({fixture_precision:.0%})")
    if class_mismatches:
        print("class drift (non-blocking):")
        for cid, exp, got in class_mismatches:
            print(f"  {cid}: expected {exp}, got {got}")
    print(f"findings total        : {len(findings)}")
    print(f"scan elapsed          : {scanner.stats.elapsed_ms} ms")

    passed = recall >= 0.85 and fpr <= 0.15 and suppression_ok == suppression_total
    print("-" * 78)
    print("VERDICT:", "PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(evaluate())
