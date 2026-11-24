"""Single-entry verification runner (one Python process, one approval prompt).

Equivalent to: builder -> unit tests -> labeled evaluation -> SARIF smoke.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from eval import builder  # noqa: E402

failures: list[str] = []


def step(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main() -> int:
    step("1/4 build synthetic fixtures and 50-case dataset")
    builder.build_demo_repo()
    builder.build_dataset()

    step("2/4 primitive unit tests")
    import eval.test_units as units
    if units.main() != 0:
        failures.append("unit tests")

    step("3/4 labeled dataset metrics")
    import eval.evaluate as ev
    if ev.evaluate() != 0:
        failures.append("labeled evaluation")

    step("4/4 integration repo SARIF smoke")
    from credscan.engine import Scanner
    from credscan.sarif import dumps
    demo = os.path.join(ROOT, "fixtures", "demo-go")
    scanner = Scanner(demo)
    findings = scanner.scan()
    out = os.path.join(ROOT, "fixtures", "demo-go.sarif")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(dumps(findings, scanner.repo_root))
    print(f"SARIF written: {out}")
    print(f"demo repo: {scanner.stats.files_scanned} files, "
          f"{len(findings)} findings, {scanner.stats.blocking} blocking, "
          f"{scanner.stats.suppressed} suppressed, {scanner.stats.elapsed_ms} ms")
    reals = [f for f in findings if f.confidence == "real"]
    print("real findings (file:line symbol provider/kind suppressed?):")
    for f in sorted(reals, key=lambda x: (x.file, x.line)):
        print(f"  {f.file}:{f.line:<4} {f.symbol:<28} {f.provider}/{f.kind}"
              f"{' [SUPPRESSED]' if f.suppressed else ''}")

    print("\n" + "#" * 78)
    if failures:
        print(f"VERIFICATION FAILED: {failures}")
        return 1
    print("ALL VERIFICATION STEPS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
