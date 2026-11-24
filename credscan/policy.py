"""Test-fixture noise control without ever dropping a live key.

Policy principle (in this order):

1. Evidence first, context second. Suppression can only *downgrade* a finding;
   it can never erase one. Anything with structural evidence — provider prefix
   plus correct length/charset (rank 3), or a valid checksum (rank 4), or a
   PEM/JWT body that decodes — is always reported as `real`, in test files and
   generated code alike. A leaked production key committed under a testdata/
   directory is exactly the incident we are built to catch.

2. Fixture *signals* are collected from syntax-aware metadata, not guessed from
   content: directory names (testdata, mock, fixture, example, demo, sample,
   stub, docs), *_test.go file suffix, package name, and CI job names. The
   signals are attached to every finding and printed in SARIF.

3. Only weak evidence is suppressible. Entropy-only or low-confidence verdicts
   (rank <= 2) inside a fixture context are marked `suppressed` with an
   explicit reason and kept in the SARIF output as suppressed results — never
   silently dropped, so recall against the labeled set is auditable and the
   baseline file can un-suppress anything.

4. Placeholder/example classes are never blocking regardless of location; they
   surface as note/warning level so the T+1 inventory stays complete.

5. One structural signal is enough to beat one context signal: rank-3 findings
   with a single weak fixture signal (e.g. file is *_test.go but lives in a
   normal package) stay visible; suppression needs >= 2 independent signals or
   a strong path signal (testdata/ / fixtures/ directory).
"""

from __future__ import annotations

from .model import Finding

_STRONG_PATH_SIGNALS = ("path:testdata", "path:fixture", "path:fixtures",
                        "path:mock", "path:mocks", "path:example",
                        "path:examples", "path:sample", "path:samples",
                        "path:demo", "path:stub", "path:stubs")


def apply_fixture_policy(finding: Finding) -> Finding:
    if finding.confidence != "real":
        # examples/placeholders stay visible but never block the pipeline.
        return finding

    rank = 4 if (finding.structural and finding.checksum_ok) else (
        3 if finding.structural else (2 if finding.normalized_entropy >= 0.75 else 1))
    finding.reasons.append(f"evidence-rank:{rank}")

    if rank >= 3:
        # Hard guarantee: structural/checksum/PEM evidence cannot be suppressed.
        finding.reasons.append("fixture-policy:structural-evidence-immune")
        return finding

    signals = set(finding.fixture_signals)
    has_strong_path = any(any(s.startswith(p) for p in _STRONG_PATH_SIGNALS)
                          for s in signals)
    signal_count = len(signals)

    if has_strong_path or signal_count >= 2:
        finding.suppressed = True
        finding.suppression_reason = (
            "weak-evidence-in-fixture-context:" + ",".join(sorted(signals)))
        finding.reasons.append("fixture-policy:suppressed-weak-evidence")
    elif signal_count == 1:
        finding.reasons.append("fixture-policy:kept-single-signal")
    return finding
