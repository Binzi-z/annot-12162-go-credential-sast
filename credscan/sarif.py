"""SARIF v2.1.0 output.

One result per finding with:
  * ruleId carrying carrier + confidence (e.g. credscan/go-const/real)
  * partialFingerprints for stable baseline diffing across file moves
  * suppression objects with explicit reasons (inSource-style, tool-driven)
  * codeFlows rendering the const -> usage propagation chain
  * properties exposing build constraints, generated-code flags and evidence
"""

from __future__ import annotations

import json

from .model import Finding

TOOL_NAME = "credscan"
TOOL_VERSION = "0.1.0"

_RULES_CACHE: dict[str, dict] = {}

_SEVERITY_BY_CONFIDENCE = {
    "real": ("error", "high"),
    "example": ("note", "low"),
    "placeholder": ("warning", "medium"),
}


def _rule(rule_id: str, confidence: str, carrier: str) -> dict:
    if rule_id not in _RULES_CACHE:
        level, severity = _SEVERITY_BY_CONFIDENCE.get(confidence, ("warning", "medium"))
        _RULES_CACHE[rule_id] = {
            "id": rule_id,
            "name": f"HardcodedCredential{carrier.replace('-', ' ').title().replace(' ', '')}",
            "shortDescription": {
                "text": f"Hardcoded credential in {carrier} ({confidence})",
            },
            "fullDescription": {
                "text": (
                    "A credential-position syntax node contains a literal whose "
                    "content passes structural or entropy validation. Findings "
                    "classified 'real' block CI; 'example' and 'placeholder' "
                    "are inventory-only."
                ),
            },
            "defaultConfiguration": {
                "level": level,
                "properties": {"security-severity": severity},
            },
            "help": {
                "text": (
                    "Rotate the credential if it is live, remove it from source "
                    "and load it from a secret manager or environment variable. "
                    "Suppressed results are weak-evidence matches in fixture "
                    "contexts; structural/checksum-valid keys are never suppressed."
                ),
            },
        }
    return _RULES_CACHE[rule_id]


def _location(f: Finding) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": f.file.replace("\\", "/")},
            "region": {
                "startLine": f.line,
                "startColumn": f.column,
                "endColumn": max(f.end_column, f.column + 1),
                "snippet": {"text": f.value_preview},
            },
        },
        "logicalLocations": [
            {"name": f.symbol, "kind": "namespace"}
        ],
    }


def _code_flow(f: Finding) -> dict | None:
    if not f.usages:
        return None
    locations = [{
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file.replace("\\", "/")},
                "region": {"startLine": f.line, "startColumn": f.column},
            },
            "logicalLocations": [{"name": f"origin:{f.symbol}", "kind": "declaration"}],
        },
        "nestingLevel": 0,
    }]
    for k, u in enumerate(f.usages, start=1):
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": u.file.replace("\\", "/")},
                    "region": {"startLine": u.line, "startColumn": u.column,
                               "snippet": {"text": u.snippet}},
                },
                "logicalLocations": [{"name": f"{u.kind}", "kind": "function"}],
            },
            "nestingLevel": k,
        })
    return {
        "threadFlows": [{
            "id": f"flow-{f.fingerprint}",
            "locations": locations,
        }]
    }


def build_sarif(findings: list[Finding], repo_root: str) -> dict:
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()

    for f in sorted(findings, key=lambda x: (x.file, x.line, x.rule_id)):
        if f.rule_id not in seen_rules:
            seen_rules.add(f.rule_id)
            rules.append(_rule(f.rule_id, f.confidence, f.carrier))
        result = {
            "ruleId": f.rule_id,
            "level": f.sarif_level(),
            "message": {
                "text": (
                    f"{f.provider} {f.kind} at {f.symbol} — "
                    f"confidence={f.confidence}"
                    + (" [SUPPRESSED: " + f.suppression_reason + "]"
                       if f.suppressed else "")
                ),
            },
            "locations": [_location(f)],
            "partialFingerprints": {"credscan/v1": f.fingerprint},
            "properties": {
                "confidence": f.confidence,
                "provider": f.provider,
                "credential-kind": f.kind,
                "carrier": f.carrier,
                "structural": f.structural,
                "checksum-ok": f.checksum_ok,
                "normalized-entropy": round(f.normalized_entropy, 4),
                "build-constraint": f.build_constraint,
                "generated-code": f.generated,
                "fixture-signals": f.fixture_signals,
                "evidence": f.reasons,
            },
        }
        flow = _code_flow(f)
        if flow is not None:
            result["codeFlows"] = [flow]
        if f.suppressed:
            result["suppressions"] = [{
                "kind": "external",
                "status": "accepted",
                "justification": f.suppression_reason or "fixture context",
            }]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://example.invalid/credscan",
                    "rules": rules,
                },
            },
            "originalUriBaseIds": {
                "REPO_ROOT": {"uri": "file://" + repo_root.replace("\\", "/") + "/"},
            },
            "results": results,
            "columnKind": "utf16CodeUnits",
        }],
    }


def dumps(findings: list[Finding], repo_root: str) -> str:
    return json.dumps(build_sarif(findings, repo_root), indent=2, ensure_ascii=False)
