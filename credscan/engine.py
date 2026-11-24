"""Scan orchestration: discovery, carrier dispatch, caching, incremental mode.

Carriers (the four from the post-incident review):
  1. Go source — config constants and variables        -> goparser (tree-sitter)
  2. Test fixtures — Go test files + fixture data files (same parsers, policy)
  3. Container image layers — Dockerfile / compose files -> textparse
  4. CI scripts — .github/workflows, .gitlab-ci.yml, shell -> textparse

Incremental mode asks git for changed paths and only re-parses those files;
a content-hash cache (one JSON file under .credscan-cache) keeps symbol-table
work for untouched packages out of the critical path. Go cross-package
resolution still loads cached indexes of unchanged files instead of parsing.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass

from .goparser import GoAnalyzer
from .model import Finding, fixture_path_signals, is_credential_name
from .policy import apply_fixture_policy
from .secrets import analyze_value
from .textparse import (
    parse_dockerfile, parse_envfile, parse_json, parse_shell, parse_yaml,
    RawCandidate,
)

_GO_EXT = ".go"
_YAML_EXTS = (".yaml", ".yml")
_JSON_EXTS = (".json",)
_SHELL_NAMES = ("sh", "bash", "zsh")
_DOCKER_NAMES = ("dockerfile",)
_IGNORE_DIRS = {".git", "node_modules", "vendor", "third_party", ".credscan-cache"}
_KEEP_DOT_DIRS = {".github", ".gitlab"}


@dataclass
class ScanStats:
    files_scanned: int = 0
    go_files: int = 0
    other_files: int = 0
    findings_total: int = 0
    blocking: int = 0
    suppressed: int = 0
    elapsed_ms: int = 0
    incremental: bool = False


class Scanner:
    def __init__(self, repo_root: str, active_tags: frozenset[str] | None = None,
                 goos: frozenset[str] | None = None,
                 goarch: frozenset[str] | None = None,
                 cache_dir: str | None = None):
        self.repo_root = os.path.abspath(repo_root)
        self.tags = active_tags or frozenset({"linux", "amd64"})
        self.goos = goos or frozenset({"linux", "darwin", "windows"})
        self.goarch = goarch or frozenset({"amd64", "arm64"})
        self.cache_dir = cache_dir or os.path.join(self.repo_root, ".credscan-cache")
        self.stats = ScanStats()
        self.findings: list[Finding] = []

    # ------------------------------------------------------------ discovery
    def discover(self) -> list[str]:
        rel_paths: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self.repo_root):
            dirnames[:] = [
                d for d in dirnames
                if d in _KEEP_DOT_DIRS
                or (d not in _IGNORE_DIRS and not d.startswith("."))
            ]
            for name in filenames:
                abs_path = os.path.join(dirpath, name)
                rel = os.path.relpath(abs_path, self.repo_root).replace("\\", "/")
                if self._classify(rel, name) is not None:
                    rel_paths.append(rel)
        return sorted(rel_paths)

    @staticmethod
    def _classify(rel: str, name: str) -> str | None:
        low = rel.lower()
        base = name.lower()
        if base.endswith(_GO_EXT):
            return "go"
        if base in _DOCKER_NAMES or base.startswith("dockerfile."):
            return "dockerfile"
        if base.endswith(_YAML_EXTS):
            return "yaml"
        if base.endswith(_JSON_EXTS):
            return "json"
        if base == ".env" or base.endswith(".env") or base.endswith(".properties"):
            return "envfile"
        if "." in base and base.rsplit(".", 1)[-1] in _SHELL_NAMES:
            return "shell"
        if base in ("makefile", "gnumakefile"):
            return "shell"
        if low.startswith((".github/workflows/", ".gitlab/")):
            return "yaml"
        return None

    def _read_module_path(self) -> str:
        go_mod = os.path.join(self.repo_root, "go.mod")
        if not os.path.isfile(go_mod):
            return ""
        try:
            with open(go_mod, encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("module "):
                        return line.split(None, 1)[1].strip()
        except OSError:
            pass
        return ""

    # ------------------------------------------------------------ entrypoint
    def scan(self, rel_paths: list[str] | None = None, incremental: bool = False) -> list[Finding]:
        t0 = time.perf_counter()
        self.stats.incremental = incremental
        all_paths = self.discover() if rel_paths is None else rel_paths
        go_files: list[tuple[str, str]] = []
        text_files: list[tuple[str, str]] = []
        for rel in all_paths:
            kind = self._classify(rel, os.path.basename(rel))
            abs_path = os.path.join(self.repo_root, rel)
            if kind == "go":
                go_files.append((abs_path, rel))
            elif kind in {"yaml", "json", "dockerfile", "shell", "envfile"}:
                text_files.append((abs_path, rel))
        self.stats.go_files = len(go_files)
        self.stats.other_files = len(text_files)
        self.stats.files_scanned = len(go_files) + len(text_files)

        if go_files:
            self._scan_go(go_files)
        for abs_path, rel in text_files:
            self._scan_text(abs_path, rel)

        for finding in self.findings:
            apply_fixture_policy(finding)
        self._finalize_stats(t0)
        return self.findings

    def scan_incremental(self, base_ref: str = "HEAD") -> list[Finding]:
        changed = self._git_changed(base_ref)
        return self.scan(rel_paths=changed, incremental=True)

    def _git_changed(self, base_ref: str) -> list[str]:
        try:
            proc = subprocess.run(
                ["git", "-C", self.repo_root, "diff", "--name-only", "--diff-filter=ACMR",
                 base_ref],
                capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            return self.discover()
        if proc.returncode != 0:
            return self.discover()
        candidates = [p.strip().replace("\\", "/") for p in proc.stdout.splitlines() if p.strip()]
        return [p for p in candidates if self._classify(p, os.path.basename(p))]

    # ------------------------------------------------------------ Go side
    def _scan_go(self, go_files: list[tuple[str, str]]) -> None:
        analyzer = GoAnalyzer(self.repo_root, self.tags, self.goos, self.goarch)
        module_path = self._read_module_path()
        analyzer.parse_all(go_files, module_path)
        analyzer.build_index()
        self.findings.extend(analyzer.analyze())

    # ------------------------------------------------------------ text side
    def _scan_text(self, abs_path: str, rel: str) -> None:
        try:
            with open(abs_path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            return
        kind = self._classify(rel, os.path.basename(rel))
        if kind == "yaml":
            raw = parse_yaml(rel, text)
        elif kind == "json":
            raw = parse_json(rel, text)
        elif kind == "dockerfile":
            raw = parse_dockerfile(rel, text)
        elif kind == "shell":
            raw = parse_shell(rel, text)
        elif kind == "envfile":
            raw = parse_envfile(rel, text)
        else:
            return

        rel_parts = tuple(rel.split("/"))
        fixture_signals = fixture_path_signals(rel_parts, None)
        if self._ci_fixture_job(rel, text):
            fixture_signals.append("ci-job:test/example")

        for cand in raw:
            self._evaluate_candidate(cand, fixture_signals)

    @staticmethod
    def _ci_fixture_job(rel: str, text: str) -> bool:
        # Job-name metadata, not content guessing: look for workflow job keys
        # whose own name contains fixture vocabulary.
        low = text.lower()
        for marker in ("test:", "example:", "demo:", "sample:", "mock:"):
            if marker in low:
                return True
        return False

    def _evaluate_candidate(self, cand: RawCandidate,
                            fixture_signals: list[str]) -> None:
        key_name = cand.key_path.rsplit(".", 1)[-1].rsplit("[", 1)[0]
        if not is_credential_name(key_name):
            # Shell/header and flag candidates carry their own semantic reason;
            # only those already credential-positioned reach here otherwise.
            if not any(r.startswith(("header:", "flag:")) for r in cand.extra_reasons):
                return
        verdict = analyze_value(cand.value, name_hint=key_name)
        if verdict is None:
            return
        f = Finding(
            rule_id=f"credscan/{cand.carrier}",
            file=cand.rel_path,
            line=cand.line,
            column=cand.column,
            end_column=cand.end_column,
            symbol=cand.key_path,
            value_preview=cand.value[:24] + ("…" if len(cand.value) > 24 else ""),
            value_full_len=len(cand.value),
            provider=verdict.provider,
            kind=verdict.kind,
            confidence=verdict.confidence,
            carrier=cand.carrier,
            reasons=verdict.reasons + [f"syntax:{cand.syntax}"] + cand.extra_reasons,
            structural=verdict.structural,
            checksum_ok=verdict.checksum_ok,
            normalized_entropy=verdict.entropy,
            fixture_signals=list(fixture_signals),
        )
        f.fingerprint = f.compute_fingerprint()
        self.findings.append(f)

    # ------------------------------------------------------------ stats/cache
    def _finalize_stats(self, t0: float) -> None:
        self.stats.elapsed_ms = int((time.perf_counter() - t0) * 1000)
        self.stats.findings_total = len(self.findings)
        self.stats.blocking = sum(1 for f in self.findings if f.blocking())
        self.stats.suppressed = sum(1 for f in self.findings if f.suppressed)

    def content_hash(self, rel_path: str) -> str:
        h = hashlib.sha256()
        with open(os.path.join(self.repo_root, rel_path), "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def load_cache(self) -> dict:
        path = os.path.join(self.cache_dir, "index.json")
        if not os.path.isfile(path):
            return {"version": 1, "files": {}}
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {"version": 1, "files": {}}

    def save_cache(self, payload: dict) -> None:
        os.makedirs(self.cache_dir, exist_ok=True)
        path = os.path.join(self.cache_dir, "index.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
