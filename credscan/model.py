"""Core data model and identifier semantics.

The credential *vocabulary* below is the only "naming" knowledge in the tool.
It is matched against identifier/key names obtained from syntax nodes (variable
names, struct fields, YAML keys, shell assignment LHS), never against raw file
contents.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

# Stems (after splitting camelCase / snake_case / digit boundaries) that mark
# an identifier as a credential-bearing position.
CREDENTIAL_STEMS = frozenset(
    {
        "ak", "sk", "key", "secret", "token", "password", "passwd", "pwd",
        "credential", "credentials", "creds", "auth", "apikey", "api_key",
        "accesskey", "access_key", "secretkey", "secret_key", "private",
        "privkey", "private_key", "cert", "certificate", "jwt", "bearer",
        "pat", "sig", "signature", "hmac", "clientsecret", "client_secret",
        "appsecret", "app_secret", "encryptionkey", "encryption_key",
        "connectionstring", "connection_string", "dsn", "webhook",
    }
)

# Exact multi-word names (normalized by lower-casing + removing separators).
CREDENTIAL_PHRASES = frozenset(
    {
        "accesskey", "accesskeyid", "accesskeyidentifier", "secretaccesskey",
        "secretkey", "awsaccesskeyid", "awssecretaccesskey", "apikey",
        "apisecret", "clientsecret", "appsecret", "privatekey",
        "accountkey", "account_name", "accountkey", "securitytoken",
        "sessiontoken", "refreshtoken", "accesstoken", "personalaccesstoken",
        "connectionstring", "clienttoken",
    }
)

# Words that signal fake / sample / test intent. Applied to identifiers and
# file paths, never used to silently drop a structurally valid live key.
FIXTURE_WORDS = frozenset(
    {
        "test", "tests", "testdata", "fixture", "fixtures", "mock", "mocks",
        "fake", "fakes", "dummy", "sample", "samples", "example", "examples",
        "demo", "sandbox", "stub", "stubs", "doc", "docs", "tutorial",
    }
)

PLACEHOLDER_TOKENS = (
    "example", "sample", "dummy", "fake", "placeholder", "changeme",
    "redacted", "your_", "your-", "replace_me", "replace-me", "todo",
    "xxx", "mock", "test", "demo", "foobar", "foo", "bar", "baz",
    "here", "insert", "fill", "unknown", "none", "null",
)

# Well-known public documentation example values (AWS docs etc.). Exact match
# or prefix match — these are published fake keys and must never be called real.
FAMOUS_EXAMPLES = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AKIAI44QH8DHBEXAMPLE",
        "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    }
)


def split_identifier(name: str) -> list[str]:
    """Split camelCase / PascalCase / snake_case / kebab-case into stems."""
    out: list[str] = []
    buf: list[str] = []
    prev_lower = False
    for ch in name:
        if ch in "_-.:/ ":
            if buf:
                out.append("".join(buf).lower())
                buf = []
            prev_lower = False
            continue
        if ch.isupper() and prev_lower:
            if buf:
                out.append("".join(buf).lower())
            buf = [ch.lower()]
            prev_lower = False
            continue
        if ch.isdigit():
            if buf:
                out.append("".join(buf).lower())
                buf = []
            out.append(ch)
            prev_lower = False
            continue
        buf.append(ch)
        prev_lower = ch.islower()
    if buf:
        out.append("".join(buf).lower())
    return out


def is_credential_name(name: str) -> bool:
    """Identifier-semantics check: does this syntactic position hold a secret?"""
    if not name:
        return False
    normalized = name.lower().replace("_", "").replace("-", "")
    if normalized in CREDENTIAL_PHRASES:
        return True
    stems = split_identifier(name)
    for i, stem in enumerate(stems):
        if stem in CREDENTIAL_STEMS:
            # Bare "key"/"secret"/"token" is meaningful; "keyboard" would have
            # been split differently, but guard against obvious non-secrets.
            return True
        # two-stem compounds such as access+key, secret+key
        if i + 1 < len(stems):
            pair = stem + stems[i + 1]
            if pair in CREDENTIAL_PHRASES:
                return True
    return False


def fixture_path_signals(rel_parts: tuple[str, ...], package_name: str | None) -> list[str]:
    """Return the fixture-context signals present in path/package metadata."""
    signals: list[str] = []
    for part in rel_parts[:-1]:
        low = part.lower()
        for word in FIXTURE_WORDS:
            if low == word or low.startswith(word + "_") or low.endswith("_" + word):
                signals.append(f"path:{part}")
                break
    fname = rel_parts[-1].lower() if rel_parts else ""
    if fname.endswith("_test.go") or "_test." in fname:
        signals.append("test-file")
    if package_name:
        for tok in split_identifier(package_name):
            if tok in FIXTURE_WORDS:
                signals.append(f"package:{package_name}")
                break
    return signals


@dataclass
class Usage:
    """One point in the propagation chain after the originating literal."""

    file: str
    line: int  # 1-based
    column: int  # 1-based
    kind: str  # reference | assignment | call-arg | sink | return | field | dynamic-sink
    snippet: str


@dataclass
class Finding:
    rule_id: str
    file: str
    line: int
    column: int
    end_column: int
    symbol: str                      # syntactic position, e.g. pkg.ConstName / yaml key path
    value_preview: str               # truncated, for snippets only
    value_full_len: int
    provider: str
    kind: str                        # access-key-id | secret-key | token | pem | ...
    confidence: str                  # real | example | placeholder
    carrier: str                     # go-const | go-var | go-field | yaml | json | dockerfile | shell | envfile
    reasons: list[str] = field(default_factory=list)
    structural: bool = False
    checksum_ok: Optional[bool] = None
    normalized_entropy: float = 0.0
    usages: list[Usage] = field(default_factory=list)
    build_constraint: Optional[str] = None
    generated: bool = False
    fixture_signals: list[str] = field(default_factory=list)
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    fingerprint: str = ""

    def sarif_level(self) -> str:
        if self.suppressed:
            return "warning"
        if self.confidence == "real":
            return "error"
        return "note"

    def blocking(self) -> bool:
        return self.confidence == "real" and not self.suppressed

    def compute_fingerprint(self) -> str:
        h = hashlib.sha256()
        h.update(self.file.encode("utf-8", "replace"))
        h.update(b"|")
        h.update(self.symbol.encode("utf-8", "replace"))
        h.update(b"|")
        h.update(str(self.value_full_len).encode())
        h.update(b"|")
        h.update(self.value_preview[:8].encode("utf-8", "replace"))
        return h.hexdigest()[:16]
