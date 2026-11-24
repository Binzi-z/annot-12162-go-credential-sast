"""Credential content validation.

Input is always a *decoded string literal value* taken from a syntax node
(Go interpreted/raw string, YAML scalar, JSON string, shell word, Dockerfile
word). We never see raw file text here.

Classification:
  real        — structural format match and (where defined) checksum/keyspace
                evidence, OR high-entropy secret at a credential-named position
                with no placeholder/example signals
  example     — famous documentation value, or secret-shaped value carrying an
                explicit example/sample/demo signal
  placeholder — template / env-reference / obvious dummy, or low-variation
                value at a credential position

This module contains no regex scans of source files; structural checks use
prefix/alphabet/length predicates and integer checksum arithmetic.
"""

from __future__ import annotations

import base64
import math
from dataclasses import dataclass
from typing import Optional

from .model import FAMOUS_EXAMPLES

# ---------------------------------------------------------------------------
# Entropy: Shannon entropy normalized to [0,1] over the alphabet actually used
# (base-26 for lowercase-only, base-62 for mixed, base-64 for +/ etc.).
# ---------------------------------------------------------------------------


def normalized_entropy(s: str) -> float:
    if len(s) < 8:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    alphabet = set(s)
    base = len(alphabet) if len(alphabet) > 1 else 2
    return h / math.log2(base)


def _all_in(s: str, alphabet: frozenset[str]) -> bool:
    return all(ch in alphabet for ch in s)


_B32 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_B32_CASE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz234567")
_B64 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX = frozenset("0123456789abcdefABCDEF")
_AZ09 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def aws_access_key_checksum(key: str) -> bool:
    """AWS access-key-id / GCP client-id base32 CRC check (public, offline).

    The last character of the id is a checksum over the preceding characters
    interpreted as base32 big-endian integers: checksum = (sum + len) % 32,
    mapped onto the base32 alphabet. Published in AWS docs tooling and used by
    independent scanners; it separates real ids from look-alike 20-char strings
    with ~1/32 false-acceptance on random data.
    """
    if len(key) != 20 or not _all_in(key, _B32):
        return False
    prefix = key[:-1]
    total = sum(_B32_INDEX[ch] for ch in prefix)
    # checksum char = base32[(sum(prefix indices) + len(prefix)) % 32]
    return _B32_ALPHABET[(total + len(prefix)) % 32] == key[-1]


_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_INDEX = {ch: i for i, ch in enumerate(_B32_ALPHABET)}


def _looks_like_pem(s: str) -> Optional[str]:
    # Structural marker check, not a regex: require the exact ASN.1 PEM fence
    # tokens and a base64 body of plausible length.
    begin = "-----BEGIN "
    end = "-----END "
    if begin not in s or end not in s or "PRIVATE KEY-----" not in s.split("\n", 1)[0]:
        return None
    header_line = s.split("\n", 1)[0]
    label = header_line.replace(begin, "").replace("-----", "").strip()
    if "PRIVATE KEY" not in label:
        return None
    body_lines = [ln.strip() for ln in s.splitlines()[1:] if ln.strip() and not ln.startswith("-----")]
    body = "".join(body_lines)
    if len(body) < 64 or not _all_in(body.rstrip("="), _B64 - {"="}):
        return None
    try:
        base64.b64decode(body, validate=True)
    except Exception:
        return None
    return label


def _looks_like_jwt(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 3 or not all(parts):
        return False
    for part in parts[:2]:
        try:
            base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        except Exception:
            return False
    return _all_in(parts[2].rstrip("="), _B64 - {"="})


@dataclass
class Verdict:
    confidence: str            # real | example | placeholder
    provider: str
    kind: str
    structural: bool
    checksum_ok: Optional[bool]
    entropy: float
    reasons: list[str]

    @property
    def evidence_rank(self) -> int:
        """Higher = stronger evidence. Drives fixture-suppression policy."""
        if self.structural and self.checksum_ok:
            return 4
        if self.structural:
            return 3
        if self.entropy >= 0.75:
            return 2
        if self.entropy >= 0.55:
            return 1
        return 0


# Provider structural signatures. Each entry:
# (provider, kind, tuple of accepted prefixes, exact lengths or None, alphabet)
_SIGNATURES = [
    ("aws", "access-key-id", ("AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA"), (20,), _B32),
    ("gcp", "service-account-id", ("100", "101", "102", "103", "104", "105", "106", "107", "108", "109"), (21,), _B32_CASE),
    ("github", "pat-classic", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), (40,), None),
    ("github", "pat-fine-grained", ("github_pat_",), (93,), None),
    ("github", "oauth-client-secret", ("9e64af0489b7153d",), (40,), _HEX),
    ("stripe", "secret-key", ("sk_live_",), None, None),
    ("stripe", "restricted-key", ("rk_live_",), None, None),
    ("stripe", "publishable-key", ("pk_live_",), None, None),
    ("alicloud", "access-key-id", ("LTAI",), (24,), _AZ09),
    ("tencent", "secret-id", ("AKID",), (36,), _AZ09),
    ("slack", "token", ("xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxe.xoxp-", "xoxe.xoxb-"), None, None),
    ("azure", "storage-account-key", None, (88,), _B64),
    ("gitlab", "pat", ("glpat-",), (27,), None),
]

_TESTMODE_PREFIXES = ("sk_test_", "rk_test_", "pk_test_")


def _env_reference(s: str) -> bool:
    """Template expansion / env indirection — not a secret, structural test."""
    if not s:
        return False
    if s.startswith("${") and s.endswith("}"):
        return True
    if s.startswith("$") and s[1:].replace("_", "").isalnum():
        return True
    if s.startswith("@") and ("@" in s[1:] or s[1:].isupper()):
        return True  # Dockerfile/BuildKit secret mounts, e.g. @env:NAME
    if s.startswith("{{") and s.endswith("}}"):
        return True  # helm/template
    if s.startswith("<") and s.endswith(">"):
        return True
    if s.startswith("%") and s.endswith("%"):
        return True
    return False


_PLACEHOLDER_WORDS = frozenset({
    "your", "you", "access", "key", "keys", "secret", "token", "password",
    "credential", "here", "changeme", "placeholder", "example", "sample",
    "dummy", "fake", "mock", "demo", "test", "tests", "redacted", "todo",
    "insert", "fill", "replace", "me", "unknown", "none", "null", "foo",
    "bar", "baz", "foobar", "xxxx", "xxx", "value",
})
_PLACEHOLDER_MARKERS = frozenset({
    "your", "changeme", "placeholder", "example", "sample", "dummy", "fake",
    "mock", "demo", "redacted", "todo", "insert", "fill", "replace", "xxxx",
    "xxx", "here", "unknown",
})
_DELIMITERS = "_-./: @+#,"
_GENERIC_WORDS = frozenset({
    "password", "secret", "credential", "credentials", "token", "apikey",
    "yourkey", "yoursecret",
})


def _placeholder_signal(s: str) -> Optional[str]:
    """Structural dummy detection — never substring matching, so a random
    high-entropy secret that happens to contain 'foo'/'test' stays real."""
    low = s.lower()
    compact = low.rstrip("=")
    if len(set(compact)) <= 3 and len(compact) >= 6:
        return "low-variation"
    if compact in _GENERIC_WORDS:
        return "generic-word"
    # Split on delimiters and digit runs; require every alphabetic token to be
    # placeholder vocabulary plus at least one explicit marker.
    tokens: list[str] = []
    buf: list[str] = []
    for ch in low:
        if ch in _DELIMITERS or ch.isdigit():
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    if not tokens:
        return None
    if all(t in _PLACEHOLDER_WORDS for t in tokens) and (
            len(tokens) > 1 or any(t in _PLACEHOLDER_MARKERS for t in tokens)):
        return "placeholder-words:" + ",".join(tokens[:4])
    return None


def analyze_value(raw: str, *, name_hint: str = "", min_secret_len: int = 12) -> Optional[Verdict]:
    """Classify a decoded literal value. Returns None when nothing credential
    is present at all (so callers can count 'safe' positions)."""
    if raw is None:
        return None
    s = raw.strip()
    if len(s) < 4:
        return None

    reasons: list[str] = []
    ent = normalized_entropy(s)
    ph = _placeholder_signal(s)
    is_famous = s in FAMOUS_EXAMPLES or any(s.startswith(v) and len(s) <= len(v) + 4 for v in FAMOUS_EXAMPLES)

    # 1) PEM private keys — strong structural evidence.
    pem_label = _looks_like_pem(s)
    if pem_label:
        if ph or is_famous:
            return Verdict("example" if is_famous else "placeholder", "generic", "pem-private-key",
                           True, None, ent, [f"pem-label:{pem_label}", ph or "famous-example"])
        return Verdict("real", "generic", "pem-private-key", True, None, ent,
                       [f"pem-label:{pem_label}", "base64-body-valid"])

    # 2) JWT with decodable header/payload.
    if _looks_like_jwt(s):
        conf = "placeholder" if ph else ("example" if is_famous else "real")
        return Verdict(conf, "generic", "jwt", True, None, ent,
                       ["jwt-three-segments-decodable"] + ([ph] if ph else []))

    # 3) Provider signatures.
    for provider, kind, prefixes, lengths, alphabet in _SIGNATURES:
        sig_reasons: list[str] = []
        for prefix in (prefixes or ("",)):
            if prefix and not s.startswith(prefix):
                continue
            body = s
            if alphabet is not None and not _all_in(body, alphabet):
                continue
            if lengths is not None and len(body) not in lengths:
                continue
            checksum = None
            if provider == "aws":
                checksum = aws_access_key_checksum(body)
                sig_reasons.append(f"aws-crc-checksum:{'ok' if checksum else 'fail'}")
            sig_reasons.append(f"prefix:{prefix or '(none)'}")
            # Famous example short-circuit (AKIAIOSFODNN7EXAMPLE is checksum-valid
            # by construction — the doc key was built to pass; name match wins).
            if is_famous:
                return Verdict("example", provider, kind, True, checksum, ent,
                               sig_reasons + ["famous-documented-example"])
            if ph:
                return Verdict("placeholder", provider, kind, True, checksum, ent,
                               sig_reasons + [ph])
            if checksum is False:
                # Correct family, failed checksum -> shaped but not a live id.
                return Verdict("example", provider, kind, True, False, ent,
                               sig_reasons + ["checksum-failed-lookalike"])
            return Verdict("real", provider, kind, True, checksum, ent, sig_reasons)

    # 4) Test-mode provider keys (Stripe sk_test_ ...): structurally provider
    #    shaped but explicitly non-production.
    for prefix in _TESTMODE_PREFIXES:
        if s.startswith(prefix) and len(s) > len(prefix) + 6:
            return Verdict("example", "stripe", "test-mode-key", True, None, ent,
                           [f"prefix:{prefix}", "provider-test-mode"])

    # 5) Env/template references — credential slot, no embedded secret.
    if _env_reference(s):
        return Verdict("placeholder", "generic", "env-reference", False, None, ent,
                       ["env-or-template-indirection"])

    # 6) Bare checksum-valid AWS/GCP id without a credential name hint still
    #    counts (defense for literals passed straight into sinks).
    if len(s) == 20 and _all_in(s, _B32) and aws_access_key_checksum(s):
        if is_famous:
            return Verdict("example", "aws", "access-key-id", True, True, ent, ["famous-documented-example"])
        return Verdict("real", "aws", "access-key-id", True, True, ent, ["bare-literal-crc-ok"])

    # 7) Generic credential-named position: entropy-based fallback.
    if name_hint:
        if ph:
            return Verdict("placeholder", "generic", "generic-secret", False, None, ent, [ph])
        if is_famous:
            return Verdict("example", "generic", "generic-secret", False, None, ent, ["famous-documented-example"])
        # Short values at a credential slot are dummy secrets, not live keys:
        # real production secrets are long by construction.
        if len(s) < min_secret_len:
            return Verdict("placeholder", "generic", "generic-secret", False, None, ent,
                           [f"short-credential-value:{len(s)}"])
        if len(s) >= min_secret_len and ent >= 0.75 and " " not in s and "\n" not in s:
            return Verdict("real", "generic", "high-entropy-secret", False, None, ent,
                           [f"entropy={ent:.2f}", "credential-named-position"])
        if len(s) >= min_secret_len and ent >= 0.55:
            return Verdict("example", "generic", "low-confidence-literal", False, None, ent,
                           [f"entropy={ent:.2f}", "weak-evidence"])
        return Verdict("placeholder", "generic", "generic-secret", False, None, ent,
                       ["low-entropy"])
    return None
