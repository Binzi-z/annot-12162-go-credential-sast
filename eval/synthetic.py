"""Deterministic synthetic fixture generator.

Generates checksum-valid (but entirely fake) cloud credential literals so the
fixture repo is reproducible and contains nothing live. A tiny LCG keeps the
output deterministic — no Math.random-style nondeterminism.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from credscan.secrets import _B32_ALPHABET, _B32_INDEX  # noqa: E402

_LCG_STATE = 0x1234ABCD


def _next_int(mod: int) -> int:
    global _LCG_STATE
    _LCG_STATE = (_LCG_STATE * 1103515245 + 12345) & 0x7FFFFFFF
    return _LCG_STATE % mod


def synthetic_aws_id(prefix: str = "AKIA", tag: str = "F4KETEST") -> str:
    """Build a 20-char base32 id whose last char satisfies the AWS CRC."""
    body = list(prefix + tag)
    while len(body) < 19:
        body.append(_B32_ALPHABET[_next_int(32)])
    body = body[:19]
    total = sum(_B32_INDEX[ch] for ch in body)
    body.append(_B32_ALPHABET[(total + 19) % 32])
    key = "".join(body)
    assert len(key) == 20
    return key


def synthetic_b64_secret(seed_text: str, length: int = 40) -> str:
    """Deterministic high-entropy-looking base64-ish secret from a seed."""
    alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                "0123456789+/")
    out = []
    state = sum(ord(c) * (i + 7) for i, c in enumerate(seed_text)) & 0x7FFFFFFF
    for _ in range(length):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(alphabet[state % 64])
    return "".join(out)


if __name__ == "__main__":
    # Smoke values printed for fixture authoring.
    for _ in range(4):
        print(synthetic_aws_id())
    print(synthetic_b64_secret("demo-secret-signing", 40))
