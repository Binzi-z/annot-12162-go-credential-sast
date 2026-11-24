"""Unit tests for the syntax/validation primitives (no fixture repo needed)."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from credscan.buildtags import evaluate  # noqa: E402
from credscan.goparser import decode_go_string  # noqa: E402
from credscan.model import is_credential_name, split_identifier  # noqa: E402
from credscan.secrets import (  # noqa: E402
    analyze_value, aws_access_key_checksum, normalized_entropy,
)
from credscan.textparse import (  # noqa: E402
    parse_dockerfile, parse_envfile, parse_json, parse_shell, parse_yaml,
)

FAILURES = []


def check(name: str, cond: bool, extra: str = "") -> None:
    status = "ok" if cond else "FAIL"
    print(f"  [{status}] {name}{(' — ' + extra) if extra and not cond else ''}")
    if not cond:
        FAILURES.append(name)


def test_identifier_semantics() -> None:
    print("identifier semantics")
    check("split camel", split_identifier("AccessKeyID") == ["access", "key", "id"])
    check("split snake", split_identifier("secret_access_key") == ["secret", "access", "key"])
    check("cred name const", is_credential_name("AccessKeyID"))
    check("cred name yaml", is_credential_name("secret-access-key"))
    check("cred name token", is_credential_name("authToken"))
    check("non-cred keyboard", not is_credential_name("KeyboardLayout"))
    check("non-cred region", not is_credential_name("region"))
    check("non-cred endpoint", not is_credential_name("Endpoint"))


def test_go_string_decode() -> None:
    print("go literal decode")
    check("interpreted", decode_go_string('"a\\nb\\t"') == "a\nb\t")
    check("hex escape", decode_go_string('"\\x41"') == "A")
    check("unicode", decode_go_string('"\\u0041"') == "A")
    check("raw", decode_go_string("`raw\\ntext`") == "raw\\ntext")


def test_checksum() -> None:
    print("aws checksum")
    check("famous key valid", aws_access_key_checksum("AKIAIOSFODNN7EXAMPLE"))
    check("random junk invalid", not aws_access_key_checksum("AKIA0000000000000000"))
    check("wrong length", not aws_access_key_checksum("AKIA"))


def test_classification() -> None:
    print("classification")
    real = analyze_value("AKIAIOSFODNN7EXAMPLE", name_hint="AccessKeyID")
    check("famous -> example", real is not None and real.confidence == "example")
    ph = analyze_value("your-access-key-here", name_hint="token")
    check("placeholder", ph is not None and ph.confidence == "placeholder")
    env = analyze_value("${AWS_ACCESS_KEY_ID}", name_hint="key")
    check("env ref", env is not None and env.confidence == "placeholder" and env.kind == "env-reference")
    none = analyze_value("cn-north-1", name_hint="region")
    check("non-secret none", none is None)
    secret = analyze_value("q7T2mW9xK4pL8vN3jR6hB1cF5dG0sY8aZ", name_hint="SigningSecret")
    check("entropy real", secret is not None and secret.confidence == "real")
    low = analyze_value("password123", name_hint="password")
    check("low entropy placeholder", low is not None and low.confidence == "placeholder")
    check("entropy range", 0.0 <= normalized_entropy("abcdefghijklmnop") <= 1.0)
    jwt = analyze_value(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlYm9keV9kZW1vXzAwMDAwMDAwMDA",
        name_hint="bearerToken")
    check("jwt structural", jwt is not None and jwt.kind == "jwt" and jwt.confidence == "real")


def test_build_tags() -> None:
    print("build constraints")
    active = frozenset({"linux", "amd64", "integration"})
    r1 = evaluate(["//go:build integration && linux"], active, frozenset({"linux"}), frozenset({"amd64"}))
    check("tag satisfied", r1.satisfied)
    r2 = evaluate(["//go:build windows"], active, frozenset({"linux"}), frozenset({"amd64"}))
    check("tag excluded", not r2.satisfied)
    r3 = evaluate(["//go:build !integration"], active, frozenset({"linux"}), frozenset({"amd64"}))
    check("negation", not r3.satisfied)
    r4 = evaluate(["// +build linux"], frozenset(), frozenset({"linux"}), frozenset({"amd64"}))
    check("legacy syntax", r4.satisfied)
    r5 = evaluate(["package p"], active, frozenset({"linux"}), frozenset({"amd64"}))
    check("no constraint", r5.satisfied)


def test_yaml_json() -> None:
    print("yaml/json parsers")
    yc = parse_yaml("w.yml", 'env:\n  AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE"\n')
    check("yaml leaf", len(yc) == 1 and yc[0].key_path == "env.AWS_ACCESS_KEY_ID"
          and yc[0].value == "AKIAIOSFODNN7EXAMPLE")
    yb = parse_yaml("b.yml", "script: |\n  export TOKEN='abc'\n  echo done\n")
    check("yaml block scalar does not recurse", all(c.key_path != "script.TOKEN" for c in yb))
    jc = parse_json("c.json", '{\n  "credentials": {\n    "secret_key": "abcdefghijklmnop"\n  }\n}\n')
    check("json leaf", len(jc) == 1 and jc[0].line == 3 and jc[0].key_path.endswith("secret_key"))


def test_docker_shell_env() -> None:
    print("dockerfile/shell/env parsers")
    dc = parse_dockerfile("Dockerfile",
                          'FROM scratch\nENV A="x" \\\n    SECRET_ACCESS_KEY="abcdefghijklmnop"\n')
    check("docker continuation", any(c.key_path == "SECRET_ACCESS_KEY" for c in dc))
    sc = parse_shell("d.sh",
                     '#!/bin/bash\nexport SIGNING_SECRET="abcdefghijklmnop"\n'
                     'client --secret-key="qrstuvwxyz123456"\n')
    check("shell export", any(c.syntax == "export-assignment" and c.key_path == "SIGNING_SECRET" for c in sc))
    check("shell flag", any(r.startswith("flag:") for c in sc for r in c.extra_reasons))
    ec = parse_envfile(".env", "export K1=abc\n# comment\nK2=def\n")
    check("envfile", len(ec) == 2 and {c.key_path for c in ec} == {"K1", "K2"})


def main() -> int:
    for fn in (test_identifier_semantics, test_go_string_decode, test_checksum,
               test_classification, test_build_tags, test_yaml_json,
               test_docker_shell_env):
        fn()
    print("-" * 60)
    if FAILURES:
        print(f"{len(FAILURES)} FAILURE(S): {FAILURES}")
        return 1
    print("all unit tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
