"""Deterministic fixture and labeled-dataset builder.

Outputs:
  fixtures/demo-go/      integration repo mirroring the incident's four carriers
  fixtures/dataset/      50 labeled cases + labels.json
  fixtures/perf-repo/    (on demand) ~200k LOC synthetic repo for timing

All credential material is generated locally; AWS-style ids are checksum-valid
by construction but are fake values that were never issued.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from credscan.secrets import _B32_ALPHABET, _B32_INDEX, aws_access_key_checksum  # noqa: E402

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
HEX = "0123456789abcdef"
AZ09 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


class Lcg:
    def __init__(self, seed: int = 0x1234ABCD):
        self.state = seed & 0x7FFFFFFF

    def n(self, mod: int) -> int:
        self.state = (self.state * 1103515245 + 12345) & 0x7FFFFFFF
        return self.state % mod

    def pick(self, alphabet: str, length: int) -> str:
        return "".join(alphabet[self.n(len(alphabet))] for _ in range(length))


def aws_id(prefix: str = "AKIA", tag: str = "F4KETEST") -> str:
    rnd = Lcg(ord(prefix[0]) * 7919 + len(tag) * 104729)
    body = list(prefix + tag)
    while len(body) < 19:
        body.append(_B32_ALPHABET[rnd.n(32)])
    body = body[:19]
    total = sum(_B32_INDEX[c] for c in body)
    body.append(_B32_ALPHABET[(total + 19) % 32])
    key = "".join(body)
    assert aws_access_key_checksum(key)
    return key


def aws_id_bad_checksum() -> str:
    key = aws_id("AKIA", "BR0KENSUM")
    idx = (_B32_INDEX[key[-1]] + 7) % 32  # guarantee a different checksum char
    return key[:-1] + _B32_ALPHABET[idx]


def github_pat() -> str:
    return "ghp_" + Lcg(0x47).pick(HEX, 36)


def github_fg_pat() -> str:
    body = Lcg(0x48).pick(B64.replace("+/", "AB"), 81)
    return "github_pat_" + body


def stripe_live() -> str:
    return "sk_live_" + Lcg(0x53).pick(B64.replace("+/", "ab"), 24)


def stripe_test() -> str:
    return "sk_test_" + Lcg(0x54).pick(B64.replace("+/", "ab"), 24)


def alicloud_id() -> str:
    return "LTAI" + Lcg(0x41).pick(AZ09, 20)


def tencent_id() -> str:
    return "AKID" + Lcg(0x54).pick(AZ09, 32)


def gitlab_pat() -> str:
    return "glpat-" + Lcg(0x47).pick(B64.replace("+/", "AB"), 20)


def slack_token() -> str:
    return "xoxb-" + Lcg(0x53).pick("0123456789abcdef-", 24)


def azure_storage_key() -> str:
    return Lcg(0x41).pick(B64, 88)


def entropy_secret(seed: int, length: int = 40) -> str:
    return Lcg(seed).pick(B64, length)


def weak_secret(seed: int) -> str:
    # 12 chars over a small alphabet -> real Shannon entropy around 3.5 bits
    return Lcg(seed).pick("Ab3Xy9Pq2Mn7", 12)


def jwt_token() -> str:
    def b64u(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64u(json.dumps({"sub": "demo-svc", "exp": 1893456000}, separators=(",", ":")).encode())
    sig = Lcg(0x4A).pick(B64.replace("+/", "ab"), 43)
    return f"{header}.{payload}.{sig}"


def pem_key() -> str:
    body_blob = Lcg(0x50).pick(B64, 768)
    lines = [body_blob[i:i + 64] for i in range(0, len(body_blob), 64)]
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----"


FAMOUS_ID = "AKIAIOSFODNN7EXAMPLE"
FAMOUS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# --------------------------------------------------------------------------
# Integration repo
# --------------------------------------------------------------------------

def write(rel_path: str, content: str) -> None:
    abs_path = os.path.join(ROOT, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def build_demo_repo() -> None:
    base = "fixtures/demo-go"
    write(f"{base}/go.mod", "module example.invalid/demo-go\n\ngo 1.22\n")

    id_a = aws_id("AKIA", "F4KETEST01")
    id_b = aws_id("AKIA", "F4KETEST02")
    write(f"{base}/internal/config/config.go", f"""// Package config holds service-wide credential constants.
package config

// All key material is synthetic; ids are checksum-valid but never issued.
const (
\tAccessKeyID     = "{id_a}"
\tSecretAccessKey = "{entropy_secret(11)}"
\tregion          = "cn-north-1"
)

// Concatenated constant: folding must recover the full literal across symbols.
const keyPartA = "{id_b[:16]}"
const keyPartB = "{id_b[16:]}"
const CombinedAccessKey = keyPartA + keyPartB

// Placeholder and example values that must NOT be classified real.
const (
\tPlaceholderToken = "your-access-key-here"
\tExampleAWSKey    = "{FAMOUS_ID}"
\tEnvIndirection   = "${{AWS_ACCESS_KEY_ID}}"
\tTemplateRef      = "{{{{ .Values.secretKey }}}}"
)

var SharedSigningSecret = "{entropy_secret(22)}"
""")

    write(f"{base}/internal/config/misc.go", f"""package config

// Non-secret constants sharing vocabulary; must not trigger.
const (
\tKeyboardLayout = "us-intl"
\tTimeoutSeconds = 30
\tEndpoint       = "https://sts.example.invalid"
)

// Low-entropy dummy at a credential position -> placeholder.
var DevPassword = "password123"
""")

    write(f"{base}/internal/cloudaws/client.go", f"""// Package cloudaws consumes config through cross-package taint.
package cloudaws

import (
\t"example.invalid/demo-go/internal/config"
)

type Client struct {{
\tAccessKey string
\tSecretKey string
\tRegion    string
}}

func NewClient() *Client {{
\tc := &Client{{
\t\tAccessKey: config.AccessKeyID,
\t\tSecretKey: config.SecretAccessKey,
\t\tRegion:    "cn-north-1",
\t}}
\tc.sendSignedRequest(config.SharedSigningSecret)
\treturn c
}}

func (c *Client) sendSignedRequest(signingToken string) {{
\t_ = signingToken
}}

func (c *Client) RotateKey(newSecret string) {{
\tc.SecretKey = newSecret
\tc.AccessKey = "{aws_id('AKIA', 'F4KETEST03')}"
}}
""")

    write(f"{base}/internal/cloudaws/tagged_integration.go", f"""//go:build integration

package cloudaws

// Tag-gated file: still analyzed, constraint recorded on the finding.
const IntegrationAccessKey = "{aws_id('AKIA', 'T4GGEDFILE')}"
""")

    write(f"{base}/internal/gen/zz_generated.go", f"""// Code generated by mockgen v0.0.0; DO NOT EDIT.
// Source: internal/proto/auth.proto

package gen

const GeneratedClientSecret = "{github_pat()}"
""")

    write(f"{base}/internal/cloudaws/testdata/fixtures.go", f"""package testdata

// Fixture directory: weak-evidence literal gets suppressed; a structurally
// valid key here would still be reported as real.
var FixtureSigningToken = "{weak_secret(9)}"
var FixtureLiveKey      = "{aws_id('AKIA', '1NF1XTRUE')}"
""")

    write(f"{base}/deploy/config.yaml", f"""cloud:
  region: cn-north-1
  access_key_id: "{aws_id('AKIA', 'Y4MLV4LUES')}"
  secret_access_key: "{entropy_secret(33)}"
  endpoint: "https://sts.example.invalid"
""")

    write(f"{base}/deploy/service-account.json", json.dumps({
        "type": "service_account",
        "project_id": "demo-project",
        "client_email": "svc@demo-project.iam.gserviceaccount.com",
        "private_key": pem_key(),
        "token_uri": "https://oauth2.example.invalid/token",
        "client_secret": entropy_secret(44),
    }, indent=2) + "\n")

    write(f"{base}/deploy/Dockerfile", f"""FROM registry.example.invalid/golang:1.22 AS build
ENV AWS_ACCESS_KEY_ID={aws_id('AKIA', 'D0CKER1NV')}
ARG DEPLOY_SECRET="{entropy_secret(55)}"
LABEL maintainer="platform@example.invalid"
RUN echo "build step"
COPY . /src
ENTRYPOINT ["/usr/local/bin/demo-svc"]
""")

    write(f"{base}/.github/workflows/deploy.yml", f"""name: deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: "{aws_id('AKIA', 'C1SCR1PT01')}"
      DEPLOY_SIGNING_SECRET: "{entropy_secret(66)}"
    steps:
      - uses: actions/checkout@v4
      - name: rotate
        run: ./scripts/rotate.sh
""")

    write(f"{base}/scripts/rotate.sh", f"""#!/usr/bin/env bash
set -euo pipefail
export TENCENT_SECRET_ID="{tencent_id()}"
curl -H "Authorization: Bearer {jwt_token()}" \\
  --secret-key="{entropy_secret(77)}" \\
  https://iam.example.invalid/rotate
""")

    write(f"{base}/deploy/.env", f"""APP_ENV=production
AWS_ACCESS_KEY_ID={aws_id('AKIA', 'ENVF1L3001')}
SIGNING_SECRET={entropy_secret(88)}
LOG_LEVEL=info
""")


# --------------------------------------------------------------------------
# 50 labeled cases
# --------------------------------------------------------------------------

def _go_const(name: str, value: str, header: str = "package cases\n\n") -> str:
    return f'{header}const {name} = "{value}"\n'


def build_dataset() -> None:
    base = "fixtures/dataset/cases"
    if os.path.exists(os.path.join(ROOT, "fixtures/dataset")):
        shutil.rmtree(os.path.join(ROOT, "fixtures/dataset"))
    labels: list[dict] = []

    def case(cid: str, filename: str, content: str, expect: str,
             suppressed: bool = False, note: str = "") -> None:
        rel = f"{base}/{cid}/{filename}"
        write(rel, content)
        labels.append({"case": cid, "file": f"{cid}/{filename}",
                       "expect": expect, "suppressed": suppressed, "note": note})

    # ----- 28 real cases ------------------------------------------------
    case("01-go-const-aws-id", "a.go", _go_const("AccessKeyID", aws_id()), "real")
    case("02-go-const-secret", "a.go",
         _go_const("SecretAccessKey", entropy_secret(101)), "real")
    case("03-go-var-entropy", "a.go",
         f'package cases\n\nvar SigningToken = "{entropy_secret(102)}"\n', "real")
    folded = aws_id("AKIA", "F0LDC0NST1")
    case("04-go-concat-fold", "a.go",
         f'package cases\n\nconst partA = "{folded[:16]}"\nconst partB = '
         f'"{folded[16:]}"\nconst CombinedAccessKey = partA + partB\n', "real")
    write(f"{base}/05-cross-pkg/a/a.go",
          f'package a\n\nconst RemoteAccessKey = "{aws_id("AKIA", "CR0SSPKG01")}"\n')
    write(f"{base}/05-cross-pkg/b/b.go",
          'package b\n\nimport "example.invalid/ds/05-cross-pkg/a"\n\n'
          'func Use() string { return a.RemoteAccessKey }\n')
    labels.append({"case": "05-cross-pkg", "file": "05-cross-pkg/a/a.go",
                   "expect": "real", "suppressed": False, "note": "cross-package origin"})
    case("06-build-tagged", "tagged.go",
         f'//go:build integration\n\npackage cases\n\nconst IntegrationAccessKey = '
         f'"{aws_id("AKIA", "T4GGEDC4SE")}"\n', "real", note="build constraint recorded")
    case("07-generated", "zz_generated.go",
         f'// Code generated by tool; DO NOT EDIT.\n\npackage cases\n\n'
         f'const GeneratedClientSecret = "{github_pat()}"\n', "real",
         note="generated code still analyzed")
    case("08-composite-field", "a.go",
         'package cases\n\ntype Cfg struct {\n\tSecretKey string\n}\n\n'
         f'var Global = Cfg{{SecretKey: "{entropy_secret(108)}"}}\n', "real")
    case("09-selector-write", "a.go",
         'package cases\n\ntype Client struct {\n\tAccessKey string\n}\n\n'
         'func (c *Client) Rotate() {\n\tc.AccessKey = "' + aws_id("AKIA", "SELWR1TE01") + '"\n}\n',
         "real")
    case("10-sink-call-arg", "a.go",
         'package cases\n\nfunc NewS3Client(accessKey string) *int { _ = accessKey; return nil }\n\n'
         f'var C = NewS3Client("{entropy_secret(110)}")\n', "real")
    case("11-yaml-aws-id", "workflow.yml",
         f'env:\n  AWS_ACCESS_KEY_ID: "{aws_id("AKIA", "Y4MLC4SE11")}"\n', "real")
    case("12-yaml-secret", "values.yaml",
         f'cloud:\n  secret_access_key: "{entropy_secret(112)}"\n', "real")
    case("13-json-github-pat", "cfg.json",
         json.dumps({"credentials": {"github_token": github_pat()}}, indent=2) + "\n", "real")
    case("14-dockerfile-env", "Dockerfile",
         f'FROM scratch\nENV DEPLOY_SECRET="{entropy_secret(114)}"\n', "real")
    case("15-dockerfile-arg", "Dockerfile",
         f'FROM scratch\nARG ALICLOUD_ACCESS_KEY="{alicloud_id()}"\n', "real")
    case("16-shell-export", "deploy.sh",
         f'#!/usr/bin/env bash\nexport SIGNING_SECRET="{entropy_secret(116)}"\n', "real")
    case("17-shell-flag", "call.sh",
         f'#!/usr/bin/env bash\nclient --secret-key="{entropy_secret(117)}"\n', "real")
    case("18-shell-heredoc", "call.sh",
         '#!/usr/bin/env bash\ncat <<EOF > /tmp/cfg\n'
         f'SECRET_ACCESS_KEY="{entropy_secret(118)}"\nEOF\n', "real")
    case("19-envfile-aws-id", ".env",
         f"AWS_ACCESS_KEY_ID={aws_id('AKIA', 'ENVC4SE19')}\n", "real")
    case("20-pem-go", "key.go",
         "package cases\n\nconst PrivatePEM = `" + pem_key() + "`\n", "real")
    case("21-jwt-yaml", "cfg.yaml",
         f'auth:\n  bearer_token: "{jwt_token()}"\n', "real")
    case("22-stripe-live", "a.go", _go_const("StripeSecretKey", stripe_live()), "real")
    case("23-alicloud-json", "cfg.json",
         json.dumps({"access_key_id": alicloud_id()}) + "\n", "real")
    case("24-tencent-shell", "c.sh",
         f'#!/usr/bin/env bash\nexport TENCENT_SECRET_ID="{tencent_id()}"\n', "real")
    case("25-gitlab-yaml", "cfg.yaml",
         f'token: "{gitlab_pat()}"\n', "real")
    case("26-azure-envfile", "storage.env",
         f"STORAGE_ACCOUNT_KEY={azure_storage_key()}\n", "real")
    case("27-slack-dockerfile", "Dockerfile",
         f'FROM scratch\nENV SLACK_TOKEN="{slack_token()}"\n', "real")
    case("28-fixture-real-suppressed", "mock/a.go",
         f'package mock\n\nvar FixtureSigningToken = "{entropy_secret(128)}"\n',
         "real", suppressed=True, note="weak evidence + fixture path -> suppressed")

    # ----- 7 example cases ----------------------------------------------
    case("29-famous-key-go", "a.go", _go_const("ExampleAWSKey", FAMOUS_ID), "example")
    case("30-famous-secret-yaml", "cfg.yaml",
         f'aws_secret_access_key: "{FAMOUS_SECRET}"\n', "example")
    case("31-stripe-test-mode", "a.go", _go_const("StripeTestKey", stripe_test()), "example")
    case("32-checksum-fail", "cfg.json",
         json.dumps({"access_key_id": aws_id_bad_checksum()}) + "\n", "example")
    case("33-weak-evidence-env", "weak.env",
         f"AWS_ACCESS_KEY_ID={aws_id_bad_checksum()}\n", "example",
         note="correct family, failed checksum -> lookalike")
    case("34-famous-key-shell", "c.sh",
         f'#!/usr/bin/env bash\nexport AWS_ACCESS_KEY_ID="{FAMOUS_ID}"\n', "example")
    case("35-weak-evidence-docker", "Dockerfile",
         f'FROM scratch\nENV AWS_ACCESS_KEY_ID="{aws_id_bad_checksum()}"\n', "example")

    # ----- 7 placeholder cases ------------------------------------------
    case("36-env-ref-go", "a.go",
         'package cases\n\nconst AccessKeyRef = "${AWS_ACCESS_KEY_ID}"\n', "placeholder")
    case("37-template-yaml", "cfg.yaml", 'token: "{{ .Values.token }}"\n', "placeholder")
    case("38-your-key-go", "a.go",
         'package cases\n\nconst PlaceholderToken = "your-access-key-here"\n', "placeholder")
    case("39-password-json", "cfg.json",
         json.dumps({"password": "password123"}) + "\n", "placeholder")
    case("40-xxxx-shell", "c.sh",
         '#!/usr/bin/env bash\nexport API_TOKEN="xxxx-xxxx-xxxx"\n', "placeholder")
    case("41-changeme-docker", "Dockerfile",
         'FROM scratch\nENV ADMIN_PASSWORD="changeme"\n', "placeholder")
    case("42-insert-envfile", "p.env", "CLIENT_SECRET=<INSERT_SECRET_HERE>\n", "placeholder")

    # ----- 8 negative cases ---------------------------------------------
    case("43-negative-keyboard", "a.go",
         'package cases\n\nconst KeyboardLayout = "us-intl"\n', "none")
    case("44-negative-region", "a.go",
         'package cases\n\nconst region = "cn-north-1"\n', "none")
    case("45-negative-yaml", "cfg.yaml",
         'cloud:\n  region: cn-north-1\n  endpoint: "https://sts.example.invalid"\n', "none")
    case("46-negative-json", "cfg.json",
         json.dumps({"region": "cn-north-1", "timeout_seconds": 30,
                     "endpoint": "https://sts.example.invalid"}, indent=2) + "\n", "none")
    case("47-negative-shell", "run.sh",
         '#!/usr/bin/env bash\necho "deploy step"\nls -la /srv\n', "none")
    case("48-negative-envfile", "app.env",
         "APP_ENV=production\nLOG_LEVEL=info\nPATH=/usr/local/bin\n", "none")
    case("49-negative-dockerfile", "Dockerfile",
         "FROM scratch\nENV PATH=/usr/local/bin\nLABEL maintainer=platform\n", "none")
    case("50-negative-bare-lookalike", "a.go",
         f'package cases\n\nconst CorrelationID = "{aws_id_bad_checksum()}"\n', "none",
         note="non-credential position is never analyzed")

    with open(os.path.join(ROOT, "fixtures/dataset/labels.json"), "w",
              encoding="utf-8", newline="\n") as fh:
        json.dump({"version": 1, "count": len(labels), "labels": labels},
                  fh, indent=2)
    print(f"dataset built: {len(labels)} labeled cases")


# --------------------------------------------------------------------------
# Performance repo
# --------------------------------------------------------------------------

def build_perf_repo(target_loc: int = 200_000) -> None:
    base = "fixtures/perf-repo"
    if os.path.exists(os.path.join(ROOT, base)):
        shutil.rmtree(os.path.join(ROOT, base))
    write(f"{base}/go.mod", "module example.invalid/perf\n\ngo 1.22\n")
    written = 0
    pkg_idx = 0
    while written < target_loc:
        pkg = f"pkg{pkg_idx:04d}"
        content = [f"package {pkg}", ""]
        for j in range(120):  # ~120 logical lines per file
            content.append(f"// field {j} documentation line")
            content.append(f"const Value{j} = \"constant-text-{j}-{pkg_idx}\"")
            content.append(f"var Endpoint{j} = \"https://service{j}.example.invalid/api\"")
            written += 3
        # Sprinkle one real secret every ~40 files so the run is non-trivial.
        if pkg_idx % 40 == 0:
            content.append(f"const AccessKeyID{pkg_idx} = \"{aws_id('AKIA', f'PERF{pkg_idx:04d}'[:10])}\"")
        write(f"{base}/{pkg}/file.go", "\n".join(content) + "\n")
        pkg_idx += 1
    print(f"perf repo built: ~{written} LOC across {pkg_idx} packages")


if __name__ == "__main__":
    build_demo_repo()
    build_dataset()
    if "--perf" in sys.argv:
        build_perf_repo()
    print("done")
