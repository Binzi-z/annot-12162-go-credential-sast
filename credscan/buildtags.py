"""Go build-constraint evaluation (//go:build and legacy // +build).

Grammar for //go:build (Go 1.17+):

    Expr   = Or
    Or     = And { "||" And }
    And    = Not { "&&" Not }
    Not    = "!" Not | Atom
    Atom   = Tag | "(" Expr ")"
    Tag    = identifier [ "." identifier ] [ "," version ]

Legacy lines are AND of space-separated options, where options within a
comma group are OR'd; '!' negates.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConstraintResult:
    satisfied: bool
    expression: str | None
    reason: str


class _Tokenizer:
    def __init__(self, text: str):
        self.tokens = text.replace("(", " ( ").replace(")", " ) ").split()
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> str | None:
        tok = self.peek()
        if tok is not None:
            self.pos += 1
        return tok


def _eval_tag(tag: str, tags: frozenset[str], goos: frozenset[str], goarch: frozenset[str]) -> bool:
    # versioned tags like go1.22
    if tag.startswith("go1."):
        return True  # toolchain assumed modern; version gates never hide code
    base = tag.split(",", 1)[0]
    if "." in base:
        key, value = base.split(".", 1)
        if key == "goos":
            return value in goos
        if key == "goarch":
            return value in goarch
        return False
    if base in ("goos", "goarch"):
        return False
    return base in tags or base in goos or base in goarch


def _parse_or(tk: _Tokenizer, tags, goos, goarch) -> bool:
    value = _parse_and(tk, tags, goos, goarch)
    while tk.peek() == "||":
        tk.next()
        value = value or _parse_and(tk, tags, goos, goarch)
    return value


def _parse_and(tk: _Tokenizer, tags, goos, goarch) -> bool:
    value = _parse_not(tk, tags, goos, goarch)
    while tk.peek() == "&&":
        tk.next()
        value = value and _parse_not(tk, tags, goos, goarch)
    return value


def _parse_not(tk: _Tokenizer, tags, goos, goarch) -> bool:
    if tk.peek() == "!":
        tk.next()
        return not _parse_not(tk, tags, goos, goarch)
    if tk.peek() == "(":
        tk.next()
        value = _parse_or(tk, tags, goos, goarch)
        if tk.peek() == ")":
            tk.next()
        return value
    tag = tk.next()
    if tag is None:
        return False
    return _eval_tag(tag, tags, goos, goarch)


def _eval_go_build(expr: str, tags: frozenset[str], goos: frozenset[str], goarch: frozenset[str]) -> bool:
    return _parse_or(_Tokenizer(expr), tags, goos, goarch)


def _eval_legacy_line(line: str, tags: frozenset[str], goos: frozenset[str], goarch: frozenset[str]) -> bool:
    # AND over space-separated groups; OR over comma-separated options.
    for group in line.split():
        satisfied = False
        for option in group.split(","):
            negate = option.startswith("!")
            tag = option.lstrip("!")
            ok = _eval_tag(tag, tags, goos, goarch)
            if negate:
                ok = not ok
            satisfied = satisfied or ok
        if not satisfied:
            return False
    return True


def evaluate(source_lines: list[str], active_tags: frozenset[str],
             goos: frozenset[str], goarch: frozenset[str]) -> ConstraintResult:
    """Inspect only the leading comment block + blank lines (Go spec position)."""
    expr: str | None = None
    legacy: list[str] = []
    i = 0
    while i < len(source_lines) and i < 20:
        line = source_lines[i].strip()
        if line == "":
            i += 1
            continue
        if line.startswith("package ") or line.startswith("import"):
            break
        if line.startswith("//go:build"):
            expr = line[len("//go:build"):].strip()
        elif line.startswith("// +build") or line.startswith("//+build"):
            legacy.append(line.split("build", 1)[1].strip())
        elif line.startswith("/*") or line.startswith("//"):
            i += 1
            continue
        else:
            break
        i += 1

    if expr is None and not legacy:
        return ConstraintResult(True, None, "no-constraint")

    ok = True
    if expr is not None:
        ok = _eval_go_build(expr, active_tags, goos, goarch)
    for line in legacy:
        ok = ok and _eval_legacy_line(line, active_tags, goos, goarch)
    shown = expr or (" && ".join(f"({l})" for l in legacy))
    if ok:
        return ConstraintResult(True, shown, "constraint-satisfied")
    return ConstraintResult(False, shown, "constraint-excludes-file")
