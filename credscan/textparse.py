"""Syntax parsers for non-Go credential carriers.

Every parser below consumes grammar, not text patterns:
  * JSON  -> stdlib json (a complete grammar parser), line numbers recovered
             via a small streaming tokenizer over the same bytes
  * YAML  -> hand-written indentation parser (maps, sequences, block scalars,
             flow collections, quoted scalars, comments)
  * Dockerfile -> instruction parser with line continuation + exec-form JSON
  * Shell -> hand-written tokenizer/parser: assignments, export, env-prefixed
             commands, heredocs, quoted words, flag/header arguments
  * .env -> line parser honoring quotes and export prefix

Candidate extraction is keyed on syntactic positions (map keys, assignment
LHS, instruction names, flag semantics), never on substring search.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RawCandidate:
    rel_path: str
    line: int
    column: int
    end_column: int
    key_path: str
    value: str
    carrier: str                       # yaml | json | dockerfile | shell | envfile
    syntax: str                        # map-value | assignment | exec-arg | flag-arg | heredoc
    extra_reasons: list[str] = field(default_factory=list)


# ===========================================================================
# JSON with line tracking
# ===========================================================================

class _JsonLineScanner:
    """Map byte offsets to 1-based (line, column) for position reporting."""

    def __init__(self, text: str):
        self.text = text
        self.line_starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self.line_starts.append(i + 1)

    def position(self, offset: int) -> tuple[int, int]:
        lo, hi = 0, len(self.line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, offset - self.line_starts[lo] + 1


def parse_json(rel_path: str, text: str) -> list[RawCandidate]:
    """Recursive-descent parse that keeps byte offsets of every string value.

    Grammar-driven (objects, arrays, strings, literals); no value regex.
    """
    n = len(text)
    pos = 0

    def skip_ws() -> None:
        nonlocal pos
        while pos < n and text[pos] in " \t\r\n":
            pos += 1

    def parse_string() -> tuple[str, int]:
        nonlocal pos
        start = pos
        pos += 1  # opening quote
        buf: list[str] = []
        while pos < n and text[pos] != '"':
            if text[pos] == "\\" and pos + 1 < n:
                nxt = text[pos + 1]
                if nxt == "u" and pos + 5 < n:
                    buf.append(chr(int(text[pos + 2:pos + 6], 16)))
                    pos += 6
                else:
                    simple = {"b": "\b", "f": "\f", "n": "\n", "r": "\r",
                              "t": "\t", '"': '"', "\\": "\\", "/": "/"}
                    buf.append(simple.get(nxt, nxt))
                    pos += 2
            else:
                buf.append(text[pos])
                pos += 1
        pos += 1  # closing quote
        return "".join(buf), start

    def parse_value(path: list[str], leaves: list) -> None:
        skip_ws()
        if pos >= n:
            return
        ch = text[pos]
        if ch == '"':
            value, offset = parse_string()
            leaves.append((list(path), value, offset))
        elif ch == "{":
            parse_object(path, leaves)
        elif ch == "[":
            parse_array(path, leaves)
        else:
            # number / true / false / null — skip to delimiter
            while pos < n and text[pos] not in ",]} \t\r\n":
                pos += 1

    def parse_object(path: list[str], leaves: list) -> None:
        nonlocal pos
        pos += 1  # {
        skip_ws()
        if pos < n and text[pos] == "}":
            pos += 1
            return
        while pos < n:
            skip_ws()
            key, _ = parse_string()
            skip_ws()
            if pos < n and text[pos] == ":":
                pos += 1
            parse_value(path + [key], leaves)
            skip_ws()
            if pos < n and text[pos] == ",":
                pos += 1
                continue
            if pos < n and text[pos] == "}":
                pos += 1
            break

    def parse_array(path: list[str], leaves: list) -> None:
        nonlocal pos
        pos += 1  # [
        skip_ws()
        if pos < n and text[pos] == "]":
            pos += 1
            return
        idx = 0
        while pos < n:
            parse_value(path + [f"[{idx}]"], leaves)
            idx += 1
            skip_ws()
            if pos < n and text[pos] == ",":
                pos += 1
                continue
            if pos < n and text[pos] == "]":
                pos += 1
            break

    leaves: list[tuple[list[str], str, int]] = []
    try:
        parse_value([], leaves)
    except (IndexError, ValueError):
        return []
    scanner = _JsonLineScanner(text)
    candidates: list[RawCandidate] = []
    for path, value, offset in leaves:
        line, col = scanner.position(offset)
        candidates.append(RawCandidate(
            rel_path, line, col, col + len(value) + 2,
            ".".join(path), value, "json", "map-value"))
    return candidates


# ===========================================================================
# YAML subset parser
# ===========================================================================

@dataclass
class _YamlNode:
    kind: str                 # map | seq | scalar
    line: int
    column: int
    key: str = ""
    value: str = ""
    children: list = field(default_factory=list)
    quoted: bool = False
    key_line: int = 0
    key_col: int = 0


def _strip_yaml_comment(line: str) -> str:
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in " \t":
                return line[:i]
    return line


def _unquote_yaml_scalar(raw: str) -> tuple[str, bool]:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        if raw[0] == '"':
            try:
                return json.loads(raw), True
            except json.JSONDecodeError:
                return raw[1:-1], True
        return raw[1:-1].replace("''", "'"), True
    return raw, False


def parse_yaml(rel_path: str, text: str) -> list[RawCandidate]:
    lines = text.splitlines()
    # Logical lines with block-scalar expansion tracking.
    root = _YamlNode("map", 0, 0)
    stack: list[tuple[int, _YamlNode]] = [(-1, root)]
    i = 0
    while i < len(lines):
        raw_line = lines[i]
        stripped = _strip_yaml_comment(raw_line).rstrip()
        if not stripped.strip() or stripped.lstrip().startswith("---") or stripped.lstrip().startswith("..."):
            i += 1
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        content = stripped.strip()

        # Block scalar (| or >) — collect indented body verbatim.
        if content.endswith(("|", ">", "|-", ">-", "|+", ">+")) and ":" in content:
            key_part, _ = content.split(":", 1)
            key = _unquote_yaml_scalar(key_part.strip())[0]
            body_lines, ni = _collect_block_scalar(lines, i + 1, indent)
            node = _YamlNode("scalar", i + 1, indent + 1, key=key,
                             value="\n".join(body_lines), quoted=False,
                             key_line=i + 1, key_col=indent + 1)
            _attach(stack, indent, node)
            i = ni
            continue

        if content.startswith("- "):
            item_text = content[2:].strip()
            seq_node = _ensure_seq(stack, indent)
            if ":" in item_text and not item_text.startswith(("'", '"')):
                key, rest = item_text.split(":", 1)
                map_node = _YamlNode("map", i + 1, indent + 1)
                seq_node.children.append(map_node)
                stack_push = (indent, map_node)
                _push_node(stack, indent, map_node)
                if rest.strip():
                    val, q = _unquote_yaml_scalar(rest.strip())
                    map_node.children.append(_YamlNode(
                        "scalar", i + 1, indent + 3, key=key.strip(), value=val,
                        quoted=q, key_line=i + 1, key_col=indent + 3))
                else:
                    map_node.children.append(_YamlNode(
                        "scalar", i + 1, indent + 3, key=key.strip(), value="",
                        key_line=i + 1, key_col=indent + 3))
            else:
                val, q = _unquote_yaml_scalar(item_text)
                seq_node.children.append(_YamlNode(
                    "scalar", i + 1, indent + 3, value=val, quoted=q))
            i += 1
            continue

        if ":" in content:
            key, rest = content.split(":", 1)
            key_val, _ = _unquote_yaml_scalar(key.strip())
            parent = _parent_for(stack, indent)
            if rest.strip():
                val, q = _unquote_yaml_scalar(rest.strip())
                parent.children.append(_YamlNode(
                    "scalar", i + 1, indent + 1, key=key_val, value=val,
                    quoted=q, key_line=i + 1, key_col=indent + 1))
            else:
                map_node = _YamlNode("map", i + 1, indent + 1, key=key_val)
                parent.children.append(map_node)
                _push_node(stack, indent, map_node)
            i += 1
            continue

        i += 1

    out: list[RawCandidate] = []
    _emit_yaml_leaves(rel_path, root, [], out)
    return out


def _collect_block_scalar(lines: list[str], start: int, parent_indent: int):
    body: list[str] = []
    i = start
    while i < len(lines):
        ln = lines[i]
        if ln.strip() == "":
            body.append("")
            i += 1
            continue
        indent = len(ln) - len(ln.lstrip(" "))
        if indent <= parent_indent:
            break
        body.append(ln.lstrip(" "))
        i += 1
    while body and body[-1] == "":
        body.pop()
    return body, i


def _attach(stack: list, indent: int, node: _YamlNode) -> None:
    _parent_for(stack, indent).children.append(node)


def _push_node(stack: list, indent: int, node: _YamlNode) -> None:
    while stack and stack[-1][0] >= indent:
        stack.pop()
    stack.append((indent, node))


def _parent_for(stack: list, indent: int) -> _YamlNode:
    while stack and stack[-1][0] >= indent:
        stack.pop()
    return stack[-1][1]


def _ensure_seq(stack: list, indent: int) -> _YamlNode:
    if stack and stack[-1][0] == indent and stack[-1][1].kind == "seq":
        return stack[-1][1]
    seq = _YamlNode("seq", 0, indent + 1)
    stack[-1][1].children.append(seq)
    stack.append((indent, seq))
    return seq


def _emit_yaml_leaves(rel_path: str, node: _YamlNode, path: list[str],
                      out: list[RawCandidate]) -> None:
    if node.kind == "scalar":
        if node.key:
            out.append(RawCandidate(
                rel_path, node.key_line, node.key_col,
                node.key_col + len(node.key),
                ".".join(path + [node.key]), node.value, "yaml", "map-value"))
        return
    for child in node.children:
        if child.kind == "scalar" and child.key:
            _emit_yaml_leaves(rel_path, child, path, out)
        elif child.key:
            _emit_yaml_leaves(rel_path, child, path + [child.key], out)
        else:
            _emit_yaml_leaves(rel_path, child, path, out)


# ===========================================================================
# Dockerfile
# ===========================================================================

def _join_continuation_lines(text: str) -> list[tuple[str, int]]:
    """Return (logical line, starting physical line number, 1-based)."""
    physical = text.splitlines()
    logical: list[tuple[str, int]] = []
    buf: list[str] = []
    start = 1
    for idx, line in enumerate(physical, start=1):
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            if not buf:
                start = idx
            buf.append(stripped[:-1])
        else:
            buf.append(line)
            logical.append((" ".join(s.strip() for s in buf), start))
            buf = []
            start = idx + 1
    if buf:
        logical.append((" ".join(buf), start))
    return logical


def parse_dockerfile(rel_path: str, text: str) -> list[RawCandidate]:
    out: list[RawCandidate] = []
    for line, line_no in _join_continuation_lines(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if not parts:
            continue
        instruction = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ""

        if instruction in ("ENV", "ARG"):
            out.extend(_docker_env_pairs(rel_path, line_no, rest, instruction))
        elif instruction == "LABEL":
            out.extend(_docker_env_pairs(rel_path, line_no, rest, "LABEL"))
        elif instruction in ("RUN",):
            out.extend(_shell_words(rel_path, line_no, rest, "dockerfile",
                                    prefix=f"RUN@{line_no}"))
        elif instruction in ("CMD", "ENTRYPOINT"):
            if rest.lstrip().startswith("["):
                try:
                    argv = json.loads(rest)
                except json.JSONDecodeError:
                    argv = []
                for idx, word in enumerate(argv):
                    out.extend(_shell_word_candidates(
                        rel_path, line_no, word, "dockerfile", "exec-arg",
                        f"CMD[{idx}]", []))
            else:
                out.extend(_shell_words(rel_path, line_no, rest, "dockerfile",
                                        prefix=f"{instruction}@{line_no}"))
    return out


def _docker_env_pairs(rel_path: str, line_no: int, rest: str,
                      instruction: str) -> list[RawCandidate]:
    out: list[RawCandidate] = []
    words = _tokenize_shell_line(rest)
    for word, col, _ in words:
        if "=" not in word:
            continue
        name, value = word.split("=", 1)
        name = name.strip()
        out.append(RawCandidate(
            rel_path, line_no, col, col + len(word), name,
            _strip_quotes(value), "dockerfile",
            f"{instruction.lower()}-assignment"))
    return out


def _strip_quotes(word: str) -> str:
    if len(word) >= 2 and word[0] == word[-1] and word[0] in "'\"":
        return word[1:-1]
    return word


# ===========================================================================
# Shell tokenizer / mini-parser
# ===========================================================================

def _tokenize_shell_line(line: str) -> list[tuple[str, int, str]]:
    """Tokenize one logical shell line into (word, start_column, quote)."""
    words: list[tuple[str, int, str]] = []
    i, n = 0, len(line)
    while i < n:
        while i < n and line[i] in " \t":
            i += 1
        if i >= n:
            break
        start = i
        buf: list[str] = []
        quote = ""
        while i < n:
            ch = line[i]
            if ch in "'\"":
                if not quote:
                    quote = ch
                    i += 1
                    continue
                if quote == ch:
                    quote = ""
                    i += 1
                    continue
            if ch == "\\" and i + 1 < n:
                buf.append(line[i + 1])
                i += 2
                continue
            if ch in " \t" and not quote:
                break
            if ch in ";|&" and not quote:
                break
            buf.append(ch)
            i += 1
        words.append(("".join(buf), start + 1, quote or "plain"))
    return words


def parse_shell(rel_path: str, text: str) -> list[RawCandidate]:
    out: list[RawCandidate] = []
    physical = text.splitlines()
    i = 0
    while i < len(physical):
        line = physical[i]
        line_no = i + 1
        # heredoc: <<[-]DELIM
        if "<<" in line:
            delim = _heredoc_delim(line)
            if delim:
                j = i + 1
                body: list[str] = []
                while j < len(physical) and physical[j].strip() != delim:
                    body.append(physical[j])
                    j += 1
                for k, body_line in enumerate(body):
                    out.extend(_shell_assignment_line(
                        rel_path, i + 2 + k, body_line, "heredoc"))
                i = j + 1
                continue
        # line continuations
        joined = line
        start_no = line_no
        while joined.rstrip().endswith("\\") and i + 1 < len(physical):
            i += 1
            joined = joined.rstrip()[:-1] + " " + physical[i]
        out.extend(_shell_assignment_line(rel_path, start_no, joined, "shell"))
        i += 1
    return out


def _heredoc_delim(line: str) -> Optional[str]:
    idx = line.find("<<")
    if idx < 0:
        return None
    rest = line[idx + 2:].lstrip("-").lstrip()
    rest = rest.strip().strip("'\"")
    return rest.split()[0] if rest else None


def _shell_assignment_line(rel_path: str, line_no: int, line: str,
                           carrier: str) -> list[RawCandidate]:
    out: list[RawCandidate] = []
    if line.lstrip().startswith("#"):
        return out
    words = _tokenize_shell_line(line)
    expect_export = False
    for idx, (word, col, quote) in enumerate(words):
        bare = word
        if bare == "export":
            expect_export = True
            continue
        if "=" in bare and _valid_shell_name(bare.split("=", 1)[0]):
            name, value = bare.split("=", 1)
            out.append(RawCandidate(
                rel_path, line_no, col, col + len(bare), name,
                _strip_quotes(value), carrier,
                "export-assignment" if expect_export else "assignment"))
            expect_export = False
            continue
        expect_export = False
        # command and its flag arguments
        out.extend(_shell_word_candidates(
            rel_path, line_no, bare, carrier, "flag-arg",
            f"argv[{idx}]", _flag_context(words, idx)))
    return out


def _flag_context(words: list[tuple[str, int, str]], idx: int) -> list[str]:
    if idx == 0:
        return []
    prev = words[idx - 1][0]
    if prev.startswith("-"):
        return [f"flag:{prev.lstrip('-')}"]
    return []


def _shell_words(rel_path: str, line_no: int, line: str, carrier: str,
                 prefix: str) -> list[RawCandidate]:
    out: list[RawCandidate] = []
    for idx, (word, col, quote) in enumerate(_tokenize_shell_line(line)):
        if "=" in word and _valid_shell_name(word.split("=", 1)[0]):
            name, value = word.split("=", 1)
            out.append(RawCandidate(rel_path, line_no, col, col + len(word),
                                    name, _strip_quotes(value), carrier,
                                    "env-prefix-assignment"))
            continue
        out.extend(_shell_word_candidates(
            rel_path, line_no, word, carrier, "flag-arg",
            f"{prefix}.argv[{idx}]", _flag_context(_tokenize_shell_line(line), idx)))
    return out


def _shell_word_candidates(rel_path: str, line_no: int, word: str,
                           carrier: str, syntax: str, path: str,
                           reasons: list[str]) -> list[RawCandidate]:
    """Only credential-positioned shell words become candidates:
    header words (Name: value), --flag=value with a credential flag, or words
    whose own prefix is credential-shaped (e.g. aws configure set <name>)."""
    out: list[RawCandidate] = []
    if ":" in word and not word.startswith("http"):
        header, _, rest = word.partition(":")
        if is_header_credential(header):
            value = rest.strip()
            if header.strip().lower() == "authorization" and value.lower().startswith("bearer "):
                value = value[7:].strip()
            out.append(RawCandidate(
                rel_path, line_no, 1, 1 + len(word), f"header:{header.strip()}",
                value, carrier, "header-arg",
                reasons + [f"header:{header.strip()}"]))
            return out
    if "=" in word and word.startswith("-"):
        flag, _, value = word.partition("=")
        if is_credential_flag(flag.lstrip("-")):
            out.append(RawCandidate(
                rel_path, line_no, 1, 1 + len(word), flag.lstrip("-"),
                _strip_quotes(value), carrier, syntax,
                reasons + [f"flag:{flag.lstrip('-')}"]))
            return out
    for reason in reasons:
        if reason.startswith("flag:") and is_credential_flag(reason[5:]):
            out.append(RawCandidate(
                rel_path, line_no, 1, 1 + len(word), reason[5:],
                _strip_quotes(word), carrier, syntax, reasons))
            return out
    # aws/gcloud style: configure set <credential-name> <value> handled by
    # checking neighbor words — callers pass position context via path only,
    # so detect 'set <name> <value>' inside the word stream at engine level.
    return out


def _valid_shell_name(name: str) -> bool:
    if not name or not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(ch.isalnum() or ch == "_" for ch in name)


def is_header_credential(header: str) -> bool:
    from .model import is_credential_name, split_identifier
    h = header.strip().replace("-", " ")
    stems = split_identifier(h.replace(" ", "_"))
    return is_credential_name(h.replace(" ", "_")) or any(
        s in {"authorization", "auth", "token", "secret", "key", "signature"} for s in stems)


def is_credential_flag(flag: str) -> bool:
    from .model import is_credential_name
    cleaned = flag.replace("-", "_")
    return is_credential_name(cleaned) or cleaned in {
        "u", "p", "password", "token", "secret", "key", "api_key",
        "access_key", "secret_key", "authorization",
    }


# ===========================================================================
# .env / properties
# ===========================================================================

def parse_envfile(rel_path: str, text: str) -> list[RawCandidate]:
    out: list[RawCandidate] = []
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if not _valid_shell_name(name):
            continue
        out.append(RawCandidate(
            rel_path, idx, 1, 1 + len(raw), name, _strip_quotes(value.strip()),
            "envfile", "assignment"))
    return out
