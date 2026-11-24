"""Go syntax analysis on the tree-sitter CST: symbol table + taint propagation.

Everything here is driven by concrete syntax nodes. There is no textual
pattern matching: a string only becomes a candidate when it is the value of a
const/var spec, a composite-literal element, a call argument, a parameter
default position, or a selector assignment — i.e. a real syntactic slot.

Capabilities:
  * const/var declarations, const blocks with inherited expressions and iota
  * constant folding of string concatenation across symbols (cross-file)
  * package symbol tables, import aliases, cross-package selector resolution
  * struct fields and keyed composite literals
  * intra-procedural taint: short vars, assignments, params, call args,
    returns, selector writes; sink calls marked explicitly
  * build-constraint annotation and generated-file annotation (both still
    analyzed — tag-gated/generated code can ship in a real build)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from tree_sitter import Language, Node, Parser

from .buildtags import evaluate
from .model import Finding, Usage, fixture_path_signals, is_credential_name
from .secrets import analyze_value

_GO_LANG = Language(__import__("tree_sitter_go", fromlist=["language"]).language())


def _new_parser() -> Parser:
    try:
        return Parser(_GO_LANG)
    except TypeError:
        # Older tree-sitter bindings require setting the language afterwards.
        parser = Parser()
        parser.language = _GO_LANG
        return parser

GENERATED_MARKER = "DO NOT EDIT"

# Callee-name stems that mark a network / signing / client construction sink.
# Matched on identifier stems, so SetAccessKey, NewS3Client, SignRequest all hit.
SINK_STEMS = frozenset(
    {
        "client", "credential", "credentials", "auth", "sign", "signed",
        "request", "header", "upload", "put", "post", "send", "dial",
        "connect", "session", "sts", "s3", "oss", "cos", "blob", "webhook",
        "authorize", "token",
    }
)


def decode_go_string(token_text: str) -> Optional[str]:
    """Decode a Go interpreted/raw string literal token to its runtime value."""
    if len(token_text) < 2:
        return None
    if token_text.startswith("`") and token_text.endswith("`"):
        return token_text[1:-1]
    if not (token_text.startswith('"') and token_text.endswith('"')):
        return None
    body = token_text[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(body):
            break
        esc = body[i]
        simple = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
                  "t": "\t", "v": "\v", "\\": "\\", '"': '"', "`": "`"}
        if esc in simple:
            out.append(simple[esc])
            i += 1
        elif esc in "01234567":
            octal = body[i:i + 3]
            out.append(chr(int(octal, 8)))
            i += 3
        elif esc == "x":
            out.append(chr(int(body[i + 1:i + 3], 16)))
            i += 3
        elif esc == "u":
            out.append(chr(int(body[i + 1:i + 5], 16)))
            i += 5
        elif esc == "U":
            out.append(chr(int(body[i + 1:i + 9], 16)))
            i += 9
        else:
            out.append(esc)
            i += 1
    return "".join(out)


@dataclass
class PkgSymbol:
    name: str
    import_path: str
    file: str
    rel_file: str
    kind: str                     # const | var | field | func
    type_name: str = ""
    value_node: Optional[Node] = None
    folded_value: Optional[str] = None
    fold_complete: bool = False
    line: int = 0
    column: int = 0
    end_column: int = 0
    build_constraint: Optional[str] = None
    generated: bool = False
    fixture_signals: list[str] = field(default_factory=list)
    credential_named: bool = False


@dataclass
class GoFile:
    abs_path: str
    rel_path: str
    source: bytes
    tree_root: Node
    import_path: str
    package_name: str
    constraint_expr: Optional[str]
    constraint_ok: bool
    generated: bool
    fixture_signals: list[str]
    imports: dict[str, str] = field(default_factory=dict)  # alias -> import path


class GoAnalyzer:
    def __init__(self, repo_root: str, active_tags: frozenset[str],
                 goos: frozenset[str], goarch: frozenset[str]):
        self.repo_root = repo_root
        self.tags = active_tags
        self.goos = goos
        self.goarch = goarch
        self.parser = _new_parser()
        self.files: list[GoFile] = []
        # import path -> (symbol name -> PkgSymbol)
        self.pkg_symbols: dict[str, dict[str, PkgSymbol]] = {}
        # import path -> struct type name -> set(field names)
        self.struct_fields: dict[str, dict[str, set[str]]] = {}
        self.findings: list[Finding] = []
        self._folding: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ parse
    def parse_all(self, go_files: list[tuple[str, str]], module_path: str) -> None:
        for abs_path, rel_path in go_files:
            with open(abs_path, "rb") as fh:
                source = fh.read()
            try:
                tree = self.parser.parse(source)
            except Exception:
                continue
            root = tree.root_node
            if root.type != "source_file":
                continue
            text_lines = source.decode("utf-8", "replace").splitlines()
            constraint = evaluate(text_lines, self.tags, self.goos, self.goarch)
            generated = any("Code generated" in ln and GENERATED_MARKER in ln
                            for ln in text_lines[:30])
            pkg_clause = root.child_by_field_name("package_clause")
            pkg_name = pkg_clause.named_children[0].text.decode() if pkg_clause else ""
            rel_parts = tuple(rel_path.replace("\\", "/").split("/"))
            signals = fixture_path_signals(rel_parts, pkg_name or None)
            import_path = module_path + "/" + os.path.dirname(rel_path.replace("\\", "/")).replace("\\", "/") \
                if module_path else os.path.dirname(rel_path)
            import_path = import_path.rstrip("/")

            gf = GoFile(abs_path, rel_path.replace("\\", "/"), source, root, import_path,
                        pkg_name, constraint.expression, constraint.satisfied,
                        generated, signals)
            self._collect_imports(gf)
            self.files.append(gf)
            self.pkg_symbols.setdefault(import_path, {})
            self.struct_fields.setdefault(import_path, {})

    def _collect_imports(self, gf: GoFile) -> None:
        for node in self._walk(gf.tree_root):
            if node.type != "import_spec":
                continue
            path_node = node.child_by_field_name("path")
            if path_node is None:
                continue
            path = decode_go_string(path_node.text.decode())
            if not path:
                continue
            alias_node = node.child_by_field_name("name")
            if alias_node is not None:
                gf.imports[alias_node.text.decode()] = path
            else:
                gf.imports[path.rsplit("/", 1)[-1]] = path

    # ------------------------------------------------------------- symbol idx
    def build_index(self) -> None:
        for gf in self.files:
            self._index_file(gf)

    def _index_file(self, gf: GoFile) -> None:
        for node in self._walk(gf.tree_root):
            if node.type == "const_declaration":
                self._index_value_decl(gf, node, "const")
            elif node.type == "var_declaration":
                self._index_value_decl(gf, node, "var")
            elif node.type == "type_spec":
                self._index_struct(gf, node)

    def _index_value_decl(self, gf: GoFile, decl: Node, kind: str) -> None:
        # const/var declarations contain specs; specs inside one block may
        # inherit the previous spec's expression (Go spec rule).
        specs = [c for c in decl.named_children if c.type.endswith("_spec")]
        last_value_nodes: list[Node] = []
        block_iota = 0
        for spec in specs:
            names = [c for c in spec.named_children if c.type == "identifier"]
            value_nodes = [c for c in spec.named_children
                           if c.type not in ("identifier", "type_identifier", "qualified_type")]
            if not value_nodes:
                value_nodes = last_value_nodes
            else:
                last_value_nodes = value_nodes
            for idx, name_node in enumerate(names):
                value_node = value_nodes[idx] if idx < len(value_nodes) else (
                    value_nodes[-1] if value_nodes else None)
                sym = PkgSymbol(
                    name=name_node.text.decode(),
                    import_path=gf.import_path,
                    file=gf.abs_path,
                    rel_file=gf.rel_path,
                    kind=kind,
                    value_node=value_node,
                    line=name_node.start_point[0] + 1,
                    column=name_node.start_point[1] + 1,
                    end_column=name_node.end_point[1] + 1,
                    build_constraint=gf.constraint_expr,
                    generated=gf.generated,
                    fixture_signals=list(gf.fixture_signals),
                    credential_named=is_credential_name(name_node.text.decode()),
                )
                if value_node is not None:
                    sym.type_name = self._infer_type_name(value_node)
                self.pkg_symbols.setdefault(gf.import_path, {})[sym.name] = sym
            block_iota += 1

    def _index_struct(self, gf: GoFile, type_spec: Node) -> None:
        name_node = type_spec.child_by_field_name("name")
        type_node = type_spec.child_by_field_name("type")
        if name_node is None or type_node is None or type_node.type != "struct_type":
            return
        fields: set[str] = set()
        body = type_node.child_by_field_name("body")
        if body is None:
            return
        for fd in self._walk(body):
            if fd.type != "field_declaration":
                continue
            for ident in (c for c in fd.named_children if c.type == "identifier"):
                fields.add(ident.text.decode())
        self.struct_fields.setdefault(gf.import_path, {})[name_node.text.decode()] = fields

    @staticmethod
    def _infer_type_name(node: Node) -> str:
        if node.type == "composite_literal":
            t = node.child_by_field_name("type")
            return t.text.decode() if t is not None else ""
        if node.type == "unary_expression":
            operand = node.child_by_field_name("operand")
            return GoAnalyzer._infer_type_name(operand) if operand else ""
        if node.type in ("type_identifier", "qualified_type"):
            return node.text.decode()
        return ""

    # ------------------------------------------------------------- const fold
    def fold_symbol(self, sym: PkgSymbol) -> tuple[Optional[str], bool]:
        """Return (folded string value, complete). Complete means the whole
        value resolved to constants; partial folds are treated as non-literal."""
        if sym.fold_complete:
            return sym.folded_value, True
        key = (sym.import_path, sym.name)
        if key in self._folding:
            return None, False
        self._folding.add(key)
        try:
            if sym.value_node is None:
                value, ok = None, False
            else:
                value, ok = self._fold_node(sym.import_path, sym.value_node)
            sym.folded_value, sym.fold_complete = value, ok
            return value, ok
        finally:
            self._folding.discard(key)

    def _fold_node(self, import_path: str, node: Node) -> tuple[Optional[str], bool]:
        if node.type in ("interpreted_string_literal", "raw_string_literal"):
            return decode_go_string(node.text.decode()), True
        if node.type == "binary_expression" and node.child_by_field_name("operator") is not None \
                and node.child_by_field_name("operator").text.decode() == "+":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            lv, lok = self._fold_node(import_path, left)
            rv, rok = self._fold_node(import_path, right)
            if lok and rok and lv is not None and rv is not None:
                return lv + rv, True
            return None, False
        if node.type == "identifier":
            name = node.text.decode()
            if name == "iota":
                return None, False  # numeric sequence, never a secret string
            target = self.pkg_symbols.get(import_path, {}).get(name)
            if target is not None:
                return self.fold_symbol(target)
            return None, False
        if node.type == "selector_expression":
            target = self._resolve_selector(import_path, node)
            if target is not None:
                return self.fold_symbol(target)
            return None, False
        if node.type == "parenthesized_expression":
            inner = node.named_children[0]
            return self._fold_node(import_path, inner)
        if node.type == "unary_expression":
            operand = node.child_by_field_name("operand")
            if operand is not None:
                return self._fold_node(import_path, operand)
        return None, False

    def _resolve_selector(self, current_import: str, node: Node) -> Optional[PkgSymbol]:
        operand = node.child_by_field_name("operand")
        field = node.child_by_field_name("field")
        if operand is None or field is None or operand.type != "identifier":
            return None
        alias = operand.text.decode()
        # Resolve alias through the file that owns this node is not threaded
        # here; callers pre-map. Fall back: last segment match over packages.
        target_pkg = self._alias_to_package.get(alias) if hasattr(self, "_alias_to_package") else None
        if target_pkg is None:
            for gf in self.files:
                if alias in gf.imports:
                    target_pkg = gf.imports[alias]
                    break
        if target_pkg is None:
            return None
        return self.pkg_symbols.get(target_pkg, {}).get(field.text.decode())

    # ------------------------------------------------------------- analysis
    def analyze(self) -> list[Finding]:
        # Fold every indexed symbol first so cross-file/cross-package constants
        # resolve before declaration-site emission.
        for pkg in self.pkg_symbols.values():
            for sym in pkg.values():
                if sym.kind in ("const", "var"):
                    self.fold_symbol(sym)

        for gf in self.files:
            self._alias_to_package = dict(gf.imports)
            self._analyze_decls(gf)
            self._analyze_package_level(gf)
            self._analyze_bodies(gf)
        return self.findings

    def _analyze_package_level(self, gf: GoFile) -> None:
        """Top-level var/var values live outside any function body, so the
        per-function taint walker never sees them. Run a statement-less taint
        walker over each spec value: composite-literal credential fields and
        sink-call literal arguments are emitted there."""
        walker = _FuncTaint(self, gf)
        for decl in (n for n in gf.tree_root.named_children
                     if n.type in ("var_declaration", "const_declaration")):
            for spec in (c for c in decl.named_children if c.type.endswith("_spec")):
                for value in (c for c in spec.named_children
                              if c.type not in ("identifier", "type_identifier", "qualified_type")):
                    walker._expr_origins(value)

    def _emit(self, gf: GoFile, node: Node, symbol_name: str, carrier: str,
              value: str, reasons: list[str], usages: Optional[list[Usage]] = None) -> None:
        verdict = analyze_value(value, name_hint=symbol_name)
        if verdict is None:
            return
        finding = Finding(
            rule_id=f"credscan/go-{carrier}",
            file=gf.rel_path,
            line=node.start_point[0] + 1,
            column=node.start_point[1] + 1,
            end_column=node.end_point[1] + 1,
            symbol=symbol_name,
            value_preview=value[:24] + ("…" if len(value) > 24 else ""),
            value_full_len=len(value),
            provider=verdict.provider,
            kind=verdict.kind,
            confidence=verdict.confidence,
            carrier=f"go-{carrier}",
            reasons=reasons + verdict.reasons,
            structural=verdict.structural,
            checksum_ok=verdict.checksum_ok,
            normalized_entropy=verdict.entropy,
            usages=usages or [],
            build_constraint=gf.constraint_expr,
            generated=gf.generated,
            fixture_signals=list(gf.fixture_signals),
        )
        finding.fingerprint = finding.compute_fingerprint()
        self.findings.append(finding)

    def _analyze_decls(self, gf: GoFile) -> None:
        for pkg_path, symbols in self.pkg_symbols.items():
            if pkg_path != gf.import_path:
                continue
            for sym in symbols.values():
                if sym.file != gf.abs_path or sym.value_node is None:
                    continue
                if not sym.credential_named:
                    continue
                if sym.fold_complete and sym.folded_value is not None:
                    self._emit(gf, sym.value_node, sym.name, sym.kind,
                               sym.folded_value,
                               [f"decl:{sym.kind}", f"symbol:{sym.import_path}.{sym.name}"])
                    continue
                # Unfolded credential-named slot: inspect direct literal parts
                # (e.g. concat with a non-const operand) so partial literals
                # are still seen, but only structurally-valid ones will fire.
                # Composite literals are handled by the package-level walker,
                # which keys on field names instead of emitting every string.
                if sym.value_node.type == "composite_literal":
                    continue
                for lit in self._literal_nodes(sym.value_node):
                    value = decode_go_string(lit.text.decode())
                    if value is not None:
                        self._emit(gf, lit, sym.name, sym.kind, value,
                                   [f"decl:{sym.kind}", "partial-fold-literal"])

    def _analyze_bodies(self, gf: GoFile) -> None:
        """Intra-procedural taint + sink calls + composite literals."""
        for func in self._functions(gf.tree_root):
            state = _FuncTaint(self, gf)
            state.run(func)

    # ------------------------------------------------------------- utilities
    @staticmethod
    def _walk(node: Node):
        yield node
        for child in node.named_children:
            yield from GoAnalyzer._walk(child)

    @staticmethod
    def _literal_nodes(node: Node):
        for n in GoAnalyzer._walk(node):
            if n.type in ("interpreted_string_literal", "raw_string_literal"):
                yield n

    @staticmethod
    def _functions(root: Node):
        for n in GoAnalyzer._walk(root):
            if n.type in ("function_declaration", "method_declaration"):
                yield n


class _FuncTaint:
    """Per-function taint state.

    origins[local name] = list of (label, node, resolved PkgSymbol|None).
    Labels: 'lit:'+value, 'sym:'+fqname, 'field:'+name. Taint is union — any
    credential origin marks the variable; sink reporting quotes the first.
    """

    def __init__(self, analyzer: GoAnalyzer, gf: GoFile):
        self.a = analyzer
        self.gf = gf
        self.origins: dict[str, list[tuple[str, Node, Optional[PkgSymbol]]]] = {}
        self.reported_sinks: set[tuple[int, str]] = set()

    def run(self, func: Node) -> None:
        # Parameters are credential-position origins when named accordingly.
        params = func.child_by_field_name("parameters")
        if params is not None:
            for pd in (n for n in params.named_children if n.type == "parameter_declaration"):
                idents = [c for c in pd.named_children if c.type == "identifier"]
                for ident in idents:
                    if is_credential_name(ident.text.decode()):
                        self.origins[ident.text.decode()] = [
                            ("param", ident, None)]
        body = func.child_by_field_name("body")
        if body is not None:
            self._visit_block(body)

    # ------------------------------------------------------------ visiting
    def _visit_block(self, block: Node) -> None:
        for stmt in block.named_children:
            self._visit_stmt(stmt)

    def _visit_stmt(self, node: Node) -> None:
        t = node.type
        if t == "block":
            self._visit_block(node)
        elif t == "short_var_declaration":
            self._handle_short_decl(node)
        elif t == "assignment_statement":
            self._handle_assignment(node)
        elif t == "call_expression":
            self._handle_call(node)
        elif t == "var_declaration":
            self._handle_local_var(node)
        elif t == "return_statement":
            for child in node.named_children:
                self._expr_origins(child)
        elif t in ("if_statement", "for_statement", "expression_switch_statement",
                   "type_switch_statement", "range_statement", "go_statement",
                   "defer_statement", "select_statement", "case_statement",
                   "labeled_statement", "expression_statement", "inc_statement",
                   "dec_statement", "send_statement"):
            for child in node.named_children:
                if child.type in ("block", "statement_list"):
                    self._visit_block(child) if child.type == "block" else self._visit_stmt(child)
                else:
                    self._expr_origins(child)
        else:
            for child in node.named_children:
                if child.type == "block":
                    self._visit_block(child)
                elif child.is_named and child.type.endswith(("_statement", "_declaration")):
                    self._visit_stmt(child)
                else:
                    self._expr_origins(child)

    def _handle_local_var(self, node: Node) -> None:
        # var Name = expr / var Name Type = expr inside a function body
        for spec in (c for c in node.named_children if c.type == "var_spec"):
            idents = [c for c in spec.named_children if c.type == "identifier"]
            value_nodes = [c for c in spec.named_children
                           if c.type not in ("identifier", "type_identifier", "qualified_type")]
            for idx, ident in enumerate(idents):
                expr = value_nodes[idx] if idx < len(value_nodes) else (
                    value_nodes[-1] if value_nodes else None)
                if expr is None:
                    continue
                origins = self._expr_origins(expr)
                if origins:
                    self.origins[ident.text.decode()] = origins

    def _handle_short_decl(self, node: Node) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        lhs = [c for c in left.named_children if c.type == "identifier"]
        rhs = list(right.named_children) if right.type == "expression_list" else [right]
        for idx, ident in enumerate(lhs):
            expr = rhs[idx] if idx < len(rhs) else (rhs[-1] if rhs else None)
            if expr is None:
                continue
            origins = self._expr_origins(expr)
            if origins:
                self.origins[ident.text.decode()] = origins
            else:
                self.origins.pop(ident.text.decode(), None)

    def _handle_assignment(self, node: Node) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        lhs = list(left.named_children) if left.type == "expression_list" else [left]
        rhs = list(right.named_children) if right.type == "expression_list" else [right]
        for idx, target in enumerate(lhs):
            expr = rhs[idx] if idx < len(rhs) else (rhs[-1] if rhs else None)
            if expr is None:
                continue
            origins = self._expr_origins(expr)
            if target.type == "identifier":
                if origins:
                    self.origins[target.text.decode()] = origins
                else:
                    self.origins.pop(target.text.decode(), None)
            elif target.type == "selector_expression":
                self._handle_selector_write(target, expr, origins)

    def _handle_selector_write(self, target: Node, expr: Node,
                               origins: list[tuple[str, Node, Optional[PkgSymbol]]]) -> None:
        field = target.child_by_field_name("field")
        if field is None:
            return
        field_name = field.text.decode()
        if not is_credential_name(field_name):
            return
        # obj.Field = "literal"  /  obj.Field = secretConst
        lits = list(GoAnalyzer._literal_nodes(expr))
        if lits:
            for lit in lits:
                value = decode_go_string(lit.text.decode())
                if value is not None:
                    self.a._emit(self.gf, lit, field_name, "field", value,
                                 ["selector-write", f"field:{field_name}"],
                                 usages=self._usages_for(origins, lit))
        elif origins:
            self._record_usage(field, origins, "field")

    def _handle_call(self, node: Node) -> None:
        callee = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        # Recurse into nested calls first (f(g(secret))) so their args are seen.
        if callee is not None:
            self._expr_origins(callee)
        if args is None:
            return
        is_sink = callee is not None and self._is_sink(callee)
        for arg in args.named_children:
            origins = self._expr_origins(arg)
            if is_sink and origins:
                self._record_usage(arg, origins, "sink", callee)
            # Literal arguments: when the call is a sink, the taint branch
            # above already emitted the literal via _record_usage; for a
            # non-sink call a positional literal has no credential position
            # and is therefore intentionally not reported.
            if not is_sink and arg.type in ("interpreted_string_literal", "raw_string_literal"):
                value = decode_go_string(arg.text.decode())
                hint = self._arg_name_hint(node, arg)
                if value is not None and hint:
                    self.a._emit(self.gf, arg, hint, "call-arg", value,
                                 ["call-argument"], usages=[])

    def _arg_name_hint(self, call: Node, arg: Node) -> str:
        # keyed argument isn't valid Go, but composite keyed elements are;
        # calls commonly pass secrets positionally next to credential names.
        return ""

    def _is_sink(self, callee: Node) -> bool:
        from .model import split_identifier
        if callee.type == "selector_expression":
            field = callee.child_by_field_name("field")
            name = field.text.decode() if field else ""
        else:
            name = callee.text.decode()
        return any(stem in split_identifier(name) for stem in SINK_STEMS)

    # ------------------------------------------------------------ resolution
    def _expr_origins(self, node: Node) -> list[tuple[str, Node, Optional[PkgSymbol]]]:
        """Return taint origins reaching this expression, recording literals
        and composite-literal credential fields along the way."""
        if node is None:
            return []
        t = node.type
        if t in ("interpreted_string_literal", "raw_string_literal"):
            value = decode_go_string(node.text.decode())
            if value is not None:
                return [(f"lit:{value}", node, None)]
            return []
        if t == "identifier":
            name = node.text.decode()
            if name in self.origins:
                return self.origins[name]
            sym = self.a.pkg_symbols.get(self.gf.import_path, {}).get(name)
            if sym is not None:
                return [(f"sym:{sym.import_path}.{sym.name}", node, sym)]
            return []
        if t == "selector_expression":
            sym = self._resolve(node)
            if sym is not None:
                return [(f"sym:{sym.import_path}.{sym.name}", node, sym)]
            # obj.CredentialField where obj is tainted: keep taint flowing
            operand = node.child_by_field_name("operand")
            field = node.child_by_field_name("field")
            if operand is not None and field is not None:
                base = self._expr_origins(operand)
                if base and is_credential_name(field.text.decode()):
                    return base
            return []
        if t == "composite_literal":
            return self._composite_origins(node)
        if t == "call_expression":
            self._handle_call(node)
            return []  # return values conservatively untainted
        if t == "unary_expression":
            operand = node.child_by_field_name("operand")
            return self._expr_origins(operand) if operand else []
        if t == "parenthesized_expression":
            return self._expr_origins(node.named_children[0]) if node.named_children else []
        if t == "binary_expression":
            op = node.child_by_field_name("operator")
            if op is not None and op.text.decode() == "+":
                left = self._expr_origins(node.child_by_field_name("left"))
                right = self._expr_origins(node.child_by_field_name("right"))
                return left + right
            for child in node.named_children:
                origins = self._expr_origins(child)
                if origins:
                    return origins
            return []
        if t == "index_expression":
            base = node.child_by_field_name("operand")
            return self._expr_origins(base) if base else []
        # Generic recursion: union of children origins.
        out: list[tuple[str, Node, Optional[PkgSymbol]]] = []
        for child in node.named_children:
            out.extend(self._expr_origins(child))
        return out

    def _composite_origins(self, node: Node) -> list[tuple[str, Node, Optional[PkgSymbol]]]:
        body = node.child_by_field_name("body")
        if body is None:
            return []
        out: list[tuple[str, Node, Optional[PkgSymbol]]] = []
        for element in body.named_children:
            if element.type != "keyed_element":
                continue
            key = element.child_by_field_name("key")
            val = element.child_by_field_name("value")
            if key is None or val is None:
                continue
            key_name = key.text.decode().split(".")[-1]
            origins = self._expr_origins(val)
            if is_credential_name(key_name):
                for lit in GoAnalyzer._literal_nodes(val):
                    value = decode_go_string(lit.text.decode())
                    if value is not None:
                        self.a._emit(self.gf, lit, key_name, "field", value,
                                     ["composite-literal", f"field:{key_name}"])
                if origins:
                    self._record_usage(key, origins, "field")
                    out.extend(origins)
            else:
                out.extend(origins)
        return out

    def _resolve(self, selector: Node) -> Optional[PkgSymbol]:
        operand = selector.child_by_field_name("operand")
        field = selector.child_by_field_name("field")
        if operand is None or field is None:
            return None
        if operand.type == "identifier":
            alias = operand.text.decode()
            pkg_path = self.gf.imports.get(alias)
            if pkg_path is None:
                # Last-resort: match by package suffix when the scan root is
                # not itself the module root (e.g. scanning fixtures/dataset).
                for path in self.a.pkg_symbols:
                    if path.endswith("/" + alias) or path == alias:
                        pkg_path = path
                        break
            if pkg_path is not None:
                return self.a.pkg_symbols.get(pkg_path, {}).get(field.text.decode())
            # same-package alias or local package qualifier
            local = self.a.pkg_symbols.get(self.gf.import_path, {}).get(alias)
            if local is not None:
                return local
        return None

    # ------------------------------------------------------------ reporting
    def _record_usage(self, at: Node, origins: list[tuple[str, Node, Optional[PkgSymbol]]],
                      kind: str, callee: Optional[Node] = None) -> None:
        for label, origin_node, sym in origins:
            if sym is None and not label.startswith("lit:") and label != "param":
                continue
            key = (at.start_point[0], label)
            if key in self.reported_sinks:
                continue
            self.reported_sinks.add(key)
            usage = Usage(
                file=self.gf.rel_path,
                line=at.start_point[0] + 1,
                column=at.start_point[1] + 1,
                kind=("sink" if kind == "sink" and callee is not None else kind),
                snippet=(at.text.decode()[:80].replace("\n", " ")),
            )
            if sym is not None:
                self._attach_usage_to_finding(sym, usage)
            elif label.startswith("lit:"):
                # literal-origin taint reaching a sink: ensure a finding exists
                value = label[4:]
                self.a._emit(self.gf, origin_node, "sink-argument", "call-arg", value,
                             ["taint-to-sink"], usages=[usage])

    def _attach_usage_to_finding(self, sym: PkgSymbol, usage: Usage) -> None:
        for finding in self.a.findings:
            if finding.carrier.startswith("go-") and finding.symbol == sym.name \
                    and finding.file == sym.rel_file and finding.line == sym.line:
                if all(u.line != usage.line or u.file != usage.file for u in finding.usages):
                    finding.usages.append(usage)
                return

    def _usages_for(self, origins: list[tuple[str, Node, Optional[PkgSymbol]]],
                    at: Node) -> list[Usage]:
        out: list[Usage] = []
        for label, origin_node, sym in origins:
            if sym is not None:
                out.append(Usage(self.gf.rel_path, at.start_point[0] + 1,
                                 at.start_point[1] + 1, "reference",
                                 at.text.decode()[:80].replace("\n", " ")))
        return out
