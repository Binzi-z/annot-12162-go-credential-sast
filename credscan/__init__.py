"""credscan — syntax-first hardcoded credential scanner.

No regex sweeps over source text, no third-party rule packs. Every candidate
starts life as a syntax node produced by a real parser (tree-sitter CST for Go,
hand-written grammar parsers for YAML/JSON/Dockerfile/shell). Credential
*content* is validated structurally (prefix/charset/length/checksum), never by
grep-style pattern matching over files.
"""

__version__ = "0.1.0"
