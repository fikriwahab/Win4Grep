# Extract GraphQL query/mutation/fragment declarations from JS bundles
from __future__ import annotations

import re
from typing import Iterator

from ..core.models import Record
from .base import Decoder, register
from .strings_util import extract_strings

_EXT = (".jsbundle", ".bundle", ".graphql", ".gql", ".js")
# a named GraphQL operation/fragment declaration
_OP_RE = re.compile(
    r"\b(query|mutation|subscription|fragment)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+on\s+([A-Za-z_][A-Za-z0-9_]*))?")
_MAX_BODY = 1500


@register
class GraphQLDecoder(Decoder):
    name = "graphql"

    def sniff(self, path: str, head: bytes) -> bool:
        lower = path.lower()
        if lower.endswith((".jsbundle", ".bundle", ".graphql", ".gql")):
            return True
        if lower.endswith(".js"):
            return b"query " in head or b"mutation " in head or b"fragment " in head
        # Hermes bytecode magic (RN bundles compiled to Hermes)
        return head[:8] == b"\xc6\x1e\xfb\x1f\x03\x19\x01\x00" or head[:4] == b"\xc6\x1e\xfb\x1f"

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        # work over the printable strings of the (possibly bytecode) bundle
        blob = "\n".join(extract_strings(data, min_len=6))
        seen: set[tuple] = set()
        n = 0
        for m in _OP_RE.finditer(blob):
            kind, name, on_type = m.group(1), m.group(2), m.group(3)
            key = (kind, name)
            if key in seen:
                continue
            seen.add(key)
            body = blob[m.start():m.start() + _MAX_BODY]
            label = f"{kind} {name}" + (f" on {on_type}" if on_type else "")
            yield Record(source, path, self.name, f"graphql-{kind}", name, body,
                         {"operation": name, "type": kind, "on": on_type,
                          "decl": label})
            n += 1
        if n:
            yield Record(source, path, self.name, "graphql-summary", "",
                         f"{n} GraphQL operations/fragments extracted from {path}",
                         {"count": n})
        # also index the raw strings, not just the GraphQL declarations
        for i in range(0, len(blob), 200_000):
            yield Record(source, path, self.name, "strings-backstop",
                         f"chunk:{i // 200_000}", blob[i:i + 200_000], {})
