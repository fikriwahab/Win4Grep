# Protocol Buffers: schema-less decode via blackboxprotobuf
from __future__ import annotations

from typing import Iterator

from ..core.models import Record
from .base import Decoder, register
from .encodings import try_protobuf, walk_structured

_PROTO_EXT = (".pb", ".proto", ".protobuf")
_PROTO_HINT_NAMES = ("protobuf", "gdt_", "metrics", "datastore")


@register
class ProtobufDecoder(Decoder):
    name = "protobuf"

    def sniff(self, path: str, head: bytes) -> bool:
        lower = path.lower()
        if lower.endswith(_PROTO_EXT):
            return True
        # only attempt name-hinted files to stay conservative at file level
        if any(h in lower for h in _PROTO_HINT_NAMES):
            return try_protobuf(head) is not None
        return False

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        msg = try_protobuf(data)
        if msg is None:
            return
        for keypath, text in walk_structured(msg):
            if text:
                yield Record(source, path, self.name, "protobuf-field",
                             keypath, text, {"keypath": keypath})
