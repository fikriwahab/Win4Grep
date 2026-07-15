# Property lists: XML and binary, including NSKeyedArchiver object graphs
from __future__ import annotations

import plistlib
from typing import Iterator

from ..core.models import Record
from .base import Decoder, register
from .encodings import walk_structured

try:  # NSKeyedArchiver de-serialisation (UserDefaults, NSCoding blobs)
    import nska_deserialize as nska  # type: ignore
except Exception:  # pragma: no cover, optional dependency
    nska = None


@register
class PlistDecoder(Decoder):
    name = "plist"

    def sniff(self, path: str, head: bytes) -> bool:
        if head[:8] == b"bplist00":
            return True
        if path.lower().endswith(".plist"):
            return True
        stripped = head.lstrip()[:64].lower()
        return stripped.startswith(b"<?xml") and b"plist" in head[:512].lower()

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        obj = None
        is_nska = data[:8] == b"bplist00" and b"NSKeyedArchiver" in data[:4096]

        if is_nska and nska is not None:
            try:
                obj = nska.deserialize_plist_from_bytes(data, full_recurse_convert_nska=True)
            except Exception:
                obj = None

        if obj is None:
            try:
                obj = plistlib.loads(data)
            except Exception as exc:
                yield Record(source, path, self.name, "plist-error", "",
                             f"<failed to parse plist: {exc}>", {"error": str(exc)})
                return

        kind = "nska-value" if is_nska else "plist-value"
        for keypath, text in walk_structured(obj):
            if not text:
                continue
            yield Record(source, path, self.name, kind, keypath, text,
                         {"keypath": keypath, "nska": is_nska})
