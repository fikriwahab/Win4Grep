# embedded.mobileprovision: slice out the embedded XML plist and decode it
from __future__ import annotations

import plistlib
from typing import Iterator

from ..core.models import Record
from .base import Decoder, register
from .encodings import walk_structured


@register
class MobileProvisionDecoder(Decoder):
    name = "mobileprovision"

    def sniff(self, path: str, head: bytes) -> bool:
        return path.lower().endswith(".mobileprovision")

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        start = data.find(b"<?xml")
        end = data.find(b"</plist>")
        if start < 0 or end < 0:
            yield Record(source, path, self.name, "note", "",
                         "<no embedded plist found in profile>", {})
            return
        payload = data[start:end + len(b"</plist>")]
        try:
            obj = plistlib.loads(payload)
        except Exception as exc:
            yield Record(source, path, self.name, "error", "",
                         f"<plist parse failed: {exc}>", {"error": str(exc)})
            return
        for keypath, text in walk_structured(obj):
            if text:
                yield Record(source, path, self.name, "provision", keypath, text,
                             {"keypath": keypath})
