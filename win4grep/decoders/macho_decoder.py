# Mach-O binaries: extract strings and embedded URLs (thin and fat)
from __future__ import annotations

from typing import Iterator

from ..core.models import Record
from .base import Decoder, register
from .strings_util import extract_strings, extract_urls

_MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64 (little-endian)
    b"\xce\xfa\xed\xfe",  # MH_MAGIC (32-bit, little-endian)
    b"\xfe\xed\xfa\xcf",  # big-endian 64
    b"\xfe\xed\xfa\xce",  # big-endian 32
    b"\xca\xfe\xba\xbe",  # FAT (universal)
    b"\xbe\xba\xfe\xca",  # FAT little-endian
}
_MIN_LEN = 5
_MAX_STRINGS = 40000  # safety cap for huge binaries


@register
class MachODecoder(Decoder):
    name = "macho"

    def sniff(self, path: str, head: bytes) -> bool:
        return head[:4] in _MACHO_MAGICS

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        urls: set[str] = set()
        count = 0
        for s in extract_strings(data, _MIN_LEN):
            count += 1
            if count > _MAX_STRINGS:
                break
            for u in extract_urls(s):
                urls.add(u)
            # keep interesting strings, skip short/noisy tokens
            if len(s) >= 6:
                yield Record(source, path, self.name, "macho-string", "", s,
                             {})
        for u in sorted(urls):
            yield Record(source, path, self.name, "macho-url", "", u,
                         {"url": True})
