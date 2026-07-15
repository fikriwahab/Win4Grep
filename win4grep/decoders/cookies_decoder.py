# Apple Cookies.binarycookies parser (HTTP cookie jars)
from __future__ import annotations

import struct
from typing import Iterator

from ..core.models import Record
from .base import Decoder, register


@register
class BinaryCookiesDecoder(Decoder):
    name = "binarycookies"

    def sniff(self, path: str, head: bytes) -> bool:
        return head[:4] == b"cook" or path.lower().endswith(".binarycookies")

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        if data[:4] != b"cook":
            return
        try:
            num_pages = struct.unpack(">i", data[4:8])[0]
            page_sizes = [struct.unpack(">i", data[8 + i * 4:12 + i * 4])[0]
                          for i in range(num_pages)]
        except struct.error:
            return

        offset = 8 + num_pages * 4
        idx = 0
        for psize in page_sizes:
            page = data[offset:offset + psize]
            offset += psize
            yield from self._page(page, source, path, idx)
            idx += 1

    def _page(self, page: bytes, source: str, path: str, page_idx: int
              ) -> Iterator[Record]:
        try:
            n = struct.unpack("<i", page[4:8])[0]
            cookie_offsets = [struct.unpack("<i", page[8 + i * 4:12 + i * 4])[0]
                              for i in range(n)]
        except struct.error:
            return
        for i, co in enumerate(cookie_offsets):
            try:
                rec = self._cookie(page[co:])
            except Exception:
                continue
            if rec:
                yield Record(source, path, self.name, "cookie",
                             f"page{page_idx}:cookie{i}", rec, {})

    def _cookie(self, c: bytes) -> str | None:
        try:
            url_off, name_off, path_off, value_off = struct.unpack("<iiii", c[16:32])
        except struct.error:
            return None

        def cstr(start: int) -> str:
            end = c.find(b"\x00", start)
            return c[start:end if end >= 0 else len(c)].decode("utf-8", "replace")

        domain = cstr(url_off)
        name = cstr(name_off)
        cpath = cstr(path_off)
        value = cstr(value_off)
        return f"domain={domain} name={name} path={cpath} value={value}"
