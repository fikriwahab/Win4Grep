# LevelDB / IndexedDB (best-effort): extract strings and embedded encodings
from __future__ import annotations

from typing import Iterator

from ..core.models import Record
from .base import Decoder, register
from .encodings import expand
from .strings_util import extract_strings, extract_urls

_LEVELDB_EXT = (".ldb", ".log", ".sst")
_LEVELDB_NAMES = ("current", "manifest-", "lock", "log")


@register
class LevelDBDecoder(Decoder):
    name = "leveldb"

    def sniff(self, path: str, head: bytes) -> bool:
        lower = path.replace("\\", "/").lower()
        base = lower.rsplit("/", 1)[-1]
        if lower.endswith(_LEVELDB_EXT):
            return True
        return any(base.startswith(n) for n in _LEVELDB_NAMES) and "leveldb" in lower

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        urls: set[str] = set()
        for s in extract_strings(data, min_len=4):
            if len(s) >= 5:
                yield Record(source, path, self.name, "leveldb-string", "", s, {})
            for u in extract_urls(s):
                urls.add(u)
            for label, txt in expand(s):
                if label not in ("raw", "hex") and txt:
                    yield Record(source, path, self.name, "leveldb-embedded",
                                 label, txt, {"layer": label})
        for u in sorted(urls):
            yield Record(source, path, self.name, "url", "", u, {"url": True})
