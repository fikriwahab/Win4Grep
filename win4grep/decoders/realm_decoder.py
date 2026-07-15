# Realm databases (best-effort): extract strings and embedded encodings
from __future__ import annotations

from typing import Iterator

from ..core.models import Record
from .base import Decoder, register
from .encodings import expand
from .strings_util import extract_strings, extract_urls


@register
class RealmDecoder(Decoder):
    name = "realm"

    def sniff(self, path: str, head: bytes) -> bool:
        lower = path.lower()
        # Realm files commonly end in .realm, some embed the "Realm" marker early
        return lower.endswith(".realm") or b"Realm" in head[:64]

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        yield Record(source, path, self.name, "note", "",
                     "[best-effort: strings extracted; full Realm parsing needs "
                     "the native Realm engine]", {})
        urls: set[str] = set()
        for s in extract_strings(data, min_len=4):
            if len(s) >= 5:
                yield Record(source, path, self.name, "realm-string", "", s, {})
            for u in extract_urls(s):
                urls.add(u)
            # peel encoded payloads hiding in string values
            for label, txt in expand(s):
                if label not in ("raw", "hex") and txt:
                    yield Record(source, path, self.name, "realm-embedded",
                                 label, txt, {"layer": label})
        for u in sorted(urls):
            yield Record(source, path, self.name, "url", "", u, {"url": True})
