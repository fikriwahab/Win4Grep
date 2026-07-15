# Fallback decoder: treat the file as text (and peel encoded layers)
from __future__ import annotations

from typing import Iterator

from ..core.models import Record
from .base import Decoder, register
from .encodings import expand, looks_textual, to_text
from .strings_util import extract_strings, extract_urls

# media files where extracting strings yields only noise
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic",
             ".ttf", ".otf", ".woff", ".woff2", ".mp3", ".mp4", ".mov", ".aac"}

_CHUNK = 200_000  # split very large text files so records stay searchable


@register
class TextDecoder(Decoder):
    # Lowest-priority decoder, pipeline falls back to it for anything else

    name = "text"

    def sniff(self, path: str, head: bytes) -> bool:
        return False  # never auto-picked, used explicitly as fallback

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        lower = path.lower()
        if any(lower.endswith(ext) for ext in _SKIP_EXT):
            return
        if not data:
            return

        if looks_textual(data):
            text = to_text(data)
            if len(text) <= _CHUNK:
                yield Record(source, path, self.name, "text", "", text, {})
            else:
                for i in range(0, len(text), _CHUNK):
                    yield Record(source, path, self.name, "text",
                                 f"chunk:{i // _CHUNK}", text[i:i + _CHUNK], {})
        else:
            # binary: encoded payloads and printable strings
            for label, txt in expand(data):
                if label not in ("raw", "hex") and txt:
                    yield Record(source, path, self.name, "embedded", label, txt,
                                 {"layer": label})

            strings = list(extract_strings(data, min_len=4))
            if strings:
                blob = "\n".join(strings)
                urls: set[str] = set()
                for i in range(0, len(blob), _CHUNK):
                    chunk = blob[i:i + _CHUNK]
                    yield Record(source, path, self.name, "strings",
                                 f"chunk:{i // _CHUNK}", chunk, {})
                    for u in extract_urls(chunk):
                        urls.add(u)
                for u in sorted(urls):
                    yield Record(source, path, self.name, "url", "", u,
                                 {"url": True})
