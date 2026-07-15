# Extract printable strings (ASCII and UTF-16LE) from binary data
from __future__ import annotations

import re
from typing import Iterator

_ASCII_TMPL = rb"[\x20-\x7e]{%d,}"
_UTF16_TMPL = rb"(?:[\x20-\x7e]\x00){%d,}"
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>\\]{4,}", re.IGNORECASE)

_RE_CACHE: dict[tuple[bytes, int], re.Pattern] = {}


def _rx(tmpl: bytes, n: int) -> re.Pattern:
    key = (tmpl, n)
    rx = _RE_CACHE.get(key)
    if rx is None:
        rx = re.compile(tmpl % n)
        _RE_CACHE[key] = rx
    return rx


def extract_strings(data: bytes, min_len: int = 4) -> Iterator[str]:
    seen: set[str] = set()
    for m in _rx(_ASCII_TMPL, min_len).finditer(data):
        s = m.group().decode("ascii", "ignore")
        if s not in seen:
            seen.add(s)
            yield s
    for m in _rx(_UTF16_TMPL, min_len).finditer(data):
        s = m.group().decode("utf-16le", "ignore").rstrip("\x00")
        if len(s) >= min_len and s not in seen:
            seen.add(s)
            yield s


def extract_urls(text: str) -> list[str]:
    return list(dict.fromkeys(_URL_RE.findall(text)))
