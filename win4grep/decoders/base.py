# Decoder interface and the dispatch registry
from __future__ import annotations

from typing import Callable, Iterator

from ..core.models import Record

# A decoder yields Record objects for a given file
EmitFn = Callable[[Record], None]


class Decoder:
    # Base class. A decoder claims a file via ``sniff`` then produces records

    name = "base"

    def sniff(self, path: str, head: bytes) -> bool:
        # Return True if this decoder can handle the file. ``head`` is the
        # first few KB of the file (cheap magic-byte checks go here)
        return False

    def decode(self, source: str, path: str, data: bytes) -> Iterator[Record]:
        # Yield Record objects for the file's contents
        raise NotImplementedError


_REGISTRY: list[Decoder] = []


def register(decoder_cls: type[Decoder]) -> type[Decoder]:
    # Class decorator: instantiate the decoder and add it to the registry
    # (registration order == dispatch priority). Returns the class unchanged
    _REGISTRY.append(decoder_cls())
    return decoder_cls


def registry() -> list[Decoder]:
    return list(_REGISTRY)


def pick(path: str, head: bytes) -> Decoder | None:
    for dec in _REGISTRY:
        try:
            if dec.sniff(path, head):
                return dec
        except Exception:
            continue
    return None
