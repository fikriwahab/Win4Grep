# Core data structures shared across the import → decode → index pipeline
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Record:
    # one searchable unit of decoded text plus where it came from

    source: str          # logical name of the imported artifact (e.g. the .adbk file)
    path: str            # path of the file inside the source (POSIX style)
    decoder: str         # decoder that produced this record (e.g. "plist", "sqlite")
    kind: str            # fine-grained type: "plist-value", "sqlite-row", "cookie"...
    locator: str         # where inside the file: key path, "table:rowid", offset...
    text: str            # the plaintext that gets indexed and searched
    meta: dict[str, Any] = field(default_factory=dict)  # encoding chain, types, etc

    def as_row(self) -> tuple:
        import json

        return (
            self.source,
            self.path,
            self.decoder,
            self.kind,
            self.locator,
            self.text,
            json.dumps(self.meta, ensure_ascii=False, default=str),
        )


@dataclass
class Asset:
    # A raw file staged for decoding (extracted from an archive or on disk)

    source: str          # logical name of the importing artifact
    path: str            # path inside the source
    data: bytes          # raw bytes
