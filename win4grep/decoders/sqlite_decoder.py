# SQLite databases, merging any -wal/-shm sidecars via a checkpoint
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Iterator

from ..core.models import Record
from .base import Decoder, register
from .encodings import expand

SQLITE_MAGIC = b"SQLite format 3\x00"


@register
class SQLiteDecoder(Decoder):
    name = "sqlite"

    # sidecar files are provided to decode() via the pipeline's `sidecars` map
    def sniff(self, path: str, head: bytes) -> bool:
        return head[:16] == SQLITE_MAGIC

    def decode(self, source: str, path: str, data: bytes,
               sidecars: dict[str, bytes] | None = None) -> Iterator[Record]:
        tmp = Path(tempfile.mkdtemp(prefix="win4grep_sqlite_"))
        base = tmp / "db.sqlite"
        try:
            base.write_bytes(data)
            # drop WAL/SHM next to the db copy so SQLite recovers them on open
            if sidecars:
                for suffix in ("-wal", "-shm"):
                    blob = sidecars.get(suffix)
                    if blob is not None:
                        (tmp / f"db.sqlite{suffix}").write_bytes(blob)

            conn = sqlite3.connect(str(base))
            conn.text_factory = bytes
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
            yield from self._dump(conn, source, path)
            conn.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _dump(self, conn: sqlite3.Connection, source: str, path: str) -> Iterator[Record]:
        cur = conn.cursor()
        try:
            tables = cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            yield Record(source, path, self.name, "sqlite-error", "",
                         f"<cannot read schema: {exc}>", {"error": str(exc)})
            return

        for (tname_b,) in tables:
            tname = _s(tname_b)
            try:
                rows = cur.execute(f'SELECT rowid, * FROM "{tname}"')
                col_names = [d[0] for d in cur.description]
            except sqlite3.DatabaseError:
                continue
            for row in rows:
                rowid = row[0]
                parts = []
                for col, val in zip(col_names[1:], row[1:]):
                    parts.append(f"{col}={_render_value(val)}")
                    # expand encoded blobs/strings hiding in cells
                    if isinstance(val, (bytes, bytearray)) and val:
                        for label, txt in expand(bytes(val)):
                            if label != "raw" and label != "hex" and txt:
                                parts.append(f"{col}|{label}={txt}")
                text = " | ".join(parts)
                if text:
                    yield Record(source, path, self.name, "sqlite-row",
                                 f"{tname}:{rowid}", text,
                                 {"table": tname, "rowid": rowid})


def _s(b) -> str:
    return b.decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) else str(b)


def _render_value(val) -> str:
    if val is None:
        return ""
    if isinstance(val, (bytes, bytearray)):
        b = bytes(val)
        try:
            t = b.decode("utf-8")
            if t.isprintable() or "\n" in t:
                return t
        except UnicodeDecodeError:
            pass
        return f"<{len(b)}B blob>"
    return str(val)
