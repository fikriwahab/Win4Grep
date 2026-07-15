# Diff two imported sources: records added or removed between them
from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass
class DiffRow:
    change: str   # "added" | "removed"
    path: str
    locator: str
    text: str


def diff_sources(db_path: str, source_a: str, source_b: str,
                 limit: int = 5000) -> list[DiffRow]:
    # records in B but not A (added), and in A but not B (removed)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    def load(src: str) -> dict[tuple, sqlite3.Row]:
        rows = conn.execute(
            "SELECT path, locator, text FROM records WHERE source = ?", (src,))
        out = {}
        for r in rows:
            out[(_strip_root(r["path"]), r["locator"], r["text"])] = r
        return out

    a = load(source_a)
    b = load(source_b)
    conn.close()

    a_keys, b_keys = set(a), set(b)
    result: list[DiffRow] = []
    for k in b_keys - a_keys:
        r = b[k]
        result.append(DiffRow("added", r["path"], r["locator"], r["text"]))
    for k in a_keys - b_keys:
        r = a[k]
        result.append(DiffRow("removed", r["path"], r["locator"], r["text"]))
    result.sort(key=lambda d: (d.change, d.path))
    return result[:limit]


def _strip_root(path: str) -> str:
    # drop the leading (often timestamped) folder so files line up across snapshots
    parts = path.split("/", 1)
    return parts[1] if len(parts) == 2 else path
