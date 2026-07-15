# Query the cache: FTS5 full-text, regex, or plain substring
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Iterator


@dataclass
class Hit:
    id: int
    source: str
    path: str
    decoder: str
    kind: str
    locator: str
    text: str
    snippet: str


@dataclass
class Filters:
    sources: list[str] | None = None
    decoders: list[str] | None = None
    path_glob: str | None = None  # SQL LIKE pattern against path


def _fts_query(term: str) -> str:
    # tokenize like unicode61 (split on _ . etc) and prefix-match each token
    tokens = re.findall(r"[0-9A-Za-z]+", term)
    return " ".join(f'"{t}"*' for t in tokens) if tokens else f'"{term}"*'


def _where(filters: Filters | None, params: list) -> str:
    clauses = []
    if filters:
        if filters.sources:
            clauses.append("r.source IN (%s)" % ",".join("?" * len(filters.sources)))
            params.extend(filters.sources)
        if filters.decoders:
            clauses.append("r.decoder IN (%s)" % ",".join("?" * len(filters.decoders)))
            params.extend(filters.decoders)
        if filters.path_glob:
            clauses.append("r.path LIKE ?")
            params.append(filters.path_glob)
    return (" AND " + " AND ".join(clauses)) if clauses else ""


class Search:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

    def fts(self, query: str, filters: Filters | None = None,
            limit: int = 500) -> list[Hit]:
        params: list = [_fts_query(query)]
        where = _where(filters, params)
        params.append(limit)
        sql = f"""
            SELECT r.id, r.source, r.path, r.decoder, r.kind, r.locator, r.text,
                   snippet(fts, 0, '«', '»', ' … ', 12) AS snip
            FROM fts JOIN records r ON r.id = fts.rowid
            WHERE fts MATCH ? {where}
            ORDER BY bm25(fts) LIMIT ?
        """
        return [self._hit(row, row["snip"]) for row in self.conn.execute(sql, params)]

    def substring(self, needle: str, filters: Filters | None = None,
                  limit: int = 500, ignore_case: bool = True) -> list[Hit]:
        params: list = []
        where = _where(filters, params)
        op = "LIKE" if ignore_case else "GLOB"
        pat = f"%{needle}%" if ignore_case else f"*{needle}*"
        # search both the value and the field-name/path (locator)
        params.insert(0, pat)
        params.insert(1, pat)
        sql = f"""
            SELECT r.id, r.source, r.path, r.decoder, r.kind, r.locator, r.text
            FROM records r WHERE (r.text {op} ? OR r.locator {op} ?) {where} LIMIT ?
        """
        params.append(limit)
        return [self._hit(row, _ctx2(row["text"], row["locator"], needle, ignore_case))
                for row in self.conn.execute(sql, params)]

    def regex(self, pattern: str, filters: Filters | None = None,
              limit: int = 500, flags: int = re.IGNORECASE) -> list[Hit]:
        rx = re.compile(pattern, flags)
        params: list = []
        where = _where(filters, params)
        sql = f"""
            SELECT r.id, r.source, r.path, r.decoder, r.kind, r.locator, r.text
            FROM records r WHERE 1=1 {where}
        """
        hits: list[Hit] = []
        for row in self.conn.execute(sql, params):
            m = rx.search(row["text"])
            if m:
                hits.append(self._hit(row, _ctx_at(row["text"], m.start(), m.end())))
            elif rx.search(row["locator"] or ""):
                hits.append(self._hit(row, row["locator"]))
            if len(hits) >= limit:
                break
        return hits

    def _hit(self, row: sqlite3.Row, snippet: str) -> Hit:
        return Hit(row["id"], row["source"], row["path"], row["decoder"],
                   row["kind"], row["locator"], row["text"], snippet)

    def close(self) -> None:
        self.conn.close()


def _ctx(text: str, needle: str, ignore_case: bool, width: int = 60) -> str:
    idx = (text.lower().find(needle.lower()) if ignore_case else text.find(needle))
    if idx < 0:
        return text[:120]
    return _ctx_at(text, idx, idx + len(needle), width)


def _ctx2(text: str, locator: str, needle: str, ignore_case: bool) -> str:
    # Snippet from the value if the needle is there, else from the field name
    hay = (text or "")
    found = (hay.lower().find(needle.lower()) if ignore_case else hay.find(needle))
    if found >= 0:
        return _ctx_at(hay, found, found + len(needle))
    return f"[field] {locator}"


def _ctx_at(text: str, start: int, end: int, width: int = 60) -> str:
    a = max(0, start - width)
    b = min(len(text), end + width)
    pre = "…" if a > 0 else ""
    post = "…" if b < len(text) else ""
    return f"{pre}{text[a:start]}«{text[start:end]}»{text[end:b]}{post}"
