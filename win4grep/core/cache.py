# SQLite-backed cache with an FTS5 full-text index over decoded records
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable, Iterator

from .models import Record

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id      INTEGER PRIMARY KEY,
    source  TEXT NOT NULL,
    path    TEXT NOT NULL,
    decoder TEXT NOT NULL,
    kind    TEXT NOT NULL,
    locator TEXT NOT NULL,
    text    TEXT NOT NULL,
    meta    TEXT NOT NULL
);

-- index both the value and the field name (locator)
CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
    text,
    locator,
    content='records',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

-- keep the FTS index in sync with the records table
CREATE TRIGGER IF NOT EXISTS records_ai AFTER INSERT ON records BEGIN
    INSERT INTO fts(rowid, text, locator) VALUES (new.id, new.text, new.locator);
END;
CREATE TRIGGER IF NOT EXISTS records_ad AFTER DELETE ON records BEGIN
    INSERT INTO fts(fts, rowid, text, locator)
        VALUES('delete', old.id, old.text, old.locator);
END;

CREATE TABLE IF NOT EXISTS sources (
    name      TEXT PRIMARY KEY,
    origin    TEXT,
    imported  TEXT,
    n_files   INTEGER DEFAULT 0,
    n_records INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY,
    record_id INTEGER,
    source    TEXT,
    path      TEXT,
    decoder   TEXT,
    rule      TEXT,
    severity  TEXT,
    match     TEXT,
    context   TEXT
);
CREATE INDEX IF NOT EXISTS findings_rule ON findings(rule);
CREATE INDEX IF NOT EXISTS findings_sev ON findings(severity);
"""


class Cache:
    # Wraps the SQLite cache database. Use as a context manager

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # writing
    def add_records(self, records: Iterable[Record], batch: int = 2000) -> int:
        sql = ("INSERT INTO records(source, path, decoder, kind, locator, text, meta) "
               "VALUES (?, ?, ?, ?, ?, ?, ?)")
        cur = self.conn.cursor()
        n = 0
        buf: list[tuple] = []
        for rec in records:
            buf.append(rec.as_row())
            if len(buf) >= batch:
                cur.executemany(sql, buf)
                n += len(buf)
                buf.clear()
        if buf:
            cur.executemany(sql, buf)
            n += len(buf)
        self.conn.commit()
        return n

    def register_source(self, name: str, origin: str, imported: str,
                        n_files: int, n_records: int) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO sources(name, origin, imported, n_files, n_records) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, origin, imported, n_files, n_records),
        )
        self.conn.commit()

    def clear_source(self, name: str) -> None:
        self.conn.execute("DELETE FROM records WHERE source = ?", (name,))
        self.conn.execute("DELETE FROM findings WHERE source = ?", (name,))
        self.conn.execute("DELETE FROM sources WHERE name = ?", (name,))
        self.conn.commit()

    # secret/PII scan
    def run_scan(self, source: str | None = None) -> int:
        # scan records for secrets/PII and repopulate findings, returns the count
        from ..search.scanner import scan_text, scan_locator, scan_value_shape

        cols = "id, source, path, decoder, locator, text"
        if source:
            self.conn.execute("DELETE FROM findings WHERE source = ?", (source,))
            rows = self.conn.execute(
                f"SELECT {cols} FROM records WHERE source = ?", (source,))
        else:
            self.conn.execute("DELETE FROM findings")
            rows = self.conn.execute(f"SELECT {cols} FROM records")

        seen: set[tuple] = set()
        batch: list[tuple] = []

        def emit(r, f, ctx):
            key = (r["source"], f.rule, f.match)
            if key in seen:
                return
            seen.add(key)
            batch.append((r["id"], r["source"], r["path"], r["decoder"],
                          f.rule, f.severity, f.match, ctx))

        for r in rows:
            text = r["text"]
            for f in scan_text(text):
                emit(r, f, text[max(0, f.start - 40):f.end + 40])
            # by field name (locator)
            kf = scan_locator(r["locator"], text)
            if kf is not None:
                emit(r, kf, f"{r['locator']} = {text[:80]}")
            # high-entropy key/seed blob (e.g. obfuscated AES seed in prefs)
            vf = scan_value_shape(text)
            if vf is not None:
                emit(r, vf, f"{r['locator']}: {text[:60]}")
        if batch:
            self.conn.executemany(
                "INSERT INTO findings(record_id, source, path, decoder, rule, "
                "severity, match, context) VALUES (?,?,?,?,?,?,?,?)", batch)
        self.conn.commit()
        return len(batch)

    def get_findings(self, source: str | None = None) -> list[dict]:
        sql = "SELECT * FROM findings"
        params: tuple = ()
        if source:
            sql += " WHERE source = ?"
            params = (source,)
        sql += (" ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 "
                "ELSE 2 END, rule")
        return [dict(r) for r in self.conn.execute(sql, params)]

    def detect_sdks(self, source: str | None = None) -> dict:
        # fingerprint SDKs by file path and field name (locator)
        from ..search.sdk_fingerprints import detect_sdks
        where = " WHERE source = ?" if source else ""
        params: tuple = (source,) if source else ()
        paths = [r["path"] for r in
                 self.conn.execute(f"SELECT DISTINCT path FROM records{where}", params)]
        locs = [r["locator"] for r in self.conn.execute(
            f"SELECT DISTINCT locator FROM records{where}"
            f"{' AND' if source else ' WHERE'} locator <> ''", params)]
        return detect_sdks(paths + locs)

    # reading
    def stats(self) -> dict:
        c = self.conn.execute("SELECT COUNT(*) n FROM records").fetchone()["n"]
        srcs = self.conn.execute("SELECT * FROM sources ORDER BY name").fetchall()
        nf = self.conn.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
        return {"records": c, "findings": nf,
                "sources": [dict(s) for s in srcs]}

    def optimize(self) -> None:
        self.conn.execute("INSERT INTO fts(fts) VALUES('optimize')")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Cache":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
