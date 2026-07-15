# Orchestrate: stage a source, decode every file, write records to the cache
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from .. import decoders
from .cache import Cache
from .importer import Staged, stage
from .models import Record

ProgressFn = Callable[[str, int, int], None]  # (current_path, files_done, records)

_HEAD = 4096
_MAX_FILE = 256 * 1024 * 1024  # skip absurdly large files (256 MB)

# structured decoders that don't already index raw strings, run a strings backstop
_NEEDS_BACKSTOP = {"plist", "sqlite", "binarycookies", "protobuf", "mobileprovision"}
_BACKSTOP_CHUNK = 200_000
_BACKSTOP_MEDIA = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".ttf",
                   ".otf", ".woff", ".woff2", ".mp3", ".mp4", ".mov", ".aac"}


def _strings_backstop(source: str, path: str, data: bytes,
                      decoder: str) -> Iterator[Record]:
    from ..decoders.strings_util import extract_strings
    lower = path.lower()
    if any(lower.endswith(e) for e in _BACKSTOP_MEDIA):
        return
    strings = list(extract_strings(data, min_len=5))
    if not strings:
        return
    blob = "\n".join(strings)
    for i in range(0, len(blob), _BACKSTOP_CHUNK):
        yield Record(source, path, decoder, "strings-backstop",
                     f"chunk:{i // _BACKSTOP_CHUNK}", blob[i:i + _BACKSTOP_CHUNK], {})


def import_source(cache: Cache, path: str | Path,
                  progress: ProgressFn | None = None,
                  replace: bool = True, decrypt: bool = True,
                  scan: bool = True) -> dict:
    staged = stage(path)
    try:
        if replace:
            cache.clear_source(staged.name)
        n_files = 0
        n_records = 0
        records_buf: list[Record] = []

        for rec in _iter_records(staged, decrypt=decrypt):
            records_buf.append(rec)
            if len(records_buf) >= 5000:
                n_records += cache.add_records(records_buf)
                records_buf.clear()
        if records_buf:
            n_records += cache.add_records(records_buf)

        # recount files for the summary
        n_files = sum(1 for _ in staged.files())
        cache.register_source(
            staged.name, staged.origin,
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            n_files, n_records,
        )
        cache.optimize()
        n_findings = cache.run_scan(staged.name) if scan else 0
        if progress:
            progress(staged.name, n_files, n_records)
        return {"source": staged.name, "files": n_files, "records": n_records,
                "findings": n_findings}
    finally:
        staged.cleanup()


def _iter_records(staged: Staged, decrypt: bool = True) -> Iterator[Record]:
    from ..decoders.crypto import CryptoHunter

    hunter = CryptoHunter(enabled=decrypt)
    files = list(staged.files())
    on_disk = {f for f in files}
    for f in files:
        # SQLite WAL/SHM are consumed alongside their parent db, not on their own
        if f.suffix.lower() in ("-wal", "-shm") or f.name.endswith(("-wal", "-shm")):
            continue
        try:
            size = f.stat().st_size
        except OSError:
            continue
        if size == 0 or size > _MAX_FILE:
            continue

        rel = staged.rel(f)
        try:
            with f.open("rb") as fh:
                head = fh.read(_HEAD)
                fh.seek(0)
                data = fh.read()
        except OSError:
            continue

        hunter.scan_file(rel, data)

        dec = decoders.pick(rel, head) or decoders.FALLBACK
        try:
            if dec.name == "sqlite":
                sidecars = _sidecars(f, on_disk)
                yield from dec.decode(staged.name, rel, data, sidecars=sidecars)
            else:
                yield from dec.decode(staged.name, rel, data)
        except Exception as exc:  # never let one bad file kill the import
            yield Record(staged.name, rel, dec.name, "decode-error", "",
                         f"<decoder {dec.name} failed: {exc}>", {"error": str(exc)})

        # also index the file's raw strings (catches anything the decoder skipped)
        if dec.name in _NEEDS_BACKSTOP:
            yield from _strings_backstop(staged.name, rel, data, dec.name)

    # after every file is scanned, attempt to decrypt collected blobs
    for rec in hunter.run():
        rec.source = staged.name
        yield rec


def _sidecars(db: Path, on_disk: set[Path]) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for suffix in ("-wal", "-shm"):
        cand = db.with_name(db.name + suffix)
        if cand in on_disk and cand.exists():
            try:
                out[suffix] = cand.read_bytes()
            except OSError:
                pass
    return out
