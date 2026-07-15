# Background QThread workers so imports and searches never freeze the UI
from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from ..core.cache import Cache
from ..core.pipeline import import_source
from ..search.engine import Filters, Search


class ImportWorker(QThread):
    progress = Signal(str)                 # human-readable status line
    finished_one = Signal(dict)            # per-source result summary
    finished_all = Signal()
    failed = Signal(str, str)              # (path, error)

    def __init__(self, db_path: str, paths: list[str], replace: bool = True):
        super().__init__()
        self.db_path = db_path
        self.paths = paths
        self.replace = replace

    def run(self) -> None:
        with Cache(self.db_path) as cache:
            for path in self.paths:
                self.progress.emit(f"Importing {path} …")
                try:
                    res = import_source(cache, path, replace=self.replace)
                    self.finished_one.emit(res)
                    self.progress.emit(
                        f"{res['source']}: {res['files']} files, "
                        f"{res['records']} records")
                except Exception as exc:  # noqa: BLE001
                    self.failed.emit(path, str(exc))
        self.finished_all.emit()


class ScanWorker(QThread):
    # Re-run the secret/PII scan over the whole cache off the UI thread
    done = Signal(int)
    error = Signal(str)

    def __init__(self, db_path: str):
        super().__init__()
        self.db_path = db_path

    def run(self) -> None:
        try:
            with Cache(self.db_path) as cache:
                n = cache.run_scan()
            self.done.emit(n)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))


class SearchWorker(QThread):
    done = Signal(list)        # list[Hit]
    error = Signal(str)

    def __init__(self, db_path: str, query: str, mode: str,
                 filters: Filters, limit: int):
        super().__init__()
        self.db_path = db_path
        self.query = query
        self.mode = mode
        self.filters = filters
        self.limit = limit

    def run(self) -> None:
        s = Search(self.db_path)
        try:
            if self.mode == "regex":
                hits = s.regex(self.query, self.filters, self.limit)
            elif self.mode == "substring":
                hits = s.substring(self.query, self.filters, self.limit)
            else:
                hits = s.fts(self.query, self.filters, self.limit)
            self.done.emit(hits)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
        finally:
            s.close()
