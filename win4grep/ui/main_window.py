# Main application window: import dumps, search, hunt secrets, diff, export
from __future__ import annotations

import re

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QCompleter, QFileDialog, QHBoxLayout,
    QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
    QPlainTextEdit, QPushButton, QSplitter, QStatusBar, QTabWidget, QTableView,
    QToolBar, QVBoxLayout, QWidget,
)

from ..core.cache import Cache
from ..core.export import export as export_rows
from ..search.engine import Filters, Hit
from ..search.jwt_util import decode_jwt, find_jwts
from .findings_model import FindingsModel
from .results_model import ResultsModel
from .workers import ImportWorker, ScanWorker, SearchWorker

ARCHIVE_FILTER = "App dumps (*.ipa *.adbk *.zip *.abbu);;All files (*)"
ALL_DECODERS = ["plist", "sqlite", "binarycookies", "macho", "protobuf",
                "realm", "leveldb", "mobileprovision", "crypto", "text"]


class MainWindow(QMainWindow):
    def __init__(self, db_path: str):
        super().__init__()
        self.db_path = db_path
        self.setWindowTitle(f"Win4Grep - {db_path}")
        self.resize(1240, 800)

        self._import_worker: ImportWorker | None = None
        self._search_worker: SearchWorker | None = None
        self._scan_worker: ScanWorker | None = None
        self._history: list[str] = []
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(250)
        self._debounce.timeout.connect(self._run_search)

        self._build_menu()
        self._build_ui()
        self._refresh_sources()
        self._update_stats()

    # menu
    def _build_menu(self) -> None:
        m = self.menuBar()
        fm = m.addMenu("&File")
        fm.addAction("Import file…", self._import_files)
        fm.addAction("Import folder…", self._import_folder)
        fm.addSeparator()
        fm.addAction("Open cache…", self._open_cache)
        fm.addSeparator()
        fm.addAction("Quit", self.close)

        tm = m.addMenu("&Tools")
        tm.addAction("Rescan secrets", self._rescan)
        tm.addAction("Detected SDKs…", self._show_sdks)
        tm.addAction("Diff two sources…", self._diff_dialog)

        em = m.addMenu("&Export")
        em.addAction("Export search results…", lambda: self._export("search"))
        em.addAction("Export findings…", lambda: self._export("findings"))

    # UI construction
    def _build_ui(self) -> None:
        tb = QToolBar("Main")
        tb.setMovable(False)
        self.addToolBar(tb)
        tb.addAction(QAction("Import file…", self, triggered=self._import_files))
        tb.addAction(QAction("Import folder…", self, triggered=self._import_folder))
        tb.addSeparator()
        tb.addAction(QAction("Open cache…", self, triggered=self._open_cache))

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_search_tab(), "Search")
        self.tabs.addTab(self._build_findings_tab(), "Findings")
        self.setCentralWidget(self.tabs)
        self.setStatusBar(QStatusBar())

    def _build_search_tab(self) -> QWidget:
        self.query = QLineEdit()
        self.query.setPlaceholderText("Search everything…  (Enter to search)")
        self.query.textChanged.connect(lambda: self._debounce.start())
        self.query.returnPressed.connect(self._run_search)
        f = self.query.font(); f.setPointSize(f.pointSize() + 1); self.query.setFont(f)
        self._completer = QCompleter(self._history, self)
        self._completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.query.setCompleter(self._completer)

        self.mode = QComboBox()
        self.mode.addItems(["Full-text", "Substring", "Regex"])
        self.mode.currentIndexChanged.connect(self._run_search)

        self.source_filter = QComboBox()
        self.source_filter.addItem("All sources", None)
        self.source_filter.currentIndexChanged.connect(self._run_search)

        self.path_filter = QLineEdit()
        self.path_filter.setPlaceholderText("path contains…")
        self.path_filter.setMaximumWidth(180)
        self.path_filter.textChanged.connect(lambda: self._debounce.start())

        go = QPushButton("Search")
        go.clicked.connect(self._run_search)

        row = QHBoxLayout()
        row.addWidget(self.query, 1)
        row.addWidget(self.mode)
        row.addWidget(self.source_filter)
        row.addWidget(self.path_filter)
        row.addWidget(go)

        self.decoder_boxes: dict[str, QCheckBox] = {}
        dec_row = QHBoxLayout()
        dec_row.addWidget(QLabel("Types:"))
        for name in ALL_DECODERS:
            cb = QCheckBox(name)
            cb.setChecked(True)
            cb.stateChanged.connect(self._run_search)
            self.decoder_boxes[name] = cb
            dec_row.addWidget(cb)
        dec_row.addStretch(1)

        self.model = ResultsModel()
        self.table = self._make_table(self.model, self._show_detail, self._table_menu)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 320)

        self.detail = QPlainTextEdit(readOnly=True)
        self.detail.setFont(QFont("Consolas", 10))
        self.detail_header = QLabel("Select a result")
        self.detail_header.setWordWrap(True)
        self.detail_header.setTextInteractionFlags(Qt.TextSelectableByMouse)

        splitter = self._detail_splitter(self.table, self.detail_header, self.detail)
        w = QWidget()
        v = QVBoxLayout(w)
        v.addLayout(row)
        v.addLayout(dec_row)
        v.addWidget(splitter, 1)
        return w

    def _build_findings_tab(self) -> QWidget:
        self.sev_filter = QComboBox()
        self.sev_filter.addItem("All severities", None)
        for s in ("high", "medium", "low"):
            self.sev_filter.addItem(s, s)
        self.sev_filter.currentIndexChanged.connect(self._reload_findings)

        self.finding_source = QComboBox()
        self.finding_source.addItem("All sources", None)
        self.finding_source.currentIndexChanged.connect(self._reload_findings)

        rescan = QPushButton("Rescan")
        rescan.clicked.connect(self._rescan)
        exp = QPushButton("Export…")
        exp.clicked.connect(lambda: self._export("findings"))

        row = QHBoxLayout()
        row.addWidget(QLabel("Findings:"))
        row.addWidget(self.sev_filter)
        row.addWidget(self.finding_source)
        row.addStretch(1)
        row.addWidget(rescan)
        row.addWidget(exp)

        self.findings_model = FindingsModel()
        self.findings_table = self._make_table(
            self.findings_model, self._show_finding, None)
        fh = self.findings_table.horizontalHeader()
        fh.setSectionResizeMode(2, QHeaderView.Stretch)

        self.finding_detail = QPlainTextEdit(readOnly=True)
        self.finding_detail.setFont(QFont("Consolas", 10))
        self.finding_header = QLabel("Select a finding")
        self.finding_header.setWordWrap(True)
        self.finding_header.setTextInteractionFlags(Qt.TextSelectableByMouse)

        splitter = self._detail_splitter(
            self.findings_table, self.finding_header, self.finding_detail)
        w = QWidget()
        v = QVBoxLayout(w)
        v.addLayout(row)
        v.addWidget(splitter, 1)
        return w

    def _make_table(self, model, on_select, on_menu) -> QTableView:
        t = QTableView()
        t.setModel(model)
        t.setSelectionBehavior(QTableView.SelectRows)
        t.setSelectionMode(QTableView.SingleSelection)
        t.setEditTriggers(QTableView.NoEditTriggers)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        t.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        t.selectionModel().selectionChanged.connect(on_select)
        if on_menu:
            t.setContextMenuPolicy(Qt.CustomContextMenu)
            t.customContextMenuRequested.connect(on_menu)
        return t

    def _detail_splitter(self, table, header, detail) -> QSplitter:
        box = QWidget()
        dl = QVBoxLayout(box)
        dl.setContentsMargins(4, 4, 4, 4)
        dl.addWidget(header)
        dl.addWidget(detail, 1)
        sp = QSplitter(Qt.Vertical)
        sp.addWidget(table)
        sp.addWidget(box)
        sp.setSizes([480, 320])
        return sp

    # imports
    def _import_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Import .ipa / .adbk / file", "", ARCHIVE_FILTER)
        if paths:
            self._start_import(paths)

    def _import_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Import folder")
        if path:
            self._start_import([path])

    def _start_import(self, paths: list[str]) -> None:
        if self._import_worker and self._import_worker.isRunning():
            QMessageBox.information(self, "Busy", "An import is already running.")
            return
        self.statusBar().showMessage("Importing…")
        self._import_worker = ImportWorker(self.db_path, paths)
        self._import_worker.progress.connect(self.statusBar().showMessage)
        self._import_worker.failed.connect(
            lambda p, e: QMessageBox.warning(self, "Import failed", f"{p}\n\n{e}"))
        self._import_worker.finished_all.connect(self._on_import_done)
        self._import_worker.start()

    def _on_import_done(self) -> None:
        self._refresh_sources()
        self._update_stats()
        self._run_search()
        self._reload_findings()

    # search
    def _current_filters(self) -> Filters:
        decs = [n for n, cb in self.decoder_boxes.items() if cb.isChecked()]
        if len(decs) == len(self.decoder_boxes):
            decs = None
        src = self.source_filter.currentData()
        pf = self.path_filter.text().strip()
        return Filters(sources=[src] if src else None, decoders=decs,
                       path_glob=f"%{pf}%" if pf else None)

    def _run_search(self) -> None:
        q = self.query.text().strip()
        if not q:
            self.model.set_hits([])
            self._update_stats()
            return
        mode = {"Full-text": "fts", "Substring": "substring",
                "Regex": "regex"}[self.mode.currentText()]
        if mode == "regex":
            try:
                re.compile(q)
            except re.error as exc:
                self.statusBar().showMessage(f"Bad regex: {exc}")
                return
        prev = self._search_worker
        if prev is not None:
            try:
                if prev.isRunning():
                    prev.requestInterruption()
            except RuntimeError:
                pass
        worker = SearchWorker(self.db_path, q, mode, self._current_filters(), 1000)
        worker.setParent(self)
        worker.done.connect(self._on_results)
        worker.error.connect(
            lambda e: self.statusBar().showMessage(f"Search error: {e}"))
        worker.finished.connect(worker.deleteLater)
        self._search_worker = worker
        worker.start()

    def _on_results(self, hits: list[Hit]) -> None:
        if self.sender() is not self._search_worker:
            return
        self.model.set_hits(hits)
        q = self.query.text().strip()
        if q and q not in self._history:
            self._history.insert(0, q)
            self._completer.model().setStringList(self._history)
        if hits:
            self.table.selectRow(0)
        else:
            self.detail.clear()
            self.detail_header.setText("No matches")
        self.statusBar().showMessage(f"{len(hits)} hit(s)")

    def _show_detail(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        hit = self.model.hit_at(rows[0].row())
        if not hit:
            return
        self.detail_header.setText(
            f"<b>{hit.source}</b> :: {hit.path}<br>"
            f"<span style='color:#888'>{hit.decoder}/{hit.kind} - {hit.locator}</span>")
        self.detail.setPlainText(hit.text)
        self._highlight(self.detail, hit.text,
                        self.query.text().strip(), self.mode.currentText())
        self._append_jwts(self.detail, hit.text)

    def _append_jwts(self, widget: QPlainTextEdit, text: str) -> None:
        jwts = find_jwts(text)
        if not jwts:
            return
        blocks = ["", "─" * 60, f"DECODED JWT ×{len(jwts)}"]
        for tok in jwts[:5]:
            dec = decode_jwt(tok)
            if dec:
                blocks.append(f"\n• {tok[:32]}…\n{dec}")
        widget.appendPlainText("\n".join(blocks))

    @staticmethod
    def _highlight(widget: QPlainTextEdit, text: str, q: str, mode: str) -> None:
        if not q:
            return
        fmt = QTextCharFormat()
        fmt.setBackground(QColor("#ffd54f"))
        spans: list[tuple[int, int]] = []
        try:
            if mode == "Regex":
                for m in re.finditer(q, text, re.IGNORECASE):
                    spans.append((m.start(), m.end()))
            else:
                low, needle, start = text.lower(), q.lower(), 0
                while needle:
                    i = low.find(needle, start)
                    if i < 0:
                        break
                    spans.append((i, i + len(needle)))
                    start = i + len(needle)
        except re.error:
            return
        cur = widget.textCursor()
        for a, b in spans[:2000]:
            cur.setPosition(a)
            cur.setPosition(b, QTextCursor.KeepAnchor)
            cur.mergeCharFormat(fmt)
        if spans:
            c = widget.textCursor()
            c.setPosition(spans[0][0])
            widget.setTextCursor(c)
            widget.ensureCursorVisible()

    # findings
    def _reload_findings(self) -> None:
        src = self.finding_source.currentData()
        sev = self.sev_filter.currentData()
        try:
            with Cache(self.db_path) as cache:
                rows = cache.get_findings(src)
        except Exception as exc:  # noqa: BLE001
            self.statusBar().showMessage(f"Findings error: {exc}")
            return
        if sev:
            rows = [r for r in rows if r["severity"] == sev]
        self.findings_model.set_rows(rows)
        self.tabs.setTabText(1, f"Findings ({len(rows)})")

    def _show_finding(self) -> None:
        rows = self.findings_table.selectionModel().selectedRows()
        if not rows:
            return
        r = self.findings_model.row_at(rows[0].row())
        if not r:
            return
        self.finding_header.setText(
            f"<b>[{r['severity']}]</b> {r['rule']} - <b>{r['source']}</b><br>"
            f"<span style='color:#888'>{r['path']}</span>")
        full = ""
        if r.get("record_id"):
            try:
                with Cache(self.db_path) as cache:
                    row = cache.conn.execute(
                        "SELECT text FROM records WHERE id=?",
                        (r["record_id"],)).fetchone()
                    full = row["text"] if row else ""
            except Exception:
                full = ""
        body = f"MATCH: {r['match']}\n\nCONTEXT: …{r.get('context','')}…\n"
        if full:
            body += "\n" + "─" * 60 + "\nFULL RECORD:\n" + full
        self.finding_detail.setPlainText(body)
        self._highlight(self.finding_detail, body, r["match"], "Substring")
        self._append_jwts(self.finding_detail, full or r.get("context", ""))

    def _rescan(self) -> None:
        if self._scan_worker and self._scan_worker.isRunning():
            return
        self.statusBar().showMessage("Rescanning for secrets…")
        self._scan_worker = ScanWorker(self.db_path)
        self._scan_worker.setParent(self)
        self._scan_worker.done.connect(self._on_rescan)
        self._scan_worker.error.connect(
            lambda e: self.statusBar().showMessage(f"Scan error: {e}"))
        self._scan_worker.finished.connect(self._scan_worker.deleteLater)
        self._scan_worker.start()

    def _on_rescan(self, n: int) -> None:
        self.statusBar().showMessage(f"Scan complete: {n} findings")
        self._reload_findings()

    # diff / export
    def _show_sdks(self) -> None:
        src = self.source_filter.currentData()
        with Cache(self.db_path) as cache:
            sdks = cache.detect_sdks(src)
        if not sdks:
            QMessageBox.information(self, "Detected SDKs", "No known SDKs detected.")
            return
        lines = []
        for name, info in sorted(sdks.items(), key=lambda kv: (kv[1]["category"], kv[0])):
            note = f" - {info['note']}" if info["note"] else ""
            lines.append(f"[{info['category']}] {name}  ({info['count']} files){note}")
            for h in info["hits"][:4]:
                lines.append(f"      {h}")
        self.detail.setPlainText("\n".join(lines))
        self.detail_header.setText(
            f"<b>Detected SDKs</b> - {len(sdks)} telemetry/analytics SDK(s)")
        self.tabs.setCurrentIndex(0)

    def _diff_dialog(self) -> None:
        with Cache(self.db_path) as cache:
            names = [s["name"] for s in cache.stats()["sources"]]
        if len(names) < 2:
            QMessageBox.information(self, "Diff", "Need at least two imported sources.")
            return
        a, ok = QInputDialog.getItem(self, "Diff", "Baseline (A):", names, 0, False)
        if not ok:
            return
        b, ok = QInputDialog.getItem(self, "Diff", "Compare (B):", names,
                                     min(1, len(names) - 1), False)
        if not ok or a == b:
            return
        from ..core.diff import diff_sources
        rows = diff_sources(self.db_path, a, b)
        added = sum(1 for r in rows if r.change == "added")
        lines = [f"DIFF  A={a}  B={b}", f"added (in B only): {added}   "
                 f"removed (in A only): {len(rows) - added}", "─" * 60]
        for r in rows[:3000]:
            sign = "+" if r.change == "added" else "-"
            lines.append(f"{sign} {r.path} [{r.locator}]  {r.text[:120]!r}")
        self.detail.setPlainText("\n".join(lines))
        self.detail_header.setText(f"<b>Diff</b> {a} → {b}")
        self.tabs.setCurrentIndex(0)

    def _export(self, what: str) -> None:
        if what == "findings":
            items = self.findings_model._rows
            default = "findings.csv"
        else:
            items = self.model._hits if hasattr(self.model, "_hits") else []
            default = "results.csv"
        if not items:
            QMessageBox.information(self, "Export", "Nothing to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export", default,
            "CSV (*.csv);;JSON (*.json);;Markdown (*.md)")
        if not path:
            return
        try:
            out = export_rows(items, path)
            self.statusBar().showMessage(f"Exported {len(items)} rows → {out}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Export failed", str(exc))

    # helpers
    def _table_menu(self, pos) -> None:
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        hit = self.model.hit_at(idx.row())
        if not hit:
            return
        menu = QMenu(self)
        menu.addAction("Copy match text",
                       lambda: QApplication.clipboard().setText(hit.text))
        menu.addAction("Copy file path",
                       lambda: QApplication.clipboard().setText(hit.path))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _refresh_sources(self) -> None:
        with Cache(self.db_path) as cache:
            names = [s["name"] for s in cache.stats()["sources"]]
        for combo in (self.source_filter, getattr(self, "finding_source", None)):
            if combo is None:
                continue
            current = combo.currentData()
            combo.blockSignals(True)
            combo.clear()
            combo.addItem("All sources", None)
            for n in names:
                combo.addItem(n, n)
            idx = combo.findData(current)
            if idx >= 0:
                combo.setCurrentIndex(idx)
            combo.blockSignals(False)

    def _update_stats(self) -> None:
        with Cache(self.db_path) as cache:
            st = cache.stats()
        self.statusBar().showMessage(
            f"{st['records']:,} records · {st.get('findings', 0):,} findings · "
            f"{len(st['sources'])} source(s)")

    def closeEvent(self, event) -> None:  # noqa: N802
        # let background threads finish so Qt doesn't tear down a running QThread
        for w in (self._search_worker, self._scan_worker, self._import_worker):
            try:
                if w is not None and w.isRunning():
                    w.requestInterruption()
                    w.wait(3000)
            except RuntimeError:
                pass
        super().closeEvent(event)

    def _open_cache(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open cache database", "", "SQLite cache (*.db);;All files (*)")
        if path:
            self.db_path = path
            self.setWindowTitle(f"Win4Grep - {path}")
            self._refresh_sources()
            self._update_stats()
            self.model.set_hits([])
            self._reload_findings()
