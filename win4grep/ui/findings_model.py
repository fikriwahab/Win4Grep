# Qt table model for the secret/PII findings view
from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

_HEADERS = ["Severity", "Rule", "Match", "Source", "Path"]
_SEV_COLOR = {"high": "#ff5252", "medium": "#ffb300", "low": "#9e9e9e"}


class FindingsModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._rows: list[dict] = []

    def set_rows(self, rows: list[dict]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def row_at(self, row: int) -> dict | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return len(_HEADERS)

    def data(self, index, role=Qt.DisplayRole):  # noqa: N802
        if not index.isValid():
            return None
        r = self._rows[index.row()]
        if role == Qt.DisplayRole:
            return [r["severity"], r["rule"], r["match"], r["source"], r["path"]][
                index.column()]
        if role == Qt.ForegroundRole and index.column() == 0:
            return QColor(_SEV_COLOR.get(r["severity"], "#000"))
        if role == Qt.ToolTipRole:
            return r.get("context", "")
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return _HEADERS[section]
        return None
