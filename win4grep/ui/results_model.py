# Qt table model backing the search-results view
from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from ..search.engine import Hit

_HEADERS = ["Source", "Path", "Type", "Where", "Match"]


class ResultsModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._hits: list[Hit] = []

    def set_hits(self, hits: list[Hit]) -> None:
        self.beginResetModel()
        self._hits = hits
        self.endResetModel()

    def hit_at(self, row: int) -> Hit | None:
        if 0 <= row < len(self._hits):
            return self._hits[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._hits)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return len(_HEADERS)

    def data(self, index, role=Qt.DisplayRole):  # noqa: N802
        if not index.isValid():
            return None
        h = self._hits[index.row()]
        if role == Qt.DisplayRole:
            col = index.column()
            if col == 0:
                return h.source
            if col == 1:
                return h.path
            if col == 2:
                return f"{h.decoder}/{h.kind}"
            if col == 3:
                return h.locator
            if col == 4:
                return h.snippet.replace("\n", " ")
        elif role == Qt.ToolTipRole:
            return h.path
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return _HEADERS[section]
        return None
