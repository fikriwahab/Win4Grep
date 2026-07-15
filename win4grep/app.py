# GUI entry point
from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from .ui.main_window import MainWindow


def default_db_path() -> str:
    # absolute, writable cache path (a relative one breaks under a read-only CWD)
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    root = Path(base) if base else Path.home()
    d = root / "Win4Grep"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        d = Path.home()
    return str(d / "win4grep_cache.db")


def main(argv: list[str] | None = None) -> int:
    from .core.obs import setup_logging, install_excepthook
    setup_logging()
    install_excepthook()
    argv = list(sys.argv if argv is None else argv)
    db = argv[1] if len(argv) > 1 else default_db_path()
    app = QApplication(argv)
    app.setApplicationName("Win4Grep")
    app.setOrganizationName("Win4Grep")
    win = MainWindow(db)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
