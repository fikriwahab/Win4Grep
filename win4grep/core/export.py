# Export search hits or findings to CSV / JSON / Markdown
from __future__ import annotations

import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Sequence


def _rows(items: Sequence) -> list[dict]:
    out = []
    for it in items:
        out.append(asdict(it) if is_dataclass(it) else dict(it))
    return out


def export(items: Sequence, path: str | Path, fmt: str | None = None) -> str:
    p = Path(path)
    fmt = (fmt or p.suffix.lstrip(".") or "json").lower()
    rows = _rows(items)

    if fmt == "json":
        p.write_text(json.dumps(rows, indent=2, ensure_ascii=False, default=str),
                     encoding="utf-8")
    elif fmt == "csv":
        if rows:
            with p.open("w", newline="", encoding="utf-8-sig") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
        else:
            p.write_text("", encoding="utf-8")
    elif fmt in ("md", "markdown"):
        p.write_text(_to_markdown(rows), encoding="utf-8")
    else:
        raise ValueError(f"unknown export format: {fmt}")
    return str(p)


def _to_markdown(rows: list[dict]) -> str:
    if not rows:
        return "_no rows_\n"
    cols = list(rows[0].keys())
    lines = ["| " + " | ".join(cols) + " |",
             "| " + " | ".join("---" for _ in cols) + " |"]
    for r in rows:
        cells = []
        for c in cols:
            v = str(r.get(c, "")).replace("\n", " ").replace("|", "\\|")
            cells.append(v[:200])
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"
