# Stage an import source (.ipa / .adbk / .zip / folder / single file) onto disk
# so the pipeline can walk real files (and find SQLite WAL/SHM sidecars)
from __future__ import annotations

import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

_ARCHIVE_SUFFIXES = {".ipa", ".adbk", ".zip", ".abbu"}


@dataclass
class Staged:
    name: str            # logical source name (file/folder name)
    root: Path           # directory to walk
    origin: str          # original path the user gave
    _temp: Path | None   # temp dir to clean up, if any

    def files(self) -> Iterator[Path]:
        if self.root.is_file():
            yield self.root
            return
        for p in sorted(self.root.rglob("*")):
            if p.is_file():
                yield p

    def rel(self, p: Path) -> str:
        if self.root.is_file():
            return self.root.name
        return p.relative_to(self.root).as_posix()

    def cleanup(self) -> None:
        if self._temp is not None:
            import shutil
            shutil.rmtree(self._temp, ignore_errors=True)


def stage(path: str | Path) -> Staged:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(p)

    if p.is_dir():
        return Staged(name=p.name, root=p, origin=str(p), _temp=None)

    if p.suffix.lower() in _ARCHIVE_SUFFIXES and zipfile.is_zipfile(p):
        temp = Path(tempfile.mkdtemp(prefix="win4grep_import_"))
        with zipfile.ZipFile(p) as zf:
            # guard against zip-slip
            for member in zf.namelist():
                dest = (temp / member).resolve()
                if not str(dest).startswith(str(temp.resolve())):
                    continue
                zf.extract(member, temp)
        return Staged(name=p.name, root=temp, origin=str(p), _temp=temp)

    # plain single file (e.g. a lone .db or .plist)
    return Staged(name=p.name, root=p, origin=str(p), _temp=None)
