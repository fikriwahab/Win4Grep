# Local-only logging with secret redaction and a redacted crash handler
from __future__ import annotations

import logging
import logging.handlers
import re
import sys
import tempfile
import traceback
from pathlib import Path

# patterns redacted from logs and crash dumps
_REDACTIONS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), "<JWT>"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "<GOOGLE_API_KEY>"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<AWS_KEY>"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "<PRIVATE_KEY>"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"), "bearer <REDACTED>"),
    (re.compile(r"(?i)(\"?(?:pass(?:wd|word)?|pwd|secret|api[_-]?key|token|"
                r"client[_-]?secret)\"?\s*[:=]\s*\"?)[^\"'\s,}{]{3,}"), r"\1<REDACTED>"),
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "<EMAIL>"),
]

_LOGGER_NAME = "win4grep"


def redact(text: str) -> str:
    for rx, repl in _REDACTIONS:
        text = rx.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    # Masks secrets/PII in the fully-formatted log message before it is written

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True


def log_dir() -> Path:
    d = Path(tempfile.gettempdir()) / "win4grep" / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    # local rotating file logger (idempotent), no network handlers
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = logging.handlers.RotatingFileHandler(
        log_dir() / "win4grep.log", maxBytes=2_000_000, backupCount=3,
        encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    logger.propagate = False
    logger.info("logging initialised (local-only, redacted)")
    return logger


def install_excepthook() -> None:
    # log a redacted traceback, then defer to the previous excepthook
    logger = logging.getLogger(_LOGGER_NAME)
    prev = sys.excepthook

    def hook(exc_type, exc, tb) -> None:
        try:
            text = "".join(traceback.format_exception(exc_type, exc, tb))
            logger.error("UNHANDLED EXCEPTION:\n%s", redact(text))
        except Exception:
            pass
        prev(exc_type, exc, tb)

    sys.excepthook = hook


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)
