# Recursively peel base64 / hex / gzip / zlib / brotli / bplist / JSON / JWT layers
from __future__ import annotations

import base64
import binascii
import gzip
import json
import plistlib
import re
import zlib
from typing import Iterator

try:
    import blackboxprotobuf  # type: ignore
except Exception:  # pragma: no cover
    blackboxprotobuf = None

try:
    import brotli  # type: ignore
except Exception:  # pragma: no cover
    brotli = None

_B64_RE = re.compile(rb"^[A-Za-z0-9+/]{16,}={0,2}$")
_HEX_RE = re.compile(rb"^(?:[0-9a-fA-F]{2}){8,}$")
# JWT: three base64url segments, header & payload start with eyJ ('{"')
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
_MAX_DEPTH = 6


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for x in b if 9 <= x <= 13 or 32 <= x <= 126 or x >= 128)
    return printable / len(b)


def looks_textual(b: bytes) -> bool:
    return _printable_ratio(b[:4096]) > 0.85


def to_text(b: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="replace")


def _try_b64(s: bytes) -> bytes | None:
    t = s.strip()
    if len(t) < 16 or len(t) % 4 != 0 or not _B64_RE.match(t):
        return None
    try:
        out = base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None
    # reject if it just decoded back to noise of similar size with no structure
    return out if out else None


def _try_hex(s: bytes) -> bytes | None:
    t = s.strip()
    if not _HEX_RE.match(t):
        return None
    try:
        return bytes.fromhex(t.decode("ascii"))
    except ValueError:
        return None


def _try_gzip(b: bytes) -> bytes | None:
    if b[:2] != b"\x1f\x8b":
        return None
    try:
        return gzip.decompress(b)
    except OSError:
        return None


def _try_zlib(b: bytes) -> bytes | None:
    if not b or b[0] != 0x78:  # common zlib headers 0x78 0x01/9c/da
        return None
    try:
        return zlib.decompress(b)
    except zlib.error:
        return None


def _try_raw_deflate(b: bytes) -> bytes | None:
    # HTTP "Content-Encoding: deflate" sometimes ships raw (headerless) deflate
    if len(b) < 8:
        return None
    try:
        out = zlib.decompress(b, -15)
        return out if out and out != b else None
    except zlib.error:
        return None


def _try_brotli(b: bytes) -> bytes | None:
    # brotli has no magic, only attempt on non-textual blobs of reasonable size
    if brotli is None or len(b) < 8:
        return None
    try:
        out = brotli.decompress(b)
        return out if out and out != b else None
    except Exception:
        return None


def decode_jwts(text: str) -> list[tuple[str, str]]:
    # decode any JWTs in the text (header and payload) to JSON
    out: list[tuple[str, str]] = []
    for tok in dict.fromkeys(_JWT_RE.findall(text)):
        parts = tok.split(".")
        chunks = []
        for seg in parts[:2]:  # header, payload (skip signature)
            try:
                pad = seg + "=" * (-len(seg) % 4)
                obj = json.loads(base64.urlsafe_b64decode(pad))
                chunks.append(json.dumps(obj, ensure_ascii=False))
            except Exception:
                continue
        if chunks:
            out.append((tok[:24], " ".join(chunks)))
    return out


def _try_bplist(b: bytes):
    if b[:8] != b"bplist00":
        return None
    try:
        return plistlib.loads(b)
    except Exception:
        return None


def _try_json(b: bytes):
    t = b.strip()
    if not t or t[:1] not in (b"{", b"["):
        return None
    try:
        return json.loads(t)
    except Exception:
        return None


def try_protobuf(data: bytes) -> dict | None:
    # schema-less protobuf decode, returns a dict of fields or None
    if blackboxprotobuf is None or len(data) < 3:
        return None
    if (data[0] & 0x07) > 5 or (data[0] >> 3) == 0:
        return None
    try:
        message, _ = blackboxprotobuf.decode_message(data)
    except Exception:
        return None
    if not isinstance(message, dict) or not message:
        return None
    if all(v in (b"", "", 0, None) for v in message.values()):
        return None
    return _proto_stringify(message)


def _proto_stringify(obj):
    if isinstance(obj, dict):
        return {str(k): _proto_stringify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_proto_stringify(v) for v in obj]
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.hex()
    return obj


def expand(value, depth: int = 0) -> Iterator[tuple[str, str]]:
    # yield (label, text) for the value and any nested encodings
    if depth > _MAX_DEPTH:
        return

    if isinstance(value, str):
        raw = value.encode("utf-8", errors="replace")
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        return

    # the value itself
    if depth == 0:
        if looks_textual(raw):
            yield ("raw", to_text(raw))
        else:
            yield ("hex", raw.hex())

    # JWTs (base64url with dots, missed by the base64 transform)
    if looks_textual(raw):
        for tok, decoded in decode_jwts(to_text(raw)):
            yield (f"jwt[{tok}]", decoded)

    # try each transform, recurse into whatever decodes
    for label, fn in (
        ("gzip", _try_gzip),
        ("zlib", _try_zlib),
        ("bplist", _try_bplist),
        ("base64", _try_b64),
        ("hex", _try_hex),
    ):
        try:
            out = fn(raw)
        except Exception:
            out = None
        if out is None:
            continue

        if isinstance(out, (dict, list)):  # bplist → structured
            for kp, txt in walk_structured(out):
                yield (f"{label}>{kp}", txt)
            continue

        # bytes result: emit if useful, then recurse
        if isinstance(out, (bytes, bytearray)):
            if out == raw:
                continue
            if looks_textual(out):
                yield (label, to_text(out))
            sub = _try_bplist(out) or _try_json(out)
            if sub is not None:
                for kp, txt in walk_structured(sub):
                    yield (f"{label}>{kp}", txt)
            else:
                yield from ((f"{label}>{l}", t) for l, t in expand(out, depth + 1))

    # brotli / raw deflate have no magic, so binary blobs only
    if not looks_textual(raw):
        for label, fn in (("brotli", _try_brotli), ("deflate", _try_raw_deflate)):
            try:
                out = fn(raw)
            except Exception:
                out = None
            if not out:
                continue
            if looks_textual(out):
                yield (label, to_text(out))
            sub = _try_bplist(out) or _try_json(out)
            if sub is not None:
                for kp, txt in walk_structured(sub):
                    yield (f"{label}>{kp}", txt)
            else:
                yield from ((f"{label}>{l}", t) for l, t in expand(out, depth + 1))

        pb = try_protobuf(raw)
        if pb is not None:
            for kp, txt in walk_structured(pb):
                if txt:
                    yield (f"protobuf>{kp}", txt)


def walk_structured(obj, prefix: str = "") -> Iterator[tuple[str, str]]:
    # flatten a dict/list into (keypath, text) pairs, expanding encoded leaves
    if isinstance(obj, dict):
        for k, v in obj.items():
            kp = f"{prefix}.{k}" if prefix else str(k)
            yield from walk_structured(v, kp)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            kp = f"{prefix}[{i}]"
            yield from walk_structured(v, kp)
    elif isinstance(obj, (bytes, bytearray)):
        for label, txt in expand(obj):
            tag = prefix if label == "raw" or label == "hex" else f"{prefix}|{label}"
            yield (tag, txt)
    else:
        # scalar (str/int/float/bool/datetime/None)
        if isinstance(obj, str):
            for label, txt in expand(obj):
                if label == "raw":
                    yield (prefix, txt)
                else:
                    yield (f"{prefix}|{label}", txt)
        else:
            yield (prefix, str(obj))
