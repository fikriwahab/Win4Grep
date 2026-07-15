# Decode JWTs found in records (header and payload, no signature verification)
from __future__ import annotations

import base64
import json
import re

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def _b64url(seg: str):
    pad = "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg + pad))
    except Exception:
        return None


def find_jwts(text: str) -> list[str]:
    return list(dict.fromkeys(_JWT_RE.findall(text)))


def decode_jwt(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    header = _b64url(parts[0])
    payload = _b64url(parts[1])
    if header is None and payload is None:
        return None
    out = []
    if header is not None:
        out.append("header  = " + json.dumps(header, indent=2, ensure_ascii=False))
    if payload is not None:
        out.append("payload = " + json.dumps(payload, indent=2, ensure_ascii=False))
        for claim in ("exp", "iat", "nbf"):
            if isinstance(payload, dict) and claim in payload:
                from datetime import datetime, timezone
                try:
                    ts = datetime.fromtimestamp(int(payload[claim]), timezone.utc)
                    out.append(f"  {claim} = {ts.isoformat()}")
                except Exception:
                    pass
    return "\n".join(out)
