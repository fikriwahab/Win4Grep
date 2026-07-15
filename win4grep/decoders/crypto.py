# Decrypt blobs using AES keys/passphrases found elsewhere in the same dump
# (CBC/ECB/GCM). A result is accepted only when it parses as text/plist/JSON.
from __future__ import annotations

import gzip
import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Iterator

from ..core.models import Record
from .encodings import looks_textual, to_text, _try_bplist, _try_json, try_protobuf

try:
    from Crypto.Cipher import AES  # pycryptodome
except Exception:  # pragma: no cover
    AES = None

# tunables (bound the combinatorial cost)
MAX_KEYS = 300
MAX_BLOBS = 250
MAX_BLOB_LEN = 1 << 20          # 1 MB per blob
MIN_BLOB_LEN = 16
MAX_TRIALS = 150_000            # global (blob × key) trial budget
GCM_MAX_LEN = 1 << 16          # only try GCM on blobs ≤ 64 KB
KEY_SIZES = (16, 24, 32)

_HEX_KEY_RE = re.compile(rb"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})\b")
_B64_RE = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
# values whose key-name suggests a secret (we hash these into key material too)
_SECRET_HINT = re.compile(
    rb'"?(?:[a-z_]*(?:key|secret|password|passphrase|token|seed|iv|salt)[a-z_]*)"?'
    rb'\s*[:=]\s*"?([A-Za-z0-9+/=_\-]{6,64})', re.IGNORECASE)


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


@dataclass
class CryptoHunter:
    keys: dict[bytes, str] = field(default_factory=dict)        # key -> origin label
    blobs: list[tuple[bytes, str, str]] = field(default_factory=list)  # (data, path, locator)
    _passphrases: set[bytes] = field(default_factory=set)
    enabled: bool = True

    # collection (called per file during import)
    def scan_file(self, path: str, data: bytes) -> None:
        if not self.enabled or AES is None:
            return
        self._harvest_keys(data, path)
        self._harvest_blobs(data, path)

    def _add_key(self, raw: bytes, origin: str) -> None:
        if len(raw) in KEY_SIZES and raw not in self.keys and len(self.keys) < MAX_KEYS:
            self.keys[raw] = origin

    def _add_passphrase(self, pw: bytes) -> None:
        if 4 <= len(pw) <= 64:
            self._passphrases.add(pw)

    def _harvest_keys(self, data: bytes, path: str) -> None:
        import base64
        for m in _HEX_KEY_RE.finditer(data):
            try:
                self._add_key(bytes.fromhex(m.group(1).decode()), f"hex@{path}")
            except ValueError:
                pass
        for m in _SECRET_HINT.finditer(data):
            val = m.group(1)
            self._add_passphrase(val)
            try:
                self._add_key(base64.b64decode(val + b"==", validate=False),
                              f"secret-b64@{path}")
            except Exception:
                pass
        # base64 values that decode to exactly a key size
        for m in _B64_RE.finditer(data[:200_000]):
            try:
                dec = base64.b64decode(m.group() + b"==", validate=False)
            except Exception:
                continue
            self._add_key(dec, f"b64@{path}")

    def _harvest_blobs(self, data: bytes, path: str) -> None:
        # whole-file ciphertext (high-entropy, block-aligned, not a container)
        if MIN_BLOB_LEN <= len(data) <= MAX_BLOB_LEN and self._file_ciphertext(data):
            self._add_blob(data, path, "file")
        # base64-wrapped binary blobs inside text
        import base64
        for m in _B64_RE.finditer(data[:200_000]):
            try:
                dec = base64.b64decode(m.group() + b"==", validate=False)
            except Exception:
                continue
            if self._blob_candidate(dec):
                self._add_blob(dec, path, "b64-blob")

    def _add_blob(self, data: bytes, path: str, locator: str) -> None:
        if len(self.blobs) < MAX_BLOBS:
            self.blobs.append((data, path, locator))

    @staticmethod
    def _blob_candidate(b: bytes) -> bool:
        if not (MIN_BLOB_LEN <= len(b) <= MAX_BLOB_LEN):
            return False
        if b[:8] == b"bplist00" or b[:2] == b"\x1f\x8b" or b[:5] == b"<?xml":
            return False  # already-plaintext containers
        if b[:1] == b"\x03" and b[1:2] in (b"\x00", b"\x01"):
            return True   # RNCryptor v3 header
        # block-aligned, and not mostly printable ASCII (that would be plaintext)
        if len(b) % 16 != 0:
            return False
        ascii_ratio = sum(1 for c in b[:256] if 32 <= c < 127) / min(len(b), 256)
        return ascii_ratio < 0.75

    @staticmethod
    def _file_ciphertext(b: bytes) -> bool:
        if b[:1] == b"\x03" and b[1:2] in (b"\x00", b"\x01"):
            return True
        if b[:8] == b"bplist00" or b[:2] == b"\x1f\x8b":
            return False
        return len(b) % 16 == 0 and _entropy(b[:4096]) > 6.5

    # decryption (called once after all files scanned)
    def _all_keys(self) -> dict[bytes, str]:
        keys = dict(self.keys)
        for pw in self._passphrases:
            for algo in (hashlib.sha256, hashlib.md5, hashlib.sha1):
                dk = algo(pw).digest()
                if len(dk) in KEY_SIZES and dk not in keys:
                    keys[dk] = f"hash({algo().name})"
            # sha1 -> 20 bytes, not a key size, truncate/pad common variants
            keys.setdefault(hashlib.sha256(pw).digest()[:16], "sha256[:16]")
        return keys

    def run(self) -> Iterator[Record]:
        if not self.enabled or AES is None or not self.blobs or not self.keys \
                and not self._passphrases:
            return
        keys = self._all_keys()
        seen: set[bytes] = set()
        trials = 0
        for data, path, locator in self.blobs:
            for key, origin in keys.items():
                if trials >= MAX_TRIALS:
                    yield Record("", path, "crypto", "note", "",
                                 f"<decrypt budget {MAX_TRIALS} trials reached; "
                                 f"some blobs not exhausted>", {})
                    return
                trials += 1
                pt = self._try_all_modes(data, key)
                if pt is None:
                    continue
                h = hashlib.sha1(pt[:256]).digest()
                if h in seen:
                    continue
                seen.add(h)
                yield from self._emit(pt, path, locator, key, origin)
                break  # one successful key per blob is enough

    def _try_all_modes(self, ct: bytes, key: bytes) -> bytes | None:
        # CBC/ECB: test the first two blocks before decrypting the whole blob
        candidates = []
        if len(ct) > 16 and (len(ct) - 16) % 16 == 0:
            candidates.append(("cbc-iv", ct[:16], ct[16:]))
        if len(ct) % 16 == 0:
            candidates.append(("cbc-zero", b"\x00" * 16, ct))
            candidates.append(("ecb", None, ct))

        for mode, iv, body in candidates:
            probe = body[:32] if len(body) > 32 else body
            head = self._decrypt(mode, key, iv, probe)
            if head is None or not self._plausible_head(head):
                continue
            full = self._decrypt(mode, key, iv, body)  # head looks real → full
            if full is not None and self._plausible(full):
                return full

        # GCM: wrong key fails the tag check fast, small blobs only
        if 28 < len(ct) <= GCM_MAX_LEN:
            pt = self._decrypt("gcm", key, ct[:12], ct[12:])
            if pt is not None and self._plausible(pt):
                return pt
        return None

    @staticmethod
    def _plausible_head(head: bytes) -> bool:
        # does this look like the start of plaintext? (full check is _plausible)
        if not head:
            return False
        if head[:6] == b"bplist" or head[:5] == b"<?xml" or head[:2] == b"\x1f\x8b":
            return True
        if head[:1] in (b"{", b"["):
            return True
        printable = sum(1 for c in head if c in (9, 10, 13) or 32 <= c < 127)
        return printable / len(head) > 0.75

    @staticmethod
    def _decrypt(mode: str, key: bytes, iv, body: bytes) -> bytes | None:
        try:
            if mode == "ecb":
                pt = AES.new(key, AES.MODE_ECB).decrypt(body)
            elif mode.startswith("cbc"):
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            elif mode == "gcm":
                tag, ct = body[-16:], body[:-16]
                pt = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
            else:
                return None
        except Exception:
            return None
        return _unpad(pt) if mode != "gcm" else pt

    @staticmethod
    def _plausible(pt: bytes) -> bool:
        # accept only a validated container (bplist/json/xml/gzip) or plain text
        if len(pt) < 8:
            return False
        if _try_bplist(pt) is not None or _try_json(pt) is not None:
            return True
        if pt[:5] == b"<?xml":
            return True
        if pt[:2] == b"\x1f\x8b":
            try:
                gzip.decompress(pt)
                return True
            except OSError:
                return False
        try:
            s = pt.decode("utf-8")
        except UnicodeDecodeError:
            return False
        if not s:
            return False
        printable = sum(1 for ch in s if ch in "\t\r\n " or 32 <= ord(ch) < 127)
        return printable / len(s) > 0.90

    def _emit(self, pt: bytes, path: str, locator: str, key: bytes,
              origin: str) -> Iterator[Record]:
        meta = {"key_hex": key.hex(), "key_origin": origin}
        loc = f"{locator} (key {key.hex()[:16]}… from {origin})"
        obj = _try_bplist(pt) or _try_json(pt) or try_protobuf(pt)
        if obj is not None:
            from .encodings import walk_structured
            for kp, txt in walk_structured(obj):
                if txt:
                    yield Record("", path, "crypto", "decrypted", f"{loc} {kp}",
                                 txt, meta)
        else:
            yield Record("", path, "crypto", "decrypted", loc, to_text(pt), meta)


def _unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= 16 and b[-pad:] == bytes([pad]) * pad:
        return b[:-pad]
    return b
