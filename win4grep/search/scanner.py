# Secret / PII scanner: a rule pack over decoded records, emitting findings
from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass
from typing import Iterator

# severities for sorting/colouring
HIGH, MEDIUM, LOW = "high", "medium", "low"


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    pattern: re.Pattern
    validator: str | None = None  # optional extra check: "luhn"


def _rx(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


RULES: list[Rule] = [
    Rule("JWT", HIGH, _rx(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}")),
    Rule("Private key", HIGH, _rx(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    Rule("AWS access key", HIGH, _rx(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("Google API key", HIGH, _rx(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Rule("Google OAuth client", MEDIUM, _rx(r"\b\d+-[0-9a-z]{32}\.apps\.googleusercontent\.com")),
    Rule("Stripe key", HIGH, _rx(r"\b[rsp]k_(?:live|test)_[0-9A-Za-z]{10,}\b")),
    Rule("GitHub token", HIGH, _rx(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    Rule("Slack token", HIGH, _rx(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    Rule("Firebase DB URL", LOW, _rx(r"https://[a-z0-9.-]+\.firebaseio\.com")),
    Rule("Credentials in URL", HIGH, _rx(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]{2,}@[^\s]+", re.I)),
    Rule("Bearer token", MEDIUM, _rx(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}")),
    Rule("Authorization header", MEDIUM, _rx(r"(?i)authorization[\"']?\s*[:=]\s*[\"']?(?:basic|bearer|token)\s+[A-Za-z0-9._\-=/+]{8,}")),
    Rule("Password field", MEDIUM,
         _rx(r"(?i)[\"']?(?:password|passwd|passphrase|pwd)[\"']?\s*[:=]\s*[\"']?([^\"'\s,}{]{4,64})"),
         validator="cred"),
    Rule("Secret/API key field", MEDIUM, _rx(r"(?i)\"?(?:api[_-]?key|secret|client[_-]?secret|access[_-]?token|private[_-]?key)\"?\s*[:=]\s*\"?[A-Za-z0-9._\-=/+]{8,}")),
    Rule("Email", LOW, _rx(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    Rule("Indonesian phone", LOW, _rx(r"\b(?:\+?62|0)8[1-9][0-9]{6,11}\b")),
    Rule("Credit card", MEDIUM, _rx(r"\b(?:\d[ -]?){13,19}\b"), validator="card"),
    Rule("IPv4 address", LOW, _rx(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    Rule("UUID / device id", LOW, _rx(r"\b[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\b")),
]


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card_ok(s: str) -> bool:
    # passes Luhn and matches a known network prefix/length (rejects long IDs)
    d = "".join(c for c in s if c.isdigit())
    n = len(d)
    if not _luhn_ok(d):
        return False
    p2, p4, p6 = int(d[:2]), int(d[:4]), int(d[:6])
    # (network, allowed lengths, prefix test)
    if d[0] == "4" and n in (13, 16, 19):                       # Visa
        return True
    if n == 16 and (51 <= p2 <= 55 or 2221 <= p4 <= 2720):       # Mastercard
        return True
    if n == 15 and p2 in (34, 37):                               # Amex
        return True
    if n == 16 and (d[:4] == "6011" or p2 == 65 or 644 <= int(d[:3]) <= 649):  # Discover
        return True
    if n in (16, 17, 18, 19) and 3528 <= p4 <= 3589:            # JCB
        return True
    if n in (14, 16, 19) and (p2 in (36, 38) or 300 <= int(d[:3]) <= 305):  # Diners
        return True
    return False


@dataclass
class Finding:
    rule: str
    severity: str
    match: str
    start: int
    end: int


# values that look like a credential match but are really code or build artifacts
_CRED_DENY = re.compile(
    r"(?i)^(=+|loop-|inline|asm-|prolog|epilog|true|false|null|nil|undefined|"
    r"function|return|void|const|let|var|type|self|this|none)\b|===|=>|\.type|\.value")

_PLACEHOLDER = re.compile(
    r"(?i)^(x{3,}|\*{3,}|\.{3,}|-{3,}|your[_-][\w-]*|<.+>|changeme|example|sample|redacted|"
    r"null|none|todo|placeholder|dummy|password|test\d*|string|value|default|n/?a)$|^(.)\2{4,}$")

_KEYISH_CTX = re.compile(r"(?i)key|secret|seed|token|\biv\b|\bsalt\b|\baes\b|\bhmac\b|mnemonic|passw|cipher|priv|credential|session")
_CARDISH_CTX = re.compile(r"(?i)card|\bpan\b|kartu|cc[_-]?num|creditcard")
_LOCALE_CTX = re.compile(r"(?i)languagepack|localiz|l10n|i18n|translation|\blang\b|locale|\bstrings\b")
_JUNK_CTX = re.compile(r"(?i)measurement|analytics|firebase|gmp|instance_id|mpaas|automation|cfurl|\bcache\b|device[_-]?id|uuidfordevice")

_ARCHIVE_NOISE = re.compile(r"(?i)ns\.keys|ns\.objects|ns\.string|\$objects|\$archiver|bplist")

_WORDS = re.compile(r"^[A-Za-z][A-Za-z ]{3,}$")


def _context(locator: str, path: str = "") -> str:
    return _ARCHIVE_NOISE.sub(" ", f"{locator or ''} {path or ''}")


def _looks_benign(value: str) -> bool:
    v = value.strip().strip("\"'")
    return bool(_CRED_DENY.search(v) or _PLACEHOLDER.search(v))


def _cred_ok(value: str) -> bool:
    return not _looks_benign(value)


def _weigh(name: str, base: str, value: str,
           keyish: bool, cardish: bool, locale: bool, junk: bool) -> str:
    if name == "UUID / device id":
        return MEDIUM if keyish else LOW
    if name == "Password field":
        v = value.strip().strip("\"'")
        if locale or (" " in v and _WORDS.match(v)):
            return LOW
        return base
    if name == "Credit card":
        if cardish:
            return MEDIUM
        return LOW if junk else base
    return base


def scan_text(text: str, locator: str = "", path: str = "",
              max_per_rule: int = 5) -> Iterator[Finding]:
    ctx = _context(locator, path)
    keyish = bool(_KEYISH_CTX.search(ctx))
    cardish = bool(_CARDISH_CTX.search(ctx))
    locale = bool(_LOCALE_CTX.search(ctx))
    junk = bool(_JUNK_CTX.search(ctx))
    for rule in RULES:
        n = 0
        for m in rule.pattern.finditer(text):
            full = m.group(0)
            value = m.group(1) if rule.pattern.groups else full
            if rule.validator == "luhn" and not _luhn_ok(full):
                continue
            if rule.validator == "card" and not _card_ok(full):
                continue
            if rule.validator == "cred" and not _cred_ok(value):
                continue
            sev = _weigh(rule.name, rule.severity, value, keyish, cardish, locale, junk)
            yield Finding(rule.name, sev, full[:200], m.start(), m.end())
            n += 1
            if n >= max_per_rule:
                break


# detect credentials/identity by field NAME (the locator), not value shape
_KEY_RULES: list[tuple[re.Pattern, str, str]] = [
    (_rx(r"(?i)(?:^|[._/])(password|passwd|passphrase|pwd)(?:$|[._/]|_login|_value)"), HIGH, "Stored password"),
    (_rx(r"(?i)(client[_-]?secret|api[_-]?key|private[_-]?key|secret[_-]?key|app[_-]?secret)"), HIGH, "Stored secret/API key"),
    (_rx(r"(?i)(access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|application_token|sessionvar|sessionref|session[_-]?token|\bseed\b|mnemonic|\bmpin\b)"), HIGH, "Stored token/secret"),
    (_rx(r"(?i)flutter\.[a-z0-9_]*(login|password|email|msisdn|phone|nik|ktp|dob|name|userid|user_id|balance|cif|account)"), HIGH, "Flutter stored credential/PII"),
    (_rx(r"(?i)\b(username|user_name|userid|user_id|login|cif|nik|ktp|account[_-]?number|rekening|msisdn)\b"), MEDIUM, "Stored identity/account field"),
]


def scan_locator(locator: str, value: str) -> Finding | None:
    # flag a record whose field name indicates a credential or identity
    if not locator or not value:
        return None
    v = value.strip()
    if len(v) < 2 or len(v) > 400 or _looks_benign(v):
        return None
    for rx, sev, label in _KEY_RULES:
        if rx.search(locator):
            return Finding(label, sev, v[:200], 0, len(v))
    return None


_B64_BLOB = re.compile(r"^[A-Za-z0-9+/]{20,64}={0,2}$")
_HEXKEY = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{48}$|^[0-9a-fA-F]{64}$")


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def scan_value_shape(locator: str, value: str) -> Finding | None:
    # flag a high entropy base64 or hex value that decodes to a 16 24 or 32 byte key
    v = value.strip()
    keyish = bool(_KEYISH_CTX.search(_context(locator)))
    if _HEXKEY.match(v):
        if keyish:
            return Finding("Candidate key/seed (hex)", MEDIUM, v, 0, len(v))
        return Finding("High entropy hex (hash or key)", LOW, v, 0, len(v))
    if _B64_BLOB.match(v):
        # a readable identifier is letters only, real keys carry a digit or symbol
        if not re.search(r"[0-9+/]", v):
            return None
        try:
            raw = base64.b64decode(v + "==", validate=False)
        except Exception:
            return None
        if len(raw) in (16, 24, 32):
            printable = sum(1 for c in raw if 32 <= c < 127) / len(raw)
            if printable < 0.6 and _entropy(raw) > 3.0:
                return Finding("Candidate key/seed (base64)", MEDIUM, v, 0, len(v))
    return None


_SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


def severity_rank(sev: str) -> int:
    return _SEVERITY_ORDER.get(sev, 3)
