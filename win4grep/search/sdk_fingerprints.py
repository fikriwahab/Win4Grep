# Fingerprint iOS analytics / attribution / crash / push SDKs by file path
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class SDKSig:
    name: str
    category: str          # analytics | attribution | crash | push | network | telemetry
    patterns: tuple        # regex fragments matched (case-insensitive) against the path
    note: str = ""


# ordered by specificity, patterns match against POSIX-style paths
SDKS: list[SDKSig] = [
    SDKSig("NSURLSession Cache.db", "network",
           (r"/cache\.db(?:$|-wal|-shm)", r"cfurl_cache", r"/fscacheddata/"),
           "session tokens/cookies, response blobs are bplist"),
    SDKSig("Firebase Crashlytics", "crash",
           (r"com\.crashlytics\.data", r"\.clsrecord$", r"/crashlytics/"),
           "app-logged secrets can land in .clsrecord (v5/reports/active)"),
    SDKSig("Firebase/Google GDT", "analytics",
           (r"google-sdks-events", r"gdtcorflatfilestorage", r"/gdt_"),
           "Google Data Transport event queue"),
    SDKSig("Firebase Installations", "analytics",
           (r"persistedinstallation", r"firebaseinstallations", r"google.*installations"),
           "Firebase installation ID (FID)"),
    SDKSig("Google Analytics", "analytics",
           (r"googleanalytics-v\d", r"/ga_", r"\bgoogleanalytics\b"), ""),
    SDKSig("AppsFlyer", "attribution",
           (r"/appsflyer", r"appsflyer-v\d", r"appsflyerlib", r"af_"),
           "AppsFlyer UID, install attribution, IDFA/IDFV"),
    SDKSig("Adjust", "attribution",
           (r"/adjust\b", r"adjustioactivitystate", r"\badjust_"),
           "adjust device id, attribution"),
    SDKSig("Branch", "attribution",
           (r"/branch\b", r"branch_analytics", r"io\.branch"),
           "deep-link / attribution data"),
    SDKSig("MoEngage", "push",
           (r"/moengage", r"\bmoengage\b"),
           "device unique id, push, event params"),
    SDKSig("Amplitude", "analytics",
           (r"/amplitude", r"\.amplitude", r"amplitude.*\.(?:db|sqlite)"), ""),
    SDKSig("Mixpanel", "analytics",
           (r"/mixpanel", r"mpnetwork", r"mixpanel-"), ""),
    SDKSig("Segment", "analytics",
           (r"/segment\b", r"com\.segment", r"analytics\.segment"), ""),
    SDKSig("Facebook/Meta", "analytics",
           (r"com\.facebook\.sdk", r"/fbsdk", r"\bfbsdk\b"), ""),
    SDKSig("OneSignal", "push",
           (r"/onesignal", r"\bonesignal\b"), "push token"),
    SDKSig("Airship", "push",
           (r"/airship", r"com\.urbanairship", r"\buairship\b"), "push token / channel id"),
    SDKSig("Braze", "push",
           (r"/braze", r"com\.appboy", r"\bappboy\b"), ""),
    SDKSig("Singular", "attribution",
           (r"/singular\b", r"singular-"), ""),
    SDKSig("New Relic", "telemetry",
           (r"/newrelic", r"\bnrma"), ""),
    SDKSig("Datadog", "telemetry",
           (r"/datadog", r"com\.datadoghq"), ""),
    SDKSig("Sentry", "crash",
           (r"/sentry\b", r"io\.sentry"), ""),
    SDKSig("Instabug", "crash",
           (r"/instabug", r"\binstabug\b"), ""),
    SDKSig("Flutter (shared_preferences)", "framework",
           (r"\bflutter\.", r"io\.flutter", r"fluttersharedpreferences",
            r"flutter_assets"),
           "flutter.*_LOGIN keys often hold cleartext identity and credentials"),
    SDKSig("React Native (AsyncStorage)", "framework",
           (r"rctasynclocalstorage", r"react-?native", r"/rndatabase/"),
           "RCTAsyncLocalStorage often stores session/identity values"),
]

_COMPILED = [(s, [re.compile(p, re.I) for p in s.patterns]) for s in SDKS]


def classify_path(path: str) -> str | None:
    # Return the first SDK whose pattern matches this path, else None
    for sig, rxs in _COMPILED:
        if any(rx.search(path) for rx in rxs):
            return sig.name
    return None


def detect_sdks(paths: Iterable[str], max_hits: int = 25) -> dict[str, dict]:
    # Scan a set of file paths and return detected SDKs:
    # ``{name: {"category", "note", "hits": [paths...], "count": N}}``
    out: dict[str, dict] = {}
    for p in paths:
        for sig, rxs in _COMPILED:
            if any(rx.search(p) for rx in rxs):
                e = out.setdefault(sig.name, {"category": sig.category,
                                              "note": sig.note, "hits": [], "count": 0})
                e["count"] += 1
                if len(e["hits"]) < max_hits:
                    e["hits"].append(p)
    return out
