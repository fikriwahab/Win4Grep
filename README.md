# Win4Grep

Inspired by VisualGrep, shoutout to the OG. Built to supplement my needs on iOS app reversing such as `.ipa` files and `.adbk` dumps.

Win4Grep takes an iOS app data dump and lets you search everything inside it, including the stuff that normal search tools can't read because it's binary or encoded.

> Note: Some features are still under development and need improvement. Beware that the PII or secret flagging feature might detect false positives or missing out things.

## The problem it solves

A lot of what's inside an app data dump isn't plain text. It is (usually) in binary plists, NSKeyedArchiver blobs, SQLite, cookies, protobuf, or base64/gzip, so a normal text search often misses it.

Win4Grep decodes those into plain text first, then lets you search across all of it.

## What it does

* Import a `.ipa`, a `.adbk` app data dump, a folder, or a single file.
* Decode binary plists, NSKeyedArchiver, SQLite (including data left in deleted rows), cookies, protobuf, and peel back base64, hex, gzip, zlib, and brotli layers.
* Decode JWTs on the spot, so the issuer, email, and account fields buried inside a token become searchable.
* Search everything three ways: full text, plain substring, or regex. Field names are searchable too, not just values.
* Auto scan for secrets and PII (JWTs, cloud keys, private keys, passwords, tokens, emails, phone numbers, cards) and sort them by how serious they are.
* Try to decrypt encrypted blobs when the key is sitting somewhere in the same dump.
* Tell you which analytics and tracking SDKs the app ships (Cache.db, Crashlytics, Firebase, AppsFlyer, MoEngage, and more).
* Pull every GraphQL query, mutation, and fragment out of a React Native bundle.
* Diff two dumps to see exactly what data got added or removed between them.
* Export search results or findings to CSV, JSON, or Markdown.

## The idea behind it

On top of the format decoders, every file also goes through a raw strings pass, so things a decoder misses (like data in deleted SQLite rows) are still searchable.

## Build and run from source

You need Python 3.10 or newer on Windows.

1. Clone the repo:

```powershell
git clone <repo-url>
cd Win4Grep
```

2. Create a virtual environment and install the dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

3. Run the GUI:

```powershell
.\.venv\Scripts\python -m win4grep
```

That opens the GUI. Use Import in the toolbar to load a dump, then search. The Findings tab shows the secrets it flagged. The Tools menu has SDK detection and dump diffing. Export is in the menu bar.

## Command line

If you prefer the terminal:

```powershell
.\.venv\Scripts\python -m win4grep.cli --db cache.db import app.adbk
.\.venv\Scripts\python -m win4grep.cli --db cache.db search "token"
.\.venv\Scripts\python -m win4grep.cli --db cache.db search "eyJ" --regex
.\.venv\Scripts\python -m win4grep.cli --db cache.db findings --severity high
.\.venv\Scripts\python -m win4grep.cli --db cache.db sdks
.\.venv\Scripts\python -m win4grep.cli --db cache.db graphql
.\.venv\Scripts\python -m win4grep.cli --db cache.db diff dumpA.adbk dumpB.adbk
.\.venv\Scripts\python -m win4grep.cli --db cache.db export findings out.csv
```

Import is slower when it tries to decrypt blobs. Add `--no-decrypt` to skip that, or `--no-scan` to skip the secret scan.

## Build the .exe

From the same virtual environment:

```powershell
.\.venv\Scripts\python -m pip install pyinstaller
.\.venv\Scripts\python -m PyInstaller --noconfirm Win4Grep.spec
```
