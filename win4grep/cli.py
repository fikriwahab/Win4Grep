# Command-line interface for quick imports and searching without the GUI
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core.cache import Cache
from .core.pipeline import import_source
from .search.engine import Filters, Search

DEFAULT_DB = "win4grep_cache.db"


def cmd_import(args: argparse.Namespace) -> int:
    with Cache(args.db) as cache:
        for src in args.paths:
            print(f"[*] importing {src} ...", flush=True)
            res = import_source(cache, src, replace=not args.append,
                                decrypt=not args.no_decrypt,
                                scan=not args.no_scan)
            print(f"    -> {res['files']} files, {res['records']} records, "
                  f"{res.get('findings', 0)} findings")
        print(f"[+] cache: {args.db}")
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    with Cache(args.db) as cache:
        rows = cache.get_findings(args.source or None)
        if args.severity:
            rows = [r for r in rows if r["severity"] == args.severity]
        color = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[90m"}
        for r in rows:
            c = color.get(r["severity"], "")
            print(f"{c}[{r['severity']:6}]\033[0m {r['rule']:22} {r['match'][:70]}")
            print(f"         \033[36m{r['source']}\033[0m :: {r['path']}")
        print(f"\n[{len(rows)} finding(s)]", file=sys.stderr)
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    s = Search(args.db)
    filters = Filters(
        sources=args.source or None,
        decoders=args.decoder or None,
        path_glob=f"%{args.path}%" if args.path else None,
    )
    if args.regex:
        hits = s.regex(args.query, filters, limit=args.limit)
    elif args.substr:
        hits = s.substring(args.query, filters, limit=args.limit)
    else:
        hits = s.fts(args.query, filters, limit=args.limit)

    for h in hits:
        print(f"\n\033[36m{h.source}\033[0m :: {h.path}  "
              f"[\033[33m{h.decoder}/{h.kind}\033[0m {h.locator}]")
        print(f"  {h.snippet}")
    print(f"\n[{len(hits)} hit(s)]", file=sys.stderr)
    s.close()
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    with Cache(args.db) as cache:
        st = cache.stats()
        print(f"records: {st['records']}")
        for src in st["sources"]:
            print(f"  - {src['name']}: {src['n_files']} files, "
                  f"{src['n_records']} records ({src['imported']})")
    return 0


def cmd_sdks(args: argparse.Namespace) -> int:
    with Cache(args.db) as cache:
        sdks = cache.detect_sdks(args.source or None)
    if not sdks:
        print("no known SDKs detected")
        return 0
    for name, info in sorted(sdks.items(), key=lambda kv: (kv[1]["category"], kv[0])):
        note = f"  - {info['note']}" if info["note"] else ""
        print(f"\033[33m{info['category']:11}\033[0m \033[36m{name}\033[0m "
              f"({info['count']} files){note}")
        for h in info["hits"][:3]:
            print(f"             {h}")
    print(f"\n[{len(sdks)} SDK(s) detected]", file=sys.stderr)
    return 0


def cmd_graphql(args: argparse.Namespace) -> int:
    import sqlite3
    conn = sqlite3.connect(args.db)
    rows = conn.execute(
        "SELECT kind, locator FROM records WHERE decoder='graphql' "
        "AND kind LIKE 'graphql-%' AND kind != 'graphql-summary' ORDER BY kind, locator")
    by_kind: dict[str, list[str]] = {}
    for kind, name in rows:
        by_kind.setdefault(kind.replace("graphql-", ""), []).append(name)
    conn.close()
    total = 0
    for kind in ("query", "mutation", "subscription", "fragment"):
        names = by_kind.get(kind, [])
        total += len(names)
        if names:
            print(f"\033[33m{kind} ({len(names)})\033[0m")
            for n in names:
                print(f"  {n}")
    print(f"\n[{total} GraphQL operations/fragments]", file=sys.stderr)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    from .core.diff import diff_sources

    rows = diff_sources(args.db, args.source_a, args.source_b)
    for r in rows:
        sign = "\033[32m+\033[0m" if r.change == "added" else "\033[31m-\033[0m"
        print(f"{sign} {r.path} [{r.locator}]  {r.text[:100]!r}")
    added = sum(1 for r in rows if r.change == "added")
    removed = len(rows) - added
    print(f"\n[+{added} / -{removed}]", file=sys.stderr)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .core.export import export

    with Cache(args.db) as cache:
        if args.what == "findings":
            items = cache.get_findings(args.source or None)
        else:
            s = Search(args.db)
            items = s.fts(args.query or "", limit=args.limit)
            s.close()
    out = export(items, args.out, args.format)
    print(f"[+] wrote {len(items)} rows -> {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    from .core.obs import setup_logging, install_excepthook
    setup_logging()
    install_excepthook()
    p = argparse.ArgumentParser(
        prog="win4grep",
        description="Import iOS app dumps and search the decoded contents.")
    p.add_argument("--db", default=DEFAULT_DB, help="cache database path")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("import", help="import .ipa/.adbk/folder/file into the cache")
    pi.add_argument("paths", nargs="+")
    pi.add_argument("--append", action="store_true",
                    help="keep existing records for a source instead of replacing")
    pi.add_argument("--no-decrypt", action="store_true",
                    help="skip the crypto decrypt pass (faster)")
    pi.add_argument("--no-scan", action="store_true",
                    help="skip the secret/PII scan")
    pi.set_defaults(func=cmd_import)

    ps = sub.add_parser("search", help="search the cache")
    ps.add_argument("query")
    ps.add_argument("--regex", action="store_true")
    ps.add_argument("--substr", action="store_true")
    ps.add_argument("--source", action="append")
    ps.add_argument("--decoder", action="append")
    ps.add_argument("--path", help="substring match against file path")
    ps.add_argument("--limit", type=int, default=200)
    ps.set_defaults(func=cmd_search)

    pst = sub.add_parser("stats", help="show cache contents")
    pst.set_defaults(func=cmd_stats)

    pf = sub.add_parser("findings", help="list secret/PII findings")
    pf.add_argument("--source", help="limit to one source")
    pf.add_argument("--severity", choices=["high", "medium", "low"])
    pf.set_defaults(func=cmd_findings)

    psd = sub.add_parser("sdks", help="detect analytics/telemetry SDKs by fingerprint")
    psd.add_argument("--source")
    psd.set_defaults(func=cmd_sdks)

    pg = sub.add_parser("graphql", help="list GraphQL operations derived from JS bundles")
    pg.set_defaults(func=cmd_graphql)

    pd = sub.add_parser("diff", help="diff two imported sources (added/removed records)")
    pd.add_argument("source_a")
    pd.add_argument("source_b")
    pd.set_defaults(func=cmd_diff)

    pe = sub.add_parser("export", help="export findings or a search to csv/json/md")
    pe.add_argument("what", choices=["findings", "search"])
    pe.add_argument("out", help="output file (.csv/.json/.md)")
    pe.add_argument("--query", help="query when exporting a search")
    pe.add_argument("--source")
    pe.add_argument("--format", choices=["csv", "json", "md"])
    pe.add_argument("--limit", type=int, default=10000)
    pe.set_defaults(func=cmd_export)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
