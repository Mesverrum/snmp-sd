#!/usr/bin/env python3
"""Look up table INDEX clauses via public OID pages.

Kentik profiles name the TABLE oid, not the Entry, and rarely list INDEX.
snmp_exporter needs the full INDEX (or AUGMENTS target). Writes
snmp/table-indexes.yaml for convert.py.

Primary:  https://oid-base.com/get/<oid>
Fallback: https://oidref.com/<oid>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "snmp" / "table-indexes.yaml"
DEFAULT_CACHE = Path.home() / ".cache" / "snmp-sd-oid-syntax"
DEFAULT_PROFILES = ROOT / "snmp" / "profiles"
DEFAULT_OID_SYNTAX = ROOT / "snmp" / "oid-syntax.yaml"

UA = "snmp-sd-profile-convert/lookup-oid-indexes (+https://github.com/Mesverrum/snmp-sd)"

INDEX_RE = re.compile(r"\bINDEX\s*\{([^}]+)\}", re.I)
AUGMENTS_RE = re.compile(r"\bAUGMENTS\s*\{([^}]+)\}", re.I)
NAME_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9-]*)\s+OBJECT-TYPE\b")
SYNTAX_RE = re.compile(r"\bSYNTAX\s+([A-Za-z][A-Za-z0-9-]*)", re.I)
CHILD_RE = re.compile(
    r"`([0-9]+(?:\.[0-9]+)+)`:\s*`([A-Za-z][A-Za-z0-9-]*)"
    r"|([0-9]+(?:\.[0-9]+)+)[^A-Za-z0-9.-]{0,80}([A-Za-z][A-Za-z0-9-]*)\s*\(\d+\)"
)
SEQ_OF = re.compile(r"\bSEQUENCE\s+OF\b", re.I)


def http_get(url: str, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return int(exc.code), body
    except urllib.error.URLError:
        return 0, ""


def fetch_page(oid: str, timeout: float, cache: Path) -> dict:
    """Cached raw page + parsed INDEX / AUGMENTS / children."""
    oid = oid.strip().lstrip(".")
    cp = cache / f"{oid}.page.json"
    if cp.is_file():
        try:
            return json.loads(cp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    body = ""
    source = ""
    for src, url in (
        ("oid-base", f"https://oid-base.com/get/{oid}"),
        ("oidref", f"https://oidref.com/{oid}"),
    ):
        status, text = http_get(url, timeout)
        if status == 200 and text and ("OBJECT-TYPE" in text or "INDEX" in text or "AUGMENTS" in text):
            body, source = text, src
            break
        if status == 200 and text and not body:
            body, source = text, src
    rec = parse_page(oid, body, source)
    cache.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps(rec), encoding="utf-8")
    return rec


def parse_page(oid: str, body: str, source: str) -> dict:
    name_m = NAME_RE.search(body or "")
    syn_m = SYNTAX_RE.search(body or "")
    idx_m = INDEX_RE.search(body or "")
    aug_m = AUGMENTS_RE.search(body or "")
    children: dict[str, str] = {}
    for m in CHILD_RE.finditer(body or ""):
        coid = m.group(1) or m.group(3)
        cname = m.group(2) or m.group(4)
        if coid and cname:
            children[cname] = coid.lstrip(".")
    index_parts: list[dict[str, str]] = []
    if idx_m:
        for raw in idx_m.group(1).split(","):
            tok = raw.strip().strip("'\"")
            if not tok:
                continue
            implied = False
            if tok.upper().startswith("IMPLIED "):
                implied = True
                tok = tok[8:].strip()
            # Drop SMIv2 comments / annotations.
            tok = re.sub(r"\s+", "", tok)
            if not re.match(r"^[A-Za-z][A-Za-z0-9-]*$", tok):
                continue
            part = {"name": tok}
            if implied:
                part["implied"] = "true"
            index_parts.append(part)
    return {
        "oid": oid,
        "name": name_m.group(1) if name_m else "",
        "syntax": syn_m.group(1) if syn_m else "",
        "is_table": bool(SEQ_OF.search(body or "")),
        "index": index_parts,
        "augments": (aug_m.group(1).strip() if aug_m else ""),
        "children": children,
        "source": source,
        "miss": not body,
    }


def collect_table_oids(root: Path) -> dict[str, str]:
    """table_oid → profile table name (best effort)."""
    out: dict[str, str] = {}
    if yaml is None:
        return out
    for path in root.rglob("*"):
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(data, dict):
            continue
        for block in data.get("metrics") or []:
            if not isinstance(block, dict):
                continue
            table = block.get("table") or {}
            if not isinstance(table, dict):
                continue
            oid = str(table.get("OID") or "").strip().lstrip(".")
            if not oid:
                continue
            out[oid] = str(table.get("name") or out.get(oid) or "")
    return out


def index_exporter_type(syntax: str, name: str) -> str:
    s = (syntax or "").upper().replace(" ", "").replace("-", "")
    n = name or ""
    if "INETADDRESSTYPE" in s or n.endswith("AddressType"):
        return "InetAddressType"
    if "INETADDRESS" in s or n.endswith("InetAddress"):
        return "InetAddress"
    if n.endswith("Address") and "Type" not in n and "Prefix" not in n:
        return "InetAddress"
    if "PHYSADDRESS" in s or "MACADDRESS" in s or n.endswith("PhysAddress") or n.endswith("MacAddress"):
        return "PhysAddress48"
    if "IPADDRESS" in s:
        return "InetAddress"
    if any(x in s for x in ("DISPLAYSTRING", "SNMPADMINSTRING", "OCTETSTRING", "OPAQUE", "DATEANDTIME")):
        if "DATEANDTIME" in s:
            return "DateAndTime"
        return "DisplayString"
    if s in {"OBJECTIDENTIFIER", "OBJECT"}:
        return "DisplayString"
    return "gauge"


def load_oid_syntax(path: Path) -> dict[str, dict]:
    if not path.is_file() or yaml is None:
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = data.get("oids") or {}
    return {str(k).lstrip("."): v for k, v in raw.items() if isinstance(v, dict)}


def resolve_index_type(
    name: str,
    children: dict[str, str],
    name_to_oid: dict[str, str],
    syntax_map: dict[str, dict],
    pages: dict[str, dict],
    timeout: float,
    cache: Path,
) -> tuple[str, str]:
    oid = children.get(name) or name_to_oid.get(name) or ""
    syntax = ""
    if oid and oid in syntax_map:
        syntax = str(syntax_map[oid].get("syntax") or "")
    elif oid and oid in pages:
        syntax = str(pages[oid].get("syntax") or "")
    # Do not HTTP every INDEX object — name + cached SYNTAX is enough.
    # Extra fetches here serialized the full run (~minutes of timeouts).
    return index_exporter_type(syntax, name), syntax


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profiles", type=Path, default=DEFAULT_PROFILES)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    ap.add_argument("--oid-syntax", type=Path, default=DEFAULT_OID_SYNTAX)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--table", action="append", default=[], help="Look up these table OIDs only")
    args = ap.parse_args()

    if args.table:
        tables = {t.strip().lstrip("."): "" for t in args.table}
    else:
        tables = collect_table_oids(args.profiles)
    oids = sorted(tables)
    if args.limit > 0:
        oids = oids[: args.limit]
    if not oids:
        print(f"ERROR: no table OIDs in {args.profiles}", file=sys.stderr)
        return 1

    syntax_map = load_oid_syntax(args.oid_syntax)
    print(f"tables={len(oids)} oid-syntax={len(syntax_map)} workers={args.workers}", flush=True)

    pages: dict[str, dict] = {}
    fetch_oids: list[str] = []
    for t in oids:
        fetch_oids.append(t)
        fetch_oids.append(t + ".1")
    fetch_oids = list(dict.fromkeys(fetch_oids))

    t0 = time.time()
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futs = {pool.submit(fetch_page, oid, args.timeout, args.cache): oid for oid in fetch_oids}
        for fut in as_completed(futs):
            rec = fut.result()
            pages[rec["oid"]] = rec
            done += 1
            if done % 25 == 0 or done == len(fetch_oids):
                rate = done / max(time.time() - t0, 0.001)
                print(f"  pages {done}/{len(fetch_oids)} {rate:.1f}/s", flush=True)

    name_to_oid: dict[str, str] = {}
    name_to_page: dict[str, dict] = {}
    for rec in pages.values():
        if rec.get("name"):
            name_to_oid[rec["name"]] = rec["oid"]
            name_to_page[rec["name"]] = rec
        for cname, coid in (rec.get("children") or {}).items():
            name_to_oid.setdefault(cname, coid)

    def entry_for(table_oid: str) -> dict | None:
        table = pages.get(table_oid) or {}
        entry = pages.get(table_oid + ".1") or {}
        if entry.get("index") or entry.get("augments"):
            return entry
        if table.get("index") or table.get("augments"):
            return table
        if entry.get("name"):
            return entry
        if table.get("name"):
            return table
        return entry or table or None

    def resolve_indexes(entry: dict, stack: list[str]) -> list[dict[str, str]] | None:
        name = entry.get("name") or entry.get("oid") or "?"
        if name in stack:
            return None
        if entry.get("index"):
            out: list[dict[str, str]] = []
            children = dict(entry.get("children") or {})
            for part in entry["index"]:
                iname = part["name"]
                typ, syntax = resolve_index_type(
                    iname, children, name_to_oid, syntax_map, pages, args.timeout, args.cache
                )
                item = {"labelname": iname, "type": typ}
                if syntax:
                    item["syntax"] = syntax
                if part.get("implied"):
                    item["implied"] = True
                out.append(item)
            return out
        aug = (entry.get("augments") or "").strip()
        if not aug:
            return None
        parent = name_to_page.get(aug)
        if parent is None and aug in name_to_oid:
            poid = name_to_oid[aug]
            if poid not in pages:
                pages[poid] = fetch_page(poid, args.timeout, args.cache)
            parent = pages.get(poid)
            if parent and parent.get("name"):
                name_to_page[parent["name"]] = parent
        if parent:
            return resolve_indexes(parent, stack + [name])
        return None

    resolved: dict[str, dict] = {}
    missing: list[str] = []
    for table_oid in oids:
        entry = entry_for(table_oid)
        indexes = resolve_indexes(entry, []) if entry else None
        if not indexes:
            missing.append(table_oid)
            continue
        resolved[table_oid] = {
            "name": tables.get(table_oid) or (entry or {}).get("name") or "",
            "entry": (entry or {}).get("oid") or "",
            "augments": (entry or {}).get("augments") or "",
            "source": (entry or {}).get("source") or "",
            "indexes": indexes,
        }

    doc = {
        "description": (
            "Table OID → snmp_exporter indexes from public OBJECT-TYPE INDEX/AUGMENTS. "
            "Generated by tools/snmp-profile-convert/lookup-oid-indexes.py. "
            "Not a MIB library. Live-walk overrides still win in convert.py."
        ),
        "tables_wanted": len(oids),
        "tables_resolved": len(resolved),
        "tables_missing": len(missing),
        "tables": resolved,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if yaml is None:
        args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    else:
        args.out.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    if missing:
        args.out.with_suffix(args.out.suffix + ".missing").write_text(
            "\n".join(missing) + "\n", encoding="utf-8"
        )
    print(
        f"wrote {args.out} resolved={len(resolved)}/{len(oids)} missing={len(missing)}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
