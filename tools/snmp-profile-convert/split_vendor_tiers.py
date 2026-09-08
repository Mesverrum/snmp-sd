#!/usr/bin/env python3
"""Apply the hot / cold / topology split to every converted vendor pack.

Rewrites ``snmp/modules``, concatenates ``snmp-network.yml``, and rebuilds
fingerprinters / sysobjectid-index / module-tiers from the existing index
(no kentik re-ingest).

Prints leftover metric classes so an operator can pull a walk back to hot.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import yaml

from convert import (
    DEFAULT_AUTHS,
    VENDOR_SIDECAR_SUFFIXES,
    build_fingerprinters,
    build_module_tiers_doc,
    concat_snmp_network,
    dump_yaml,
    hot_leaf_names,
    metric_tier,
    sidecar_base_name,
    skip_vendor_split,
    split_vendor_family,
    write_module_file,
)

REPO = Path(__file__).resolve().parents[2]
MODULES = REPO / "snmp" / "modules"
CONCAT = REPO / "snmp" / "snmp-network.yml"
FP = REPO / "snmp" / "fingerprinters.yml"
INDEX = REPO / "snmp" / "sysobjectid-index.yaml"
TIERS = REPO / "snmp" / "module-tiers.yaml"
AUTHS = REPO / "snmp" / "auths.yml"

POWER_PRODUCT_RE = (
    "pdu",
    "ups",
    "printer",
    "workcentre",
    "roomalert",
    "liebert",
    "watchdog",
    "netbotz",
)


def load_modules(modules_dir: Path) -> dict[str, tuple[str, dict]]:
    found: dict[str, tuple[str, dict]] = {}
    for path in sorted(modules_dir.rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        vendor = path.parent.name
        for name, mod in (data.get("modules") or {}).items():
            found[name] = (vendor, mod)
    return found


def merge_family(modules: dict[str, dict], base: str) -> dict:
    """Reassemble ``base`` + sidecars so a re-split picks up classifier changes."""
    names = [base, *[f"{base}{suf}" for suf in VENDOR_SIDECAR_SUFFIXES]]
    metrics: list = []
    walks: list = []
    gets: list = []
    seen_names: set[str] = set()
    for name in names:
        mod = modules.get(name) or {}
        for metric in mod.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            key = str(metric.get("name") or "") + "|" + str(metric.get("oid") or "")
            if key in seen_names:
                continue
            seen_names.add(key)
            metrics.append(dict(metric))
        for w in mod.get("walk") or []:
            if w not in walks:
                walks.append(w)
        for g in mod.get("get") or []:
            if g not in gets:
                gets.append(g)
    merged: dict = {"metrics": metrics}
    if walks:
        merged["walk"] = walks
    if gets:
        merged["get"] = gets
    return merged


def family_names(base: str) -> list[str]:
    return [base, *[f"{base}{suf}" for suf in VENDOR_SIDECAR_SUFFIXES]]


def sidecar_index_entry(vendor: str, part_name: str) -> dict:
    return {
        "profile": f"{part_name.replace('_', '-')}.yml",
        "vendor": vendor,
        "sysobjectids": [],
        "extends": [],
        "identity_lookups": [],
        "notes": "vendor tier sidecar",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    loaded = load_modules(MODULES)
    modules = {name: dict(mod) for name, (_vendor, mod) in loaded.items()}
    vendors = {name: vendor for name, (vendor, _mod) in loaded.items()}

    flags: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    split_report: list[str] = []
    power_products: list[str] = []

    stale_files: list[Path] = []
    for name in list(modules):
        if sidecar_base_name(name) or skip_vendor_split(name):
            continue
        if any(tok in name.lower() for tok in POWER_PRODUCT_RE):
            power_products.append(name)
        merged = merge_family(modules, name)
        for metric in merged.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            _kind, flag = metric_tier(metric)
            if flag:
                flags[flag][name].append(str(metric.get("name") or ""))
        parts = split_vendor_family(name, merged)
        vendor = vendors[name]
        for old in family_names(name):
            if old in modules and old not in parts:
                del modules[old]
                stale_files.append(MODULES / vendor / f"{old}.yml")
        for part_name, part_mod in parts.items():
            modules[part_name] = part_mod
            vendors[part_name] = vendor
            split_report.append(
                f"{name} -> {part_name} ({len(part_mod.get('metrics') or [])} metrics)"
            )

    print(f"==> packs split: {len({r.split(' ->', 1)[0] for r in split_report})}")
    for line in split_report:
        print(f"  {line}")

    print("==> leftover classes (cold by default — say if any should be hot)")
    for kind in sorted(flags):
        print(f"  [{kind}]")
        for mod in sorted(flags[kind]):
            names = sorted(set(flags[kind][mod]))
            print(f"    {mod}: {', '.join(names[:12])}" + (" …" if len(names) > 12 else ""))

    print("==> power/environment products (identity hot, rest cold — expected)")
    for name in sorted(set(power_products)):
        print(f"  {name}")

    leaves = hot_leaf_names(modules)
    print(f"==> vitals-only hot leaves: {len(leaves)}")

    if args.dry_run:
        print("dry-run: no files written")
        return 0

    for path in stale_files:
        if path.exists():
            path.unlink()
            print(f"removed stale {path.name}")

    index = yaml.safe_load(INDEX.read_text(encoding="utf-8")) or {}
    index.setdefault("modules", {})
    for name, module in modules.items():
        vendor = vendors.get(name, "_general")
        write_module_file(MODULES, vendor, name, module)
        if name not in index["modules"]:
            index["modules"][name] = sidecar_index_entry(vendor, name)
    for stale in list(index["modules"]):
        if stale not in modules and (index["modules"][stale] or {}).get("notes") == "vendor tier sidecar":
            del index["modules"][stale]

    if AUTHS.exists():
        auths = (yaml.safe_load(AUTHS.read_text(encoding="utf-8")) or {}).get("auths") or {}
    elif CONCAT.exists():
        auths = (yaml.safe_load(CONCAT.read_text(encoding="utf-8")) or {}).get("auths") or {}
    else:
        auths = {}
    if not auths:
        auths = DEFAULT_AUTHS
    concat_snmp_network(auths, modules, CONCAT)
    print(f"concat {CONCAT} modules={len(modules)}")

    fp = build_fingerprinters(index, hot_leaves=leaves)
    INDEX.write_text(
        "# GENERATED sysObjectID → module index (seed for discovery.snmp).\n"
        + dump_yaml(index),
        encoding="utf-8",
    )
    FP.write_text(
        "# GENERATED. Matcher model aligns with prometheus/snmp_exporter#1468\n"
        "# modules_hot / modules_cold / modules_topology = staggered scrape tiers.\n"
        "# Legacy `modules` remains the full chain for older tools.\n"
        + dump_yaml(fp),
        encoding="utf-8",
    )
    TIERS.write_text(
        "# GENERATED module → scrape tier (hot | cold | topology).\n"
        + dump_yaml(build_module_tiers_doc(modules)),
        encoding="utf-8",
    )
    print(f"wrote {FP}")
    print(f"wrote {INDEX}")
    print(f"wrote {TIERS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
