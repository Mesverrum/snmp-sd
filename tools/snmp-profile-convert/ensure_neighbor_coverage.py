#!/usr/bin/env python3
"""Rebuild catalogs so every topology chain includes lldp_mib (cdp_mib on Cisco).

Does not re-ingest Kentik profiles. Rewrites fingerprinters / sysobjectid-index
/ module-tiers / snmp-network.yml from the on-disk module library.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from convert import (
    DEFAULT_AUTHS,
    build_fingerprinters,
    build_module_tiers_doc,
    concat_snmp_network,
    dump_yaml,
    hot_leaf_names,
    partition_module_chain,
)

REPO = Path(__file__).resolve().parents[2]
MODULES = REPO / "snmp" / "modules"
CONCAT = REPO / "snmp" / "snmp-network.yml"
FP = REPO / "snmp" / "fingerprinters.yml"
INDEX = REPO / "snmp" / "sysobjectid-index.yaml"
TIERS = REPO / "snmp" / "module-tiers.yaml"
AUTHS = REPO / "snmp" / "auths.yml"


def load_modules() -> dict:
    found: dict = {}
    for path in sorted(MODULES.rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, mod in (data.get("modules") or {}).items():
            found[name] = mod
    return found


def sidecar_entry(name: str) -> dict:
    return {
        "profile": f"{name.replace('_', '-')}.yml",
        "vendor": "_general",
        "sysobjectids": [],
        "extends": [],
        "identity_lookups": [],
        "notes": "IEEE LLDP / CISCO-CDP coverage module",
        "extends_modules": [],
        "module_chain": [name],
        "module_chain_hot": [],
        "module_chain_cold": [],
        "module_chain_topology": [name],
    }


def main() -> int:
    modules = load_modules()
    if "lldp_mib" not in modules or "cdp_mib" not in modules:
        print("need snmp/modules/_general/{lldp,cdp}_mib.yml", file=sys.stderr)
        return 1

    index = yaml.safe_load(INDEX.read_text(encoding="utf-8")) or {}
    meta = index.setdefault("modules", {})
    for name in ("lldp_mib", "cdp_mib"):
        if name not in meta:
            meta[name] = sidecar_entry(name)

    known = set(meta) | set(modules)
    leaves = hot_leaf_names(modules)
    for name, entry in meta.items():
        chain = list(entry.get("module_chain") or [name])
        tiers = partition_module_chain(chain, known, hot_leaves=leaves)
        entry["module_chain_hot"] = tiers["hot"]
        entry["module_chain_cold"] = tiers["cold"]
        entry["module_chain_topology"] = tiers["topology"]

    auths = {}
    if AUTHS.exists():
        auths = (yaml.safe_load(AUTHS.read_text(encoding="utf-8")) or {}).get("auths") or {}
    if not auths:
        auths = DEFAULT_AUTHS

    INDEX.write_text(
        "# GENERATED sysObjectID → module index (seed for discovery.snmp).\n"
        + dump_yaml(index),
        encoding="utf-8",
    )
    FP.write_text(
        "# GENERATED. Matcher model aligns with prometheus/snmp_exporter#1468\n"
        "# modules_hot / modules_cold / modules_topology = staggered scrape tiers.\n"
        "# Legacy `modules` remains the full chain for older tools.\n"
        + dump_yaml(build_fingerprinters(index, hot_leaves=leaves)),
        encoding="utf-8",
    )
    TIERS.write_text(
        "# GENERATED module → scrape tier (hot | cold | topology).\n"
        + dump_yaml(build_module_tiers_doc(modules)),
        encoding="utf-8",
    )
    concat_snmp_network(auths, modules, CONCAT)
    print(f"wrote {FP}")
    print(f"wrote {INDEX}")
    print(f"wrote {TIERS}")
    print(f"concat {CONCAT} modules={len(modules)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
