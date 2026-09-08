#!/usr/bin/env python3
"""Split the Nokia SR Linux pack onto hot / cold / topology without a full convert.

  nokia_srlinux          — identity + CPU/mem (hot)
  nokia_srlinux_sensors  — chassis / temp / fan / PSU (cold)
  nokia_srlinux_bgp      — BGP neighbor tables (topology)

Rewrites those module files, concatenates snmp-network.yml, and patches
fingerprinters.yml / sysobjectid-index.yaml / module-tiers.yaml in place
(no YAML round-trip of the 35k-line fingerprinter file).
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from convert import (
    build_module_tiers_doc,
    concat_snmp_network,
    dump_yaml,
    split_nokia_srlinux_family,
    write_module_file,
)

REPO = Path(__file__).resolve().parents[2]
MODULES = REPO / "snmp" / "modules"
CONCAT = REPO / "snmp" / "snmp-network.yml"
FP = REPO / "snmp" / "fingerprinters.yml"
INDEX = REPO / "snmp" / "sysobjectid-index.yaml"
TIERS = REPO / "snmp" / "module-tiers.yaml"

NOKIA_FP_OLD = """      modules_hot: &id202
      - if_mib
      - nokia_srlinux
      - nokia_srlinux_hot
      modules_cold: &id203
      - if_mib_meta
      - ip_addr
      modules_topology: &id204 []"""

NOKIA_FP_NEW = """      modules_hot: &id202
      - if_mib
      - nokia_srlinux
      modules_cold: &id203
      - if_mib_meta
      - ip_addr
      - nokia_srlinux_sensors
      modules_topology: &id204
      - nokia_srlinux_bgp"""

NOKIA_INDEX_OLD = """    module_chain_hot:
    - if_mib
    - nokia_srlinux
    - nokia_srlinux_hot
    module_chain_cold:
    - if_mib_meta
    - ip_addr
    module_chain_topology: []"""

NOKIA_INDEX_NEW = """    module_chain_hot:
    - if_mib
    - nokia_srlinux
    module_chain_cold:
    - if_mib_meta
    - ip_addr
    - nokia_srlinux_sensors
    module_chain_topology:
    - nokia_srlinux_bgp"""


def load_modules(modules_dir: Path) -> dict:
    modules: dict = {}
    for path in sorted(modules_dir.rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, mod in (data.get("modules") or {}).items():
            modules[name] = mod
    return modules


def merge_nokia_family(modules: dict) -> dict:
    metrics: list = []
    walks: list = []
    gets: list = []
    for name in ("nokia_srlinux", "nokia_srlinux_sensors", "nokia_srlinux_bgp"):
        mod = modules.get(name) or {}
        metrics.extend(list(mod.get("metrics") or []))
        for w in mod.get("walk") or []:
            if w not in walks:
                walks.append(w)
        for g in mod.get("get") or []:
            if g not in gets:
                gets.append(g)
    if not metrics:
        raise SystemExit("no Nokia metrics found under snmp/modules/nokia/")
    return {"metrics": metrics, "walk": walks, "get": gets}


def patch_text(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text and old not in text:
        print(f"already patched {path.name}")
        return
    if old not in text:
        raise SystemExit(f"{path}: expected Nokia block not found")
    path.write_text(text.replace(old, new), encoding="utf-8")
    print(f"patched {path}")


def main() -> int:
    modules = load_modules(MODULES)
    parts = split_nokia_srlinux_family(merge_nokia_family(modules))
    for name, part in parts.items():
        dest = write_module_file(MODULES, "nokia", name, part)
        print(f"wrote {dest} ({len(part.get('metrics') or [])} metrics)")
        modules[name] = part

    concat = yaml.safe_load(CONCAT.read_text(encoding="utf-8")) or {}
    auths = concat.get("auths") or {}
    concat_snmp_network(auths, modules, CONCAT)
    print(f"concat {CONCAT} modules={len(modules)}")

    patch_text(FP, NOKIA_FP_OLD, NOKIA_FP_NEW)
    patch_text(INDEX, NOKIA_INDEX_OLD, NOKIA_INDEX_NEW)

    TIERS.write_text(
        "# GENERATED module → scrape tier (hot | cold | topology).\n"
        + dump_yaml(build_module_tiers_doc(modules)),
        encoding="utf-8",
    )
    print(f"wrote {TIERS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
