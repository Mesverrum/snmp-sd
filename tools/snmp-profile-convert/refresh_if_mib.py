#!/usr/bin/env python3
"""Regenerate IF-MIB split + IP inventory and rebuild snmp-network.yml.

Concat is rebuilt from snmp/modules/** (not spliced) so YAML anchors stay unique.
Does not re-convert the rest of the library.

Fingerprinters / sysobjectid-index cold lists are patched in place (no YAML
dump) so matcher aliases survive.

  python3 refresh_if_mib.py --profiles /path/to/kentik_snmp
  python3 refresh_if_mib.py   # MAC + ip_addr only, using existing split modules
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from convert import (
    DEFAULT_AUTHS,
    DEFAULT_OID_SYNTAX,
    DEFAULT_TABLE_INDEXES_FILE,
    apply_if_admin_up_filter,
    build_module_tiers_doc,
    concat_snmp_network,
    convert_profile,
    dump_yaml,
    inject_ip_addr_into_cold_lists,
    ip_addr_module,
    load_oid_syntax,
    load_table_indexes,
    merge_table_indexes,
    split_if_mib_family,
    write_module_file,
    _ensure_if_mac_lookup,
)
import convert as convert_mod

REPO = Path(__file__).resolve().parents[2]
DEFAULT_MODULES = REPO / "snmp" / "modules"
DEFAULT_CONCAT = REPO / "snmp" / "snmp-network.yml"
DEFAULT_AUTHS_FILE = REPO / "snmp" / "auths.yml"
DEFAULT_FP = REPO / "snmp" / "fingerprinters.yml"
DEFAULT_INDEX = REPO / "snmp" / "sysobjectid-index.yaml"
DEFAULT_TIERS = REPO / "snmp" / "module-tiers.yaml"


def load_split_modules(modules_dir: Path) -> dict:
    modules: dict = {}
    for path in sorted(modules_dir.rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, mod in (data.get("modules") or {}).items():
            modules[name] = mod
    return modules


def load_auths(path: Path) -> dict:
    if not path.is_file():
        return DEFAULT_AUTHS
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("auths") or DEFAULT_AUTHS


def patch_existing_meta(modules_dir: Path, name: str) -> None:
    path = modules_dir / "_general" / f"{name}.yml"
    if not path.is_file():
        print(f"SKIP missing {path}", file=sys.stderr)
        return
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    mods = data.get("modules") or {}
    module = mods.get(name)
    if not isinstance(module, dict):
        print(f"SKIP no module {name} in {path}", file=sys.stderr)
        return
    metrics = [_ensure_if_mac_lookup(m) for m in (module.get("metrics") or [])]
    patched = apply_if_admin_up_filter({"metrics": metrics})
    dest = write_module_file(modules_dir, "_general", name, patched)
    print(f"patched MAC on {dest}")


def patch_text_file(path: Path) -> None:
    if not path.is_file():
        print(f"SKIP missing {path}", file=sys.stderr)
        return
    original = path.read_text(encoding="utf-8")
    updated = inject_ip_addr_into_cold_lists(original)
    if updated == original:
        print(f"already has ip_addr cold lists: {path}")
        return
    path.write_text(updated, encoding="utf-8")
    print(f"injected ip_addr into {path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profiles", type=Path, default=None)
    ap.add_argument("--modules-dir", type=Path, default=DEFAULT_MODULES)
    ap.add_argument("--concat", type=Path, default=DEFAULT_CONCAT)
    ap.add_argument("--auths", type=Path, default=DEFAULT_AUTHS_FILE)
    ap.add_argument("--fingerprinters", type=Path, default=DEFAULT_FP)
    ap.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    ap.add_argument("--tiers", type=Path, default=DEFAULT_TIERS)
    args = ap.parse_args()

    convert_mod.OID_SYNTAX = load_oid_syntax(DEFAULT_OID_SYNTAX)
    convert_mod.LOADED_TABLE_INDEXES = load_table_indexes(DEFAULT_TABLE_INDEXES_FILE)
    convert_mod.MERGED_TABLE_INDEXES = merge_table_indexes()

    converted = False
    if args.profiles:
        for fname in ("if-mib.yml", "if32-mib.yml"):
            path = args.profiles / "_general" / fname
            if not path.is_file():
                print(f"SKIP missing {path}", file=sys.stderr)
                continue
            name, vendor, module, _idx, _mp = convert_profile(path, args.profiles)
            module = apply_if_admin_up_filter(module)
            parts = split_if_mib_family(name, module)
            for part_name, part_mod in parts.items():
                dest = write_module_file(args.modules_dir, vendor, part_name, part_mod)
                print(f"wrote {dest}")
            converted = True
    if not converted:
        patch_existing_meta(args.modules_dir, "if_mib_meta")
        patch_existing_meta(args.modules_dir, "if32_mib_meta")

    dest = write_module_file(args.modules_dir, "_general", "ip_addr", ip_addr_module())
    print(f"wrote {dest}")

    patch_text_file(args.fingerprinters)
    patch_text_file(args.index)

    modules = load_split_modules(args.modules_dir)
    concat_snmp_network(load_auths(args.auths), modules, args.concat)
    print(f"rebuilt {args.concat} ({len(modules)} modules)")

    if args.tiers.parent.is_dir():
        header = "# GENERATED module → scrape tier (hot | cold | topology).\n"
        args.tiers.write_text(header + dump_yaml(build_module_tiers_doc(modules)), encoding="utf-8")
        print(f"rebuilt {args.tiers}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
