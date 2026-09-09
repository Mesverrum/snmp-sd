#!/usr/bin/env python3
"""Rewrite existing snmp/modules + concat for snmp_exporter 0.29 type panics."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import yaml

from convert import concat_snmp_network, sanitize_module, write_module_file

REPO = Path(__file__).resolve().parents[2]
MODULES = REPO / "snmp" / "modules"
CONCAT = REPO / "snmp" / "snmp-network.yml"
AUTHS = REPO / "snmp" / "auths.yml"
LAB = Path(r"C:\Users\mesve\projects\network-o11y-demo\local")


def main() -> int:
    data = yaml.safe_load(AUTHS.read_text(encoding="utf-8")) or {}
    auths = data.get("auths") or {}
    modules: dict = {}
    for path in sorted(MODULES.rglob("*.yml")):
        parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, mod in (parsed.get("modules") or {}).items():
            if not isinstance(mod, dict):
                continue
            vendor = path.parent.name
            sanitized = sanitize_module(mod)
            modules[name] = sanitized
            write_module_file(MODULES, vendor, name, sanitized)
            print(f"wrote {vendor}/{name}")
    concat_snmp_network(auths, modules, CONCAT)
    print(f"concat {CONCAT} modules={len(modules)}")
    # Optional sibling lab overlay (not part of the public product path).
    if (LAB / "fixtures" / "alloy-snmp").is_dir():
        shutil.copy2(CONCAT, LAB / "fixtures" / "alloy-snmp" / "snmp-network.yml")
        shutil.copy2(CONCAT, LAB / "alloy" / "snmp-network.yml")
        print("copied concat to sibling lab overlay")
    return 0


if __name__ == "__main__":
    sys.exit(main())
