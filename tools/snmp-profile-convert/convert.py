#!/usr/bin/env python3
"""One-shot ingest: kentik snmp-profiles YAML → snmp_exporter runtime modules.

The kentik tree is an OID cookbook (numeric OIDs, no MIB compiler). Convert
writes ``snmp/modules/`` which **is** the snmp_exporter library after that. Do not
keep a dual ktranslate name contract — edit modules in place; re-run convert
only when ingesting a new vendor pack.

Layout:
  snmp/auths.yml
  snmp/modules/<vendor>/<module>.yml
  snmp/snmp-network.yml                # concat for a single snmp_exporter --config.file
  snmp/sysobjectid-index.yaml
  snmp/fingerprinters.yml

``extends`` becomes a comma-separated ``module=`` list (snmp_exporter has no
DAG). Fingerprinter names must be a subset of converted ``modules:`` keys —
never invent sidecars such as ``nokia_srlinux_hot`` unless that file was written.
SNMPv2 identity is inlined as ``snmp_device_info`` on each fingerprint
module (``device_base`` for unknown sysObjectID). Ancestor 1:1 scalars fold
onto that metric. Point snmp_exporter ``--config.file`` at this concat; do not
merge it with the exporter image's embedded snmp.yml.

Symbols → metrics; ``metric_tags`` → lookups. Inventory enums → EnumAsInfo;
status enums → gauge + enum_values. Never EnumAsStateSet.

Names are curated ``snmp_<stem>``. Profile ``tag: CPU`` / ``MemoryUsed`` / …
are used as the stem when present; otherwise the MIB object name. Unix load
averages (UCD ``laLoadInt*``, UniFi ``loadValue``) emit ``snmp_CPULoad``,
not ``snmp_CPU``. HOST-RESOURCES ``hrProcessorLoad*`` is utilization.

Apache-2.0 profiles: see snmp/NOTICE (kentik/snmp-profiles).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise SystemExit("PyYAML required: pip install pyyaml") from exc

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILES = ROOT / "snmp" / "profiles"
DEFAULT_MODULES_DIR = ROOT / "snmp" / "modules"
DEFAULT_AUTHS_OUT = ROOT / "snmp" / "auths.yml"
DEFAULT_SNMP_OUT = ROOT / "snmp" / "snmp-network.yml"
DEFAULT_INDEX_OUT = ROOT / "snmp" / "sysobjectid-index.yaml"
DEFAULT_FP_OUT = ROOT / "snmp" / "fingerprinters.yml"
DEFAULT_TIERS_OUT = ROOT / "snmp" / "module-tiers.yaml"
DEFAULT_OID_SYNTAX = ROOT / "snmp" / "oid-syntax.yaml"
DEFAULT_TABLE_INDEXES_FILE = ROOT / "snmp" / "table-indexes.yaml"

SKIP_DIR_NAMES = {"_template", "_templates", ".git"}
SKIP_NAME_PREFIXES = ("_",)
SKIP_NAME_SUBSTRINGS = ("trap", "syslog")
SKIP_PROFILE_FILES = frozenset({"system-mib.yml", "system_mib.yml"})

# Scrape tiers:
#   hot      — minimum useful ~60s: IF-MIB octets/oper/ifHighSpeed, identity,
#              uptime, CPU / CPULoad, RAM (+ hrStorage when RAM/disk share a
#              table), and the device's core service counts when they are
#              scalars / small tables (firewall sessions, WLC client totals)
#   cold     — if_mib_meta + ip_addr + hardware sensors + everything else
#   topology — opt-in neighbor / control-plane walks (LLDP, CDP, BGP, OSPF, ISIS)
TOPOLOGY_MODULES = frozenset({"lldp_mib", "bgp4_mib", "ospf_mib"})
# Module-name matcher (lowercase file stems).
TOPOLOGY_NAME_RE = re.compile(r"(lldp|cdp|bgp|ospf|isis)", re.I)
# Metric-name matcher: camelCase / acronym tokens only.
# Do not ignore-case the whole string — ``sonicDpi`` contains ``cdp``.
TOPOLOGY_METRIC_RE = re.compile(
    r"(lldp|LLDP|Lldp|cdp|CDP|Cdp|bgp|BGP|Bgp|ospf|OSPF|Ospf|isis|ISIS|Isis)"
)
HOT_METRIC_NAMES = frozenset(
    {
        "snmp_Uptime",
        "snmp_device_info",
        "snmp_CPU",
        "snmp_CPULoad",
        "snmp_MemoryUsed",
        "snmp_MemoryFree",
        "snmp_MemoryTotal",
    }
)
# Backward-compatible alias used by the Nokia tests / older callers.
NOKIA_HOT_METRIC_NAMES = HOT_METRIC_NAMES
HOT_IF_MODULES = frozenset({"if_mib", "if32_mib"})
# Cheap SNMPv2-MIB GETs (uptime + identity). Not IF-MIB alias/descr tables.
HOT_SYSTEM_MODULES = frozenset({"device_base"})
# Vendor chassis / vital-stat modules after a pack split (not the full MIB dump).
# Expanded at convert-time with vitals-only leaves (see hot_leaf_names).
HOT_VENDOR_MODULES = frozenset({"nokia_srlinux"})
VENDOR_COLD_SIDECARS = ("_sensors", "_ext")
VENDOR_TOPO_SIDECARS = ("_topo", "_bgp")
VENDOR_SIDECAR_SUFFIXES = VENDOR_COLD_SIDECARS + VENDOR_TOPO_SIDECARS
# Sensor / environment — cold even when the name mentions CPU (cpuTemp).
# Keep Temp/Fan camelCase so ``hrSystemProcesses`` does not match ``temP``.
SENSOR_METRIC_RE = re.compile(
    r"(Temp(erature)?|Fan(Speed|Rpm|RPM|Status)?|Psu|PSU|"
    r"(?i:powersupply|power.?supply|humidity)|"
    r"entPhySensor|entSensor|SensorValue|tmnxHw|EnvMon)"
)
HOT_VITAL_RE = re.compile(
    r"(?i)("
    r"cpu(load|util|usage|busy|idle|user|system|nice|wait|raw)?"
    r"|hrprocessor"
    r"|laload"
    r"|cpmcputotal"
    r"|processor(usage|util|sysusage)"
    r"|hrsystemuptime|(?<![a-z])uptime$"
    r"|memory(used|free|total|util|avail)"
    r"|mem(total|avail|used|free|real|shared|buffer|cached|swap|usage|capacity)"
    r"|lowmem"
    r"|ram(used|free|total|util)"
    r"|hrstorage"
    r")"
)
# Core service of the box — scalars / small tables only. Wide flow / NAT /
# per-tunnel / per-policy walks stay cold (see _looks_wide_table).
HOT_SERVICE_RE = re.compile(
    r"(?i)("
    r"sessions?(utilization|active|max|count|rate)"
    r"|(?<![a-z])sessions$"
    r"|firewallSessions"
    r"|panSession"
    r"|crasNum(Sessions|Users|DeclinedSessions|SetupFailInsufResources)"
    r"|crasMax(Sessions|Users)"
    r"|cfwConnectionStat"
    r"|ses(count|rate|6count|6rate)"
    r"|vdentses"
    r"|cur(clnt|srvr)?(ent)?(connections|conns)"
    r"|current(connections|sessions|conns)"
    r"|curr(ent)?connections"
    r"|conn(ection)?s?(count|stat|cur|current|active)"
    r"|conncache"
    r"|num(sessions|connections)"
    r"|crasNumUsers"
    r"|max(sessions|users|connections|conncache)"
    r"|concurrent(users|sessions)"
    r"|active(sessions|connections|tunnels)"
    r"|globalactivetunnels"
    r"|establishedconnections"
    r"|optimizedconnections"
    r"|sslcursessions"
    r"|sslsessionspersec"
    r"|activeWirelessClients"
    r"|devClientCount"
    r"|vapNumStations"
    r"|loadNumOfClients"
    r"|numberofmobilestations"
    r"|totalnumstationsassociated"
    r"|wlsxswitchtotalnumstationsassociated"
    r")"
)
WIDE_TABLE_RE = re.compile(
    r"(?i)("
    r"natsession"
    r"|session(src|dst|addr|port)"
    r"|fwpol"
    r"|(cike|cipsec|ike|ipsec)tun"
    r"|cikepeer"
    r"|createdconnections|destroyedconnections|reassignedconnections"
    r"|cacheclient"
    r")"
)
FLAG_METRIC_RE = re.compile(
    r"(?i)("
    r"hrstorage|dsk(table|percent|error)|disk|storage"
    r"|session|connection|concurrent|conncount"
    r"|client|station|associat|wireless|radio"
    r"|tunnel|vpn|sdwan|overlay"
    r"|queue|qos|wred|policy.?map"
    r"|license|stack|hastat|failover"
    r"|ifreset|cieif"
    r")"
)
COLD_IF_META = frozenset({"if_mib_meta", "if32_mib_meta", "ip_addr"})
IF_MIB_HOT_METRIC_NAMES = frozenset(
    {
        "snmp_ifHCInOctets",
        "snmp_ifHCOutOctets",
        "snmp_ifOperStatus",
        "snmp_ifHighSpeed",
    }
)
# ifHighSpeed is a Gauge32 (Mbps). Kentik ships it as metric_tag if_Speed; we
# promote it to a hot gauge so utilization can divide by a number, not a label.
IF_HIGHSPEED_OID = "1.3.6.1.2.1.31.1.1.1.15"
IF_HIGHSPEED_METRIC = "snmp_ifHighSpeed"
IF_PHYSADDRESS_OID = "1.3.6.1.2.1.2.2.1.6"
IF_NAME_OID = "1.3.6.1.2.1.31.1.1.1.1"
SNMP_METRIC_PREFIX = "snmp_"
VITAL_TAGS = frozenset(
    {
        "CPU",
        "MemoryUsed",
        "MemoryFree",
        "MemoryTotal",
        "Temperature",
        "Uptime",
    }
)
# Curated stem for Unix-style load averages that kentik tagged CPU (NR dashboards).
# Not a VITAL_TAG — profiles keep tag: CPU; we remap so scrapes do not mix them.
CPU_LOAD_AVG_STEM = "CPULoad"
# UCD-SNMP-MIB laLoadInt (float load × 100). Column OID; instances are .1/.2/.3.
UCD_LALOADINT_OID = "1.3.6.1.4.1.2021.10.1.5"
# FROGFOOT-RESOURCES-MIB loadValue (UniFi loadTable; per-mil, not % busy).
FROGFOOT_LOADVALUE_OID = "1.3.6.1.4.1.10002.1.1.1.4.2.1.3"
LA_LOADINT_NAME_RE = re.compile(r"(?i)^laLoadInt")
# HOST-RESOURCES-MIB hrProcessorLoad: % of time the processor was not idle.
HR_PROCESSOR_LOAD_OID = "1.3.6.1.2.1.25.3.3.1.2"
HR_PROCESSOR_LOAD_NAME_RE = re.compile(r"(?i)^hrProcessorLoad")
# Hot path: keep ifName only for legends — descr/type/alias are cold.
# ifHighSpeed is a hot gauge (not a lookup).
IF_MIB_HOT_LOOKUP_LABELS = frozenset({"if_interface_name"})

# Inventory-ish enums → EnumAsInfo (stock if_mib: ifType).
INVENTORY_ENUM_HINT = re.compile(
    r"(type|model|class|product|color|vendor|family|protocol|encap|"
    r"platform|entity)",
    re.I,
)
# Changing status enums → numeric gauge (stock if_mib: ifOperStatus / ifAdminStatus).
STATUS_ENUM_HINT = re.compile(
    r"(status|state|oper|admin|health|alarm|avail|enable|mode|present|"
    r"conn|fail|error|severity|reason|unreg)",
    re.I,
)

# Known table INDEX clauses (numeric OIDs → snmp_exporter index defs).
# Fallback for unknown tables is a single gauge index named `index`.
#
# Prefer snmp/table-indexes.yaml (public OID INDEX/AUGMENTS lookup). This
# builtin map is a leftover for convert-without-lookup. Live-walk exceptions
# that disagree with the MIB go in INDEX_OVERRIDES (last writer).
#
# Conversion rules (kentik snmp-profiles → snmp_exporter):
# 1. Metric OID must be table.1.column (kentik symbols already include the
#    implicit Entry `.1`; do not strip it).
# 2. snmp_exporter indexes must match the FULL MIB INDEX — incomplete indexes
#    collapse rows onto the same labels and fail the scrape with
#    "collected before with the same name and label values".
# 3. ktranslate can tolerate loose indexing; snmp_exporter cannot.
TABLE_INDEXES: dict[str, list[dict[str, Any]]] = {
    # TIMETRA-CHASSIS-MIB
    "1.3.6.1.4.1.6527.3.1.2.2.1.8": [
        {"labelname": "tmnxChassisIndex", "type": "gauge"},
        {"labelname": "tmnxHwIndex", "type": "gauge"},
    ],
    # tmnxPhysChassisFanEntry INDEX:
    #   { tmnxPhysChassisClass, tmnxPhysChassisNum, tmnxPhysChassisFanIndex }
    "1.3.6.1.4.1.6527.3.1.2.2.1.24.1": [
        {"labelname": "tmnxPhysChassisClass", "type": "gauge"},
        {"labelname": "tmnxPhysChassisNum", "type": "gauge"},
        {"labelname": "tmnxPhysChassisFanIndex", "type": "gauge"},
    ],
    # tmnxPhysChassisPMEntry: on SR Linux the instance after column OID is a
    # single packed sub-id (e.g. …1.7.83886081), not the 3-part INDEX form.
    "1.3.6.1.4.1.6527.3.1.2.2.1.24.9": [
        {"labelname": "tmnxPhysChassisPMIndex", "type": "gauge"},
    ],
    # TIMETRA-BGP-MIB
    "1.3.6.1.4.1.6527.3.1.2.14.4.7": [
        {"labelname": "vRtrID", "type": "gauge"},
        {"labelname": "tBgpPeerNgAddressType", "type": "InetAddressType"},
        {"labelname": "tBgpPeerNgAddress", "type": "InetAddress"},
    ],
    "1.3.6.1.4.1.6527.3.1.2.14.4.8": [
        {"labelname": "vRtrID", "type": "gauge"},
        {"labelname": "tBgpPeerNgAddressType", "type": "InetAddressType"},
        {"labelname": "tBgpPeerNgAddress", "type": "InetAddress"},
    ],
    # LENOVO-ENV-MIB
    "1.3.6.1.4.1.19046.2.3.11.1.1": [
        {"labelname": "lenovoEnvMibPowerSupplyIndex", "type": "gauge"},
    ],
    "1.3.6.1.4.1.19046.2.3.11.1.2": [
        {"labelname": "lenovoEnvMibFanIndex", "type": "gauge"},
    ],
    "1.3.6.1.4.1.19046.2.3.11.1.3": [
        {"labelname": "lenovoEnvMibTempSensorIndex", "type": "gauge"},
    ],
    # IF-MIB ifTable / ifXTable (only if converting kentik if-mib as optional module)
    "1.3.6.1.2.1.2.2": [
        {"labelname": "ifIndex", "type": "gauge"},
    ],
    "1.3.6.1.2.1.31.1.1": [
        {"labelname": "ifIndex", "type": "gauge"},
    ],
}

# Live-walk exceptions: instance suffix arity ≠ MIB INDEX (e.g. packed sub-id).
INDEX_OVERRIDES: dict[str, list[dict[str, Any]]] = {
    "1.3.6.1.4.1.6527.3.1.2.2.1.24.9": [
        {"labelname": "tmnxPhysChassisPMIndex", "type": "gauge"},
    ],
}

LOADED_TABLE_INDEXES: dict[str, list[dict[str, Any]]] = {}
MERGED_TABLE_INDEXES: dict[str, list[dict[str, Any]]] = {}
INDEX_STATS: dict[str, int] = {"mib": 0, "override": 0, "builtin": 0, "fallback": 0}

GAUGE_TAG_HINT = re.compile(
    r"(as|index|prefixes|flaps|rpm|percent|temperature|threshold|total|used|free|available)$",
    re.I,
)
# SNMP Counter / Counter64 objects. Typed as gauge, Counter64 PDUs are dropped
# (snmp_unexpected_pdu_type_total) — that is why ifHCInOctets never appeared.
COUNTER_NAME_HINT = re.compile(
    r"(octets|pkts|packets|discards|errors|collisions|unknownprotos|"
    r"ucastpkts|nucastpkts|inbroadcastpkts|outbroadcastpkts|"
    r"inmulticastpkts|outmulticastpkts)$",
    re.I,
)

DEFAULT_AUTHS: dict[str, Any] = {
    "public_v2": {
        "community": "public",
        "security_level": "noAuthNoPriv",
        "auth_protocol": "MD5",
        "priv_protocol": "DES",
        "version": 2,
    }
}


def module_name_from_path(path: Path, profiles_root: Path) -> tuple[str, str]:
    """Return (module_name, vendor_dir)."""
    try:
        rel = path.relative_to(profiles_root)
    except ValueError:
        rel = Path(path.name)
    parts = rel.parts
    vendor = parts[0] if len(parts) > 1 else "_local"
    stem = path.stem.replace("-", "_").replace(".", "_")
    return stem, vendor


def strip_instance(oid: str) -> tuple[str, str]:
    """Return (metric_oid, get_or_walk_oid). Scalars keep .0 on the get list."""
    oid = oid.strip().lstrip(".")
    if oid.endswith(".0") and oid.count(".") >= 6:
        return oid[:-2], oid
    return oid, oid


# SNMPv2-MIB system group. Kentik system-mib.yml lists these as metric_tags
# (ktranslate device tags) and hard-codes sysUpTime — converter must emit GETs.
SNMPV2_SYSTEM_SCALARS: list[tuple[str, str, str, str]] = [
    ("1.3.6.1.2.1.1.1.0", "sysDescr", "SysDescr", "DisplayString"),
    ("1.3.6.1.2.1.1.2.0", "sysObjectID", "SysObjectID", "DisplayString"),
    ("1.3.6.1.2.1.1.3.0", "sysUpTime", "Uptime", "gauge"),
    ("1.3.6.1.2.1.1.4.0", "sysContact", "SysContact", "DisplayString"),
    ("1.3.6.1.2.1.1.5.0", "sysName", "SysName", "DisplayString"),
    ("1.3.6.1.2.1.1.6.0", "sysLocation", "SysLocation", "DisplayString"),
]
SNMPV2_INFO_OID_TO_LABEL = {
    "1.3.6.1.2.1.1.1": "sysDescr",
    "1.3.6.1.2.1.1.2": "sysObjectID",
    "1.3.6.1.2.1.1.4": "sysContact",
    "1.3.6.1.2.1.1.5": "sysName",
    "1.3.6.1.2.1.1.6": "sysLocation",
}
DEVICE_INFO_KEEP_RE = re.compile(
    r"(serial|firmware|version|model|revision|product|manufacturer|"
    r"sysdescr|sysname|syscontact|syslocation|sysobjectid|software|"
    r"bios|rom|image|hostname|chassis|platform|part.?num|asset|"
    r"build.?number|ident|hw.?ver|sw.?ver|os.?ver)",
    re.I,
)
DEVICE_INFO_DROP_RE = re.compile(
    r"(amp|watt|volt|temp|humid|count|cpu|power|percent|enabled|status|"
    r"scale|phase|breaker|outlet|ip.?addr|netmask|gateway|dns|mac|"
    r"bytes|ops$|rating$)",
    re.I,
)
FIRMWARE_LABEL_RE = re.compile(
    r"(firmware|(software|sw)(rev|ver|version)|sys(sw)?version|"
    r"productversion|niosversion|osrelease)$",
    re.I,
)
SERIAL_LABEL_RE = re.compile(r"serial", re.I)
MODEL_LABEL_RE = re.compile(
    r"^(model|model_number|modelname|product_model|productmodel|product_name)$",
    re.I,
)


def _sys_native_from_kentik_tag(name: str) -> str:
    n = (name or "").strip()
    if n.startswith("Sys"):
        return "sys" + n[3:]
    return n or "sysDescr"


def _prom_label(raw: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", (raw or "").strip())
    s = re.sub(r"_+", "_", s).strip("_")
    if s and s[0].isdigit():
        s = "l_" + s
    return s or "info"


def device_info_label(tag: str, name: str, oid: str = "") -> str | None:
    """Return snmp_device_info labelname, or None if this is not device identity.

    SNMPv2-MIB scalars map to the template names (caller skips duplicates).
    Kentik serial/firmware/model tags collapse to those three names when obvious.
    """
    metric_oid, _ = strip_instance(oid) if oid else ("", "")
    if metric_oid in SNMPV2_INFO_OID_TO_LABEL:
        return SNMPV2_INFO_OID_TO_LABEL[metric_oid]
    if metric_oid == "1.3.6.1.2.1.1.3":
        return None  # sysUpTime is a gauge
    blob = f"{tag} {name}".strip()
    if not blob:
        return None
    if DEVICE_INFO_DROP_RE.search(blob) and not SERIAL_LABEL_RE.search(blob):
        return None
    if not DEVICE_INFO_KEEP_RE.search(blob):
        return None
    raw = (tag or name or "").strip()
    if SERIAL_LABEL_RE.search(raw) and not re.search(r"(ops|count|bytes)", raw, re.I):
        return "serial"
    if FIRMWARE_LABEL_RE.search(raw):
        return "firmware"
    if MODEL_LABEL_RE.search(raw):
        return "model"
    return _prom_label(raw)


def iter_scalar_symbols(block: dict[str, Any]) -> list[dict[str, Any]]:
    """Kentik scalars: `symbol:` or `symbols:` with no table (Palo session GETs)."""
    if block.get("table"):
        return []
    if "symbol" in block:
        sym = block.get("symbol") or {}
        return [sym] if isinstance(sym, dict) else []
    out: list[dict[str, Any]] = []
    for sym in block.get("symbols") or []:
        if isinstance(sym, dict):
            out.append(sym)
    return out


def identity_lookup_from_tag(tag_ent: dict[str, Any]) -> dict[str, Any] | None:
    col = tag_ent.get("column") or {}
    raw_oid = str(col.get("OID") or tag_ent.get("OID") or "").strip()
    col_name = str(col.get("name") or "").strip()
    tag = str(tag_ent.get("tag") or col_name).strip()
    if not raw_oid:
        return None
    label = device_info_label(tag, col_name or tag, raw_oid)
    if not label:
        return None
    metric_oid, _ = strip_instance(raw_oid)
    if metric_oid in SNMPV2_INFO_OID_TO_LABEL:
        return None  # already on the SNMPv2 template
    return {
        "oid": metric_oid,
        "get": strip_instance(raw_oid)[1],
        "labelname": label,
        "type": "DisplayString",
        "native": col_name or tag,
        "tag": tag,
    }


def identity_lookup_from_symbol(sym: dict[str, Any]) -> dict[str, Any] | None:
    raw_oid = str(sym.get("OID") or "").strip()
    name = str(sym.get("name") or "").strip()
    tag = str(sym.get("tag") or "").strip()
    if not raw_oid or not name:
        return None
    if str(sym.get("tag") or "") in VITAL_TAGS:
        return None
    label = device_info_label(tag, name, raw_oid)
    if not label:
        return None
    metric_oid, get_oid = strip_instance(raw_oid)
    if metric_oid in SNMPV2_INFO_OID_TO_LABEL:
        return None
    return {
        "oid": metric_oid,
        "get": get_oid,
        "labelname": label,
        "type": "DisplayString",
        "native": name,
        "tag": tag,
    }


def snmpv2_device_info_metric(extra_lookups: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    lookups = [
        {
            "labels": ["snmp_scalar_index"],
            "labelname": "sysDescr",
            "oid": "1.3.6.1.2.1.1.1",
            "type": "DisplayString",
        },
        {
            "labels": ["snmp_scalar_index"],
            "labelname": "sysObjectID",
            "oid": "1.3.6.1.2.1.1.2",
            "type": "DisplayString",
        },
        {
            "labels": ["snmp_scalar_index"],
            "labelname": "sysContact",
            "oid": "1.3.6.1.2.1.1.4",
            "type": "DisplayString",
        },
        {
            "labels": ["snmp_scalar_index"],
            "labelname": "sysLocation",
            "oid": "1.3.6.1.2.1.1.6",
            "type": "DisplayString",
        },
    ]
    seen = {str(lu["labelname"]) for lu in lookups}
    seen_oids = {str(lu["oid"]) for lu in lookups}
    for lu in extra_lookups or []:
        label = str(lu.get("labelname") or "")
        oid = str(lu.get("oid") or "").strip().lstrip(".")
        if not label or not oid or label in seen or oid in seen_oids:
            continue
        seen.add(label)
        seen_oids.add(oid)
        lookups.append(
            {
                "labels": ["snmp_scalar_index"],
                "labelname": label,
                "oid": oid,
                "type": str(lu.get("type") or "DisplayString"),
            }
        )
    return {
        "name": "snmp_device_info",
        "oid": "1.3.6.1.2.1.1.5",
        "type": "DisplayString",
        "help": (
            "Device identity (info metric, value 1). sysName is the DisplayString; "
            "SNMPv2 + vendor scalars are lookups. Dummy snmp_scalar_index (.0) is "
            "required: snmp_exporter skips lookups with empty labels. Relabel "
            "snmp_device_info → sysName and drop snmp_scalar_index if you want a name label."
        ),
        "indexes": [{"labelname": "snmp_scalar_index", "type": "gauge"}],
        "lookups": lookups,
    }


def snmp_uptime_metric() -> dict[str, Any]:
    return {
        "name": "snmp_Uptime",
        "oid": "1.3.6.1.2.1.1.3",
        "type": "gauge",
        "help": "sysUpTime (SNMPv2-MIB) TimeTicks",
    }


def inject_device_identity(
    module: dict[str, Any], extra_lookups: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Inline SNMPv2 identity + folded vendor scalars onto one snmp_device_info."""
    module = dict(module)
    gets = list(module.get("get") or [])
    metrics = list(module.get("metrics") or [])
    for get_oid, _native, _tag, _typ in SNMPV2_SYSTEM_SCALARS:
        if get_oid not in gets:
            gets.append(get_oid)
    for lu in extra_lookups or []:
        get_oid = str(lu.get("get") or "")
        if get_oid and get_oid not in gets:
            gets.append(get_oid)
    metrics = [m for m in metrics if str(m.get("name") or "") not in {"snmp_device_info", "snmp_Uptime"}]
    if not any(str(m.get("oid") or "").strip().lstrip(".") == "1.3.6.1.2.1.1.3" for m in metrics):
        metrics.insert(0, snmp_uptime_metric())
    metrics.insert(1, snmpv2_device_info_metric(extra_lookups))
    module["get"] = gets
    module["metrics"] = metrics
    return module


def device_base_module() -> dict[str, Any]:
    return inject_device_identity({"metrics": []}, [])


def ip_addr_module() -> dict[str, Any]:
    """IP-MIB address tables for dashboard joins on ifIndex.

    snmp_exporter lookups are 1:1 on the metric INDEX. ipAddrTable /
    ipAddressTable are indexed by address, so IPs cannot be labels on
    ifHCInOctets. These gauges carry ifIndex (and ifName) as labels so
    dashboards can ``on(device_name, ifIndex) group_left(ipAdEntAddr)``.
    """
    def if_name_lookup() -> dict[str, Any]:
        return {
            "labels": ["ifIndex"],
            "labelname": "if_interface_name",
            "oid": IF_NAME_OID,
            "type": "DisplayString",
        }

    v4_idx = [{"labelname": "ipAdEntAddr", "type": "InetAddressIPv4"}]
    v4_labels = ["ipAdEntAddr"]
    # snmp_exporter 0.29: one combined InetAddress index, not InetAddressType + InetAddress.
    v6_idx = [{"labelname": "ipAddressAddr", "type": "InetAddress"}]
    v6_labels = ["ipAddressAddr"]
    return {
        "walk": [
            "1.3.6.1.2.1.4.20.1.2",
            "1.3.6.1.2.1.4.20.1.3",
            "1.3.6.1.2.1.4.34.1.3",
            "1.3.6.1.2.1.4.34.1.4",
            "1.3.6.1.2.1.4.34.1.6",
            "1.3.6.1.2.1.4.34.1.7",
            IF_NAME_OID,
        ],
        "metrics": [
            {
                "name": "snmp_ipAdEntIfIndex",
                "oid": "1.3.6.1.2.1.4.20.1.2",
                "type": "gauge",
                "help": (
                    "ipAdEntIfIndex (IP-MIB ipAddrTable) — IPv4 address → ifIndex. "
                    "Join IF-MIB on (device_name, ifIndex)."
                ),
                "indexes": v4_idx,
                "lookups": [
                    {
                        "labels": v4_labels,
                        "labelname": "ifIndex",
                        "oid": "1.3.6.1.2.1.4.20.1.2",
                        "type": "gauge",
                    },
                    {
                        "labels": v4_labels,
                        "labelname": "ipAdEntNetMask",
                        "oid": "1.3.6.1.2.1.4.20.1.3",
                        "type": "InetAddressIPv4",
                    },
                    if_name_lookup(),
                ],
            },
            {
                "name": "snmp_ipAddressIfIndex",
                "oid": "1.3.6.1.2.1.4.34.1.3",
                "type": "gauge",
                "help": (
                    "ipAddressIfIndex (IP-MIB ipAddressTable) — IPv4/IPv6 address → ifIndex. "
                    "Join IF-MIB on (device_name, ifIndex)."
                ),
                "indexes": v6_idx,
                "lookups": [
                    {
                        "labels": v6_labels,
                        "labelname": "ifIndex",
                        "oid": "1.3.6.1.2.1.4.34.1.3",
                        "type": "gauge",
                    },
                    # snmp_exporter Lookup has no enum_values field (metrics do).
                    # EnumAsInfo still stringifies the integer; names stay in help text.
                    {
                        "labels": v6_labels,
                        "labelname": "ipAddressType",
                        "oid": "1.3.6.1.2.1.4.34.1.4",
                        "type": "EnumAsInfo",
                    },
                    {
                        "labels": v6_labels,
                        "labelname": "ipAddressOrigin",
                        "oid": "1.3.6.1.2.1.4.34.1.6",
                        "type": "EnumAsInfo",
                    },
                    {
                        "labels": v6_labels,
                        "labelname": "ipAddressStatus",
                        "oid": "1.3.6.1.2.1.4.34.1.7",
                        "type": "EnumAsInfo",
                    },
                    if_name_lookup(),
                ],
            },
        ],
    }


def ip_addr_index_entry() -> dict[str, Any]:
    return {
        "profile": "ip-addr.yml",
        "vendor": "_general",
        "sysobjectids": [],
        "extends": [],
        "identity_lookups": [],
        "notes": (
            "Cold IP-MIB address inventory (ipAddrTable + ipAddressTable) "
            "for dashboard joins on ifIndex. Not kentik ip-mib.yml (stats)."
        ),
    }


def skipped_extends(raw: str) -> bool:
    """Kentik system-mib.yml is folded into snmp_device_info — not a scrape module."""
    base = Path(str(raw)).name
    if base in SKIP_PROFILE_FILES:
        return True
    stem = Path(base).stem.replace("-", "_").replace(".", "_")
    return stem in {"system_mib"}


def skip_identity_inject(name: str) -> bool:
    """IF-MIB / topology / hot splits stay tables-only; identity lives on the fingerprint leaf."""
    n = (name or "").strip()
    if n in HOT_IF_MODULES or n in COLD_IF_META or n in TOPOLOGY_MODULES:
        return True
    if n in {"device_base", "system_mib", "ip_addr"}:
        return True
    if n.endswith("_meta") or n.endswith("_hot") or n.endswith("_identity"):
        return True
    if n.endswith(("_sensors", "_bgp", "_topo", "_ext")):
        return True
    if TOPOLOGY_NAME_RE.search(n):
        return True
    return False


def strip_nested_device_lookups(
    module: dict[str, Any], identity_oids: set[str]
) -> dict[str, Any]:
    """Drop device-level scalar lookups copied onto table metrics (1:N)."""
    if not identity_oids:
        return module
    module = dict(module)
    out: list[dict[str, Any]] = []
    for metric in module.get("metrics") or []:
        m = dict(metric)
        if str(m.get("name") or "") == "snmp_device_info":
            out.append(m)
            continue
        lookups = m.get("lookups") or []
        if not lookups:
            out.append(m)
            continue
        kept: list[dict[str, Any]] = []
        for lu in lookups:
            oid, _ = strip_instance(str(lu.get("oid") or ""))
            if oid in identity_oids:
                continue
            kept.append(lu)
        if kept:
            m["lookups"] = kept
        else:
            m.pop("lookups", None)
        out.append(m)
    module["metrics"] = out
    return module


def fold_device_identity(modules: dict[str, Any], index: dict[str, Any]) -> dict[str, int]:
    """Inline SNMPv2 + ancestor identity scalars onto one snmp_device_info per scrape.

    snmp_exporter has no kentik ``extends`` DAG — a comma-separated module list.
    Parents that both fingerprint (sysobjectids) *and* have children keep tables
    only; identity moves to ``{name}_identity`` so a child scrape is not two info
    metrics.
    """
    meta: dict[str, Any] = index.setdefault("modules", {})
    file_to_mod = {
        m.get("profile"): name
        for name, m in meta.items()
        if m.get("profile")
    }

    def extends_to_mods(filenames: list[str]) -> list[str]:
        out: list[str] = []
        for raw in filenames:
            if skipped_extends(raw):
                continue
            base = Path(str(raw)).name
            mod = file_to_mod.get(base) or file_to_mod.get(str(raw))
            if not mod:
                print(f"WARN: extends {raw!r} has no converted module", file=sys.stderr)
                continue
            out.append(mod)
        return out

    direct: dict[str, list[str]] = {}
    children: dict[str, set[str]] = {}
    for name, m in meta.items():
        deps = extends_to_mods(list(m.get("extends") or []))
        m["extends_modules"] = deps
        direct[name] = deps
        for dep in deps:
            children.setdefault(dep, set()).add(name)

    collect_memo: dict[str, list[dict[str, Any]]] = {}

    def collect(name: str, visiting: set[str] | None = None) -> list[dict[str, Any]]:
        if name in collect_memo:
            return collect_memo[name]
        visiting = visiting or set()
        if name in visiting:
            return []
        visiting.add(name)
        acc: list[dict[str, Any]] = []
        seen: set[str] = set()

        def add(lu: dict[str, Any]) -> None:
            oid = str(lu.get("oid") or "").strip().lstrip(".")
            if not oid or oid in seen:
                return
            seen.add(oid)
            acc.append(lu)

        for lu in (meta.get(name) or {}).get("identity_lookups") or []:
            add(lu)
        for dep in direct.get(name, []):
            for lu in collect(dep, visiting):
                add(lu)
        visiting.discard(name)
        collect_memo[name] = acc
        return acc

    snmpv2_oids = set(SNMPV2_INFO_OID_TO_LABEL)
    for name, module in list(modules.items()):
        extras = collect(name)
        oids = snmpv2_oids | {
            str(lu.get("oid") or "").strip().lstrip(".") for lu in extras
        }
        modules[name] = strip_nested_device_lookups(module, oids)

    modules["device_base"] = device_base_module()
    meta["device_base"] = {
        "profile": "device_base.yml",
        "vendor": "_general",
        "sysobjectids": [],
        "extends": [],
        "identity_lookups": [],
        "notes": "Unknown sysObjectID — SNMPv2 identity only (replaces kentik system-mib.yml)",
    }
    modules["ip_addr"] = ip_addr_module()
    meta["ip_addr"] = ip_addr_index_entry()

    inlined = 0
    sidecars = 0
    for name in list(modules):
        if skip_identity_inject(name):
            continue
        m = meta.get(name) or {}
        has_ids = bool(m.get("sysobjectids"))
        has_kids = bool(children.get(name))
        extras = collect(name)
        if has_ids and has_kids:
            sidecar = f"{name}_identity"
            modules[sidecar] = inject_device_identity({"metrics": []}, extras)
            meta[sidecar] = {
                "profile": f"{sidecar.replace('_', '-')}.yml",
                "vendor": m.get("vendor") or "_general",
                "sysobjectids": [],
                "extends": [],
                "identity_lookups": extras,
                "notes": (
                    f"Identity sidecar for {name} (parent fingerprints and has children; "
                    f"tables stay on {name})"
                ),
            }
            m["identity_sidecar"] = sidecar
            sidecars += 1
        elif has_ids:
            modules[name] = inject_device_identity(modules[name], extras)
            inlined += 1

    return {"inlined": inlined, "sidecars": sidecars}


def _enum_name(name: Any) -> str:
    # PyYAML treats unquoted on/off/yes/no as booleans.
    if name is True:
        return "on"
    if name is False:
        return "off"
    return str(name)


def invert_enum(enum: dict[str, Any] | None) -> dict[int, str] | None:
    if not enum:
        return None
    out: dict[int, str] = {}
    for name, num in enum.items():
        try:
            out[int(num)] = _enum_name(name)
        except (TypeError, ValueError):
            continue
    return out or None


def prefix_metric_name(stem: str) -> str:
    """Curated Prom name: snmp_<stem>. Do not double-prefix."""
    stem = (stem or "").strip()
    if not stem:
        return stem
    if stem.startswith(SNMP_METRIC_PREFIX):
        return stem
    return SNMP_METRIC_PREFIX + stem


def _norm_oid(oid: str) -> str:
    return (oid or "").strip().lstrip(".")


def _oid_under(oid: str, prefix: str) -> bool:
    o = _norm_oid(oid)
    p = _norm_oid(prefix)
    return bool(o) and (o == p or o.startswith(p + "."))


def is_unix_load_average(native: str, oid: str = "") -> bool:
    """True for run-queue / load-average objects — not CPU utilization %.

    ``hrProcessorLoad`` / vendor percent-busy objects stay ``snmp_CPU``.
    """
    if _oid_under(oid, UCD_LALOADINT_OID) or _oid_under(oid, FROGFOOT_LOADVALUE_OID):
        return True
    n = (native or "").strip()
    if LA_LOADINT_NAME_RE.match(n):
        return True
    return n == "loadValue"


def is_hr_processor_utilization(native: str, oid: str = "") -> bool:
    """HOST-RESOURCES hrProcessorLoad — utilization %, despite the name."""
    if _oid_under(oid, HR_PROCESSOR_LOAD_OID):
        return True
    return bool(HR_PROCESSOR_LOAD_NAME_RE.match((native or "").strip()))


def vital_stem(native: str, tag: str, oid: str = "") -> str:
    """Pick the curated stem. Load averages never inherit tag CPU."""
    tag = (tag or "").strip()
    if is_unix_load_average(native, oid):
        return CPU_LOAD_AVG_STEM
    if is_hr_processor_utilization(native, oid):
        return "CPU"
    if tag in VITAL_TAGS:
        return tag
    return native


def claim_metric_stem(
    native: str,
    tag: str,
    index_labels: tuple[str, ...],
    claimed: dict[tuple[str, tuple[str, ...]], str],
    warnings: list[str],
    profile: str = "",
    oid: str = "",
) -> str:
    """Vital tag wins as stem; a second claim with the same labels keeps native."""
    want = vital_stem(native, tag, oid)
    key = (want, index_labels)
    prior = claimed.get(key)
    if prior is not None and prior != native:
        loc = f" in {profile}" if profile else ""
        warnings.append(
            f"stem {want!r} already claimed by {prior!r}{loc}; keeping native {native!r}"
        )
        return native
    claimed[key] = native
    return want


def lookup_type(column_name: str, tag: str, enum: dict[str, Any] | None = None) -> str:
    """metric_tags → lookup label types.

    Enum on a tag = stable enrichment (kentik <~30m indifference) → EnumAsInfo
    so the string lands on the label, mirroring Info-shaped enrichment.

    ``ifAlias`` / ``if_Alias`` must stay DisplayString: GAUGE_TAG_HINT's ``as$``
    otherwise matches the trailing ``as`` in Alias.
    """
    if invert_enum(enum):
        return "EnumAsInfo"
    blob = f"{column_name} {tag}"
    if re.search(r"alias", blob, re.I):
        return "DisplayString"
    if GAUGE_TAG_HINT.search(blob):
        return "gauge"
    return "DisplayString"


# snmp_exporter collector.indexOidsAsString panics on unknown type strings and
# kills the process (CrashLoopBackOff). MIB name PhysAddress is not in that
# switch; the official generator emits PhysAddress48 for 6-byte MACs.
EXPORTER_TYPE_ALIASES = {
    "PhysAddress": "PhysAddress48",
    "MacAddress": "PhysAddress48",
    # Not in snmp_exporter 0.29 indexOidsAsString — panics the process.
    # Pair with a following InetAddress index is collapsed in normalize_indexes.
    "InetAddressType": "gauge",
}


def exporter_safe_type(typ: str) -> str:
    t = str(typ or "").strip()
    return EXPORTER_TYPE_ALIASES.get(t, t)


def normalize_indexes(indexes: list[Any]) -> list[Any]:
    """snmp_exporter 0.29 combined InetAddress consumes type+addr as one index.

    Declaring InetAddressType then InetAddress panics: Unknown index type InetAddressType.
    Keep the InetAddress index (combinedTypeMapping) and drop the type sibling.
    """
    items = [dict(x) if isinstance(x, dict) else x for x in indexes]
    out: list[Any] = []
    i = 0
    while i < len(items):
        cur = items[i]
        if not isinstance(cur, dict):
            out.append(cur)
            i += 1
            continue
        nxt = items[i + 1] if i + 1 < len(items) else None
        cur_t = str(cur.get("type") or "")
        nxt_t = str(nxt.get("type") or "") if isinstance(nxt, dict) else ""
        if cur_t == "InetAddressType" and nxt_t in {"InetAddress", "InetAddressMissingSize"}:
            merged = dict(nxt)
            merged["type"] = nxt_t
            out.append(merged)
            i += 2
            continue
        cur = dict(cur)
        cur["type"] = exporter_safe_type(cur_t)
        out.append(cur)
        i += 1
    return out


def rewrite_exporter_types(obj: Any) -> Any:
    """Rewrite illegal snmp.yml type strings in module/index/lookup trees."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k == "indexes" and isinstance(v, list):
                out[k] = rewrite_exporter_types(normalize_indexes(v))
            elif k == "type" and isinstance(v, str):
                out[k] = exporter_safe_type(v)
            else:
                out[k] = rewrite_exporter_types(v)
        return out
    if isinstance(obj, list):
        return [rewrite_exporter_types(x) for x in obj]
    return obj


def sanitize_module(module: dict[str, Any]) -> dict[str, Any]:
    """Make a module safe for snmp_exporter 0.29 (types + lookup label arity)."""
    module = rewrite_exporter_types(dict(module))
    metrics: list[Any] = []
    for metric in module.get("metrics") or []:
        if not isinstance(metric, dict):
            metrics.append(metric)
            continue
        metric = dict(metric)
        idx_labels = {
            i.get("labelname")
            for i in (metric.get("indexes") or [])
            if isinstance(i, dict) and i.get("labelname")
        }
        lookups = []
        for lk in metric.get("lookups") or []:
            if not isinstance(lk, dict):
                lookups.append(lk)
                continue
            lk = dict(lk)
            labs = []
            for x in lk.get("labels") or []:
                name = str(x)
                addr_type = name.endswith("AddrType") or name.endswith("AddressType")
                if addr_type and name not in idx_labels:
                    continue
                labs.append(x)
            if labs:
                lk["labels"] = labs
            lookups.append(lk)
        metric["lookups"] = lookups
        metrics.append(metric)
    if "metrics" in module:
        module["metrics"] = metrics
    return module


OID_SYNTAX: dict[str, dict[str, str]] = {}
TYPE_STATS: dict[str, int] = {
    "enum": 0,
    "format": 0,
    "mib": 0,
    "name_hint": 0,
    "default_gauge": 0,
}


def load_oid_syntax(path: Path) -> dict[str, dict[str, str]]:
    """Load public-OID SYNTAX map: oid → {name, syntax, type}."""
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = data.get("oids") or {}
    out: dict[str, dict[str, str]] = {}
    for key, val in raw.items():
        oid = str(key).strip().lstrip(".")
        if isinstance(val, dict):
            out[oid] = {str(k): str(v) for k, v in val.items() if v is not None}
        elif isinstance(val, str):
            out[oid] = {"type": val}
    return out


def lookup_oid_syntax(oid: str) -> dict[str, str] | None:
    oid = str(oid or "").strip().lstrip(".")
    if oid.endswith(".0") and oid.count(".") >= 6:
        oid = oid[:-2]
    # Profiles sometimes bake a table instance (hrStorageSize.1). Walk parents.
    cur = oid
    for _ in range(4):
        hit = OID_SYNTAX.get(cur)
        if hit:
            return hit
        if cur.count(".") < 8:
            break
        cur = cur.rsplit(".", 1)[0]
    return None


def symbol_metric_type(
    name: str,
    tag: str,
    enum: dict[str, Any] | None,
    fmt: str = "",
    oid: str = "",
) -> str:
    """kentik symbols → own metrics. Prefer MIB SYNTAX over name guesses.

    - inventory-ish enum (*Type, model, class, …) → EnumAsInfo
    - status/state enum (oper, admin, status, …) → gauge (+ enum_values kept)
    - kentik ``format: counter|gauge`` when set
    - OBJECT-TYPE SYNTAX from oid-syntax.yaml (public OID lookup) → counter / gauge
    - octet / packet / error / discard names → counter (Counter64 must not be gauge)
    - else → gauge
    Never EnumAsStateSet.
    """
    fmt = (fmt or "").strip().lower()
    if invert_enum(enum):
        TYPE_STATS["enum"] += 1
        blob = f"{name} {tag or ''}"
        # Status wins over inventory when both match (e.g. operState).
        if STATUS_ENUM_HINT.search(blob):
            return "gauge"
        if INVENTORY_ENUM_HINT.search(blob) or name.endswith("Type"):
            return "EnumAsInfo"
        return "gauge"
    if fmt in {"counter", "gauge"}:
        TYPE_STATS["format"] += 1
        return fmt
    hit = lookup_oid_syntax(oid)
    if hit and hit.get("type") in {"counter", "gauge"}:
        TYPE_STATS["mib"] += 1
        return hit["type"]
    if COUNTER_NAME_HINT.search(name) or COUNTER_NAME_HINT.search(tag or ""):
        TYPE_STATS["name_hint"] += 1
        return "counter"
    TYPE_STATS["default_gauge"] += 1
    return "gauge"


def load_table_indexes(path: Path) -> dict[str, list[dict[str, Any]]]:
    """Load public-OID INDEX map: table oid → [{labelname, type, implied?}]."""
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = data.get("tables") or {}
    out: dict[str, list[dict[str, Any]]] = {}
    for key, val in raw.items():
        oid = str(key).strip().lstrip(".")
        idxs = val.get("indexes") if isinstance(val, dict) else val
        if not isinstance(idxs, list) or not idxs:
            continue
        clean: list[dict[str, Any]] = []
        for item in idxs:
            if not isinstance(item, dict) or not item.get("labelname"):
                continue
            row: dict[str, Any] = {
                "labelname": str(item["labelname"]),
                "type": str(item.get("type") or "gauge"),
            }
            if item.get("implied") in {True, "true", "yes", 1}:
                row["implied"] = True
            clean.append(row)
        if clean:
            out[oid] = clean
    return out


def merge_table_indexes() -> dict[str, list[dict[str, Any]]]:
    merged = {k: [dict(x) for x in v] for k, v in TABLE_INDEXES.items()}
    merged.update(LOADED_TABLE_INDEXES)
    merged.update({k: [dict(x) for x in v] for k, v in INDEX_OVERRIDES.items()})
    return merged


def index_source(table_oid: str) -> str:
    table_oid = table_oid.strip().lstrip(".")
    if table_oid in INDEX_OVERRIDES:
        return "override"
    if table_oid in LOADED_TABLE_INDEXES:
        return "mib"
    if table_oid in TABLE_INDEXES:
        return "builtin"
    return "fallback"


def indexes_for_table(table_oid: str) -> list[dict[str, Any]]:
    table_oid = table_oid.strip().lstrip(".")
    raw = MERGED_TABLE_INDEXES.get(
        table_oid,
        [{"labelname": "index", "type": "gauge"}],
    )
    return [
        {**dict(idx), "type": exporter_safe_type(str(idx.get("type") or "gauge"))}
        for idx in raw
    ]


def lookups_from_tags(metric_tags: list[dict[str, Any]] | None, indexes: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not metric_tags:
        return []
    src = [i["labelname"] for i in indexes]
    out: list[dict[str, Any]] = []
    for tag in metric_tags:
        col = tag.get("column") or {}
        oid = col.get("OID")
        name = col.get("name") or tag.get("tag")
        label = tag.get("tag") or name
        if not oid or not label:
            continue
        out.append(
            {
                "labels": list(src),
                "labelname": str(label),
                "oid": str(oid).strip().lstrip("."),
                "type": exporter_safe_type(
                    lookup_type(str(name or ""), str(label), col.get("enum"))
                ),
            }
        )
    return out


def load_profile_yaml(path: Path) -> dict[str, Any]:
    """Load kentik YAML; tolerate tabs (illegal in YAML but present upstream)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    text = text.replace("\t", " ")
    data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"expected mapping at root, got {type(data).__name__}")
    return data


def convert_profile(
    path: Path, profiles_root: Path
) -> tuple[str, str, dict[str, Any], dict[str, Any], list[dict[str, str]]]:
    data = load_profile_yaml(path)
    mod_name, vendor = module_name_from_path(path, profiles_root)
    gets: list[str] = []
    walks: list[str] = []
    metrics: list[dict[str, Any]] = []
    map_rows: list[dict[str, str]] = []
    seen_walk: set[str] = set()
    unknown_indexes: set[str] = set()
    claimed: dict[tuple[str, tuple[str, ...]], str] = {}
    stem_warnings: list[str] = []

    def emit_metric(
        native: str, tag: str, index_labels: tuple[str, ...], oid: str = ""
    ) -> str:
        stem = claim_metric_stem(
            native, tag, index_labels, claimed, stem_warnings, path.name, oid=oid
        )
        emitted = prefix_metric_name(stem)
        map_rows.append(
            {
                "native": native,
                "tag": tag or "",
                "emitted": emitted,
            }
        )
        return emitted

    identity_lookups: list[dict[str, Any]] = []
    seen_identity_oids: set[str] = set()

    def remember_identity(lu: dict[str, Any] | None) -> None:
        if not lu:
            return
        oid = str(lu.get("oid") or "")
        if not oid or oid in seen_identity_oids:
            return
        seen_identity_oids.add(oid)
        identity_lookups.append(lu)

    for block in data.get("metrics") or []:
        mib = block.get("MIB") or ""
        scalar_syms = iter_scalar_symbols(block)
        if scalar_syms:
            for sym in scalar_syms:
                raw_oid = str(sym.get("OID") or "").strip()
                name = str(sym.get("name") or "").strip()
                if not raw_oid or not name:
                    continue
                ident = identity_lookup_from_symbol(sym)
                if ident:
                    remember_identity(ident)
                    continue
                metric_oid, get_oid = strip_instance(raw_oid)
                if get_oid not in gets:
                    gets.append(get_oid)
                tag = str(sym.get("tag") or "")
                enum_values = invert_enum(sym.get("enum"))
                emitted = emit_metric(name, tag, (), raw_oid)
                help_txt = f"{name} ({mib}) - {raw_oid}"
                if is_unix_load_average(name, raw_oid):
                    help_txt += " [Unix load average, not utilization %]"
                metric: dict[str, Any] = {
                    "name": emitted,
                    "oid": metric_oid,
                    "type": symbol_metric_type(
                        name,
                        tag,
                        sym.get("enum"),
                        str(sym.get("format") or ""),
                        metric_oid,
                    ),
                    "help": help_txt,
                }
                if enum_values:
                    metric["enum_values"] = enum_values
                metrics.append(metric)
            continue

        table = block.get("table") or {}
        table_oid = str(table.get("OID") or "").strip().lstrip(".")
        if not table_oid:
            continue
        if table_oid not in seen_walk:
            walks.append(table_oid)
            seen_walk.add(table_oid)
        src = index_source(table_oid)
        INDEX_STATS[src] += 1
        if src == "fallback":
            unknown_indexes.add(table_oid)
        indexes = indexes_for_table(table_oid)
        index_labels = tuple(str(i.get("labelname") or "") for i in indexes)
        lookups = lookups_from_tags(block.get("metric_tags"), indexes)
        for sym in block.get("symbols") or []:
            raw_oid = str(sym.get("OID") or "").strip().lstrip(".")
            name = str(sym.get("name") or "").strip()
            if not raw_oid or not name:
                continue
            tag = str(sym.get("tag") or "")
            enum_values = invert_enum(sym.get("enum"))
            emitted = emit_metric(name, tag, index_labels, raw_oid)
            help_txt = f"{name} ({mib}) - {raw_oid}"
            if is_unix_load_average(name, raw_oid):
                help_txt += " [Unix load average, not utilization %]"
            metric = {
                "name": emitted,
                "oid": raw_oid,
                "type": symbol_metric_type(
                    name,
                    tag,
                    sym.get("enum"),
                    str(sym.get("format") or ""),
                    raw_oid,
                ),
                "help": help_txt,
                "indexes": [dict(i) for i in indexes],
            }
            if lookups:
                metric["lookups"] = [dict(lu) for lu in lookups]
            if enum_values:
                metric["enum_values"] = enum_values
            metrics.append(metric)

    for tag_ent in data.get("metric_tags") or []:
        remember_identity(identity_lookup_from_tag(tag_ent))

    for warn in stem_warnings:
        print(f"WARN: {path.name}: {warn}", file=sys.stderr)

    module: dict[str, Any] = {}
    if walks:
        module["walk"] = walks
    if gets:
        module["get"] = gets
    module["metrics"] = metrics

    index_entry = {
        "profile": path.name,
        "vendor": vendor,
        "provider": data.get("provider"),
        "sysobjectids": list(data.get("sysobjectid") or [])
        if not isinstance(data.get("sysobjectid"), str)
        else [data.get("sysobjectid")],
        # Filenames from kentik extends: (resolved to module names after full convert).
        "extends": [str(x) for x in (data.get("extends") or [])],
        "unknown_table_indexes": sorted(unknown_indexes),
        "identity_lookups": identity_lookups,
        "notes": "Discovery module= chain from extends; identity inlined on fingerprint modules",
    }
    return mod_name, vendor, module, index_entry, map_rows


def sidecar_base_name(name: str) -> str | None:
    n = (name or "").strip()
    for suf in VENDOR_SIDECAR_SUFFIXES:
        if n.endswith(suf) and n[: -len(suf)]:
            return n[: -len(suf)]
    return None


def skip_vendor_split(name: str) -> bool:
    """True for IF-MIB / stock MIB / already-split sidecars — do not re-split."""
    n = (name or "").strip()
    if n in HOT_IF_MODULES or n in COLD_IF_META or n in TOPOLOGY_MODULES:
        return True
    if n in HOT_SYSTEM_MODULES or n in {"ip_addr", "system_mib"}:
        return True
    if n.endswith(("_meta", "_hot", "_identity", "_sensors", "_ext", "_topo", "_bgp")):
        return True
    return False


def _looks_wide_table(metric: dict[str, Any]) -> bool:
    """True for flow / NAT / per-tunnel / per-policy walks (can be thousands of rows)."""
    name = str(metric.get("name") or "")
    if WIDE_TABLE_RE.search(name):
        return True
    indexes = [i for i in (metric.get("indexes") or []) if isinstance(i, dict)]
    labels = " ".join(str(i.get("labelname") or "") for i in indexes)
    if len(indexes) >= 3 and re.search(r"(?i)(addr|port|endpoint)", labels):
        return True
    return False


def metric_tier(metric: dict[str, Any]) -> tuple[str, str | None]:
    """Classify one metric: hot | sensor | topology | ext, plus an optional flag.

    Flags do not change the destination — leftover non-vital walks stay cold.
    They exist so an operator can pull a class back to hot later.
    """
    name = str(metric.get("name") or "")
    help_txt = str(metric.get("help") or "")
    blob = f"{name} {help_txt}"
    flag: str | None = None
    if FLAG_METRIC_RE.search(blob):
        if re.search(r"(?i)hrstorage|dsk|disk|storage", blob):
            flag = "storage"
        elif re.search(r"(?i)session|connection|concurrent|conncount", blob):
            flag = "sessions"
        elif re.search(r"(?i)client|station|associat|wireless|radio", blob):
            flag = "wireless"
        elif re.search(r"(?i)tunnel|vpn|sdwan|overlay", blob):
            flag = "overlay"
        elif re.search(r"(?i)queue|qos|wred|policy", blob):
            flag = "qos"
        elif re.search(r"(?i)license|stack|hastat|failover", blob):
            flag = "ha_stack"
        elif re.search(r"(?i)ifreset|cieif", blob):
            flag = "vendor_if"
        else:
            flag = "other"
    if SENSOR_METRIC_RE.search(name) or SENSOR_METRIC_RE.search(help_txt):
        return "sensor", flag
    if name in HOT_METRIC_NAMES or HOT_VITAL_RE.search(name):
        return "hot", None
    if TOPOLOGY_METRIC_RE.search(name):
        return "topology", None
    if not _looks_wide_table(metric) and HOT_SERVICE_RE.search(name):
        return "hot", flag
    return "ext", flag


def nokia_metric_tier(metric: dict[str, Any]) -> str:
    """Classify one Nokia metric: hot vitals, topology neighbors, else sensors."""
    kind, _flag = metric_tier(metric)
    if kind == "hot":
        return "hot"
    if kind == "topology":
        return "topology"
    return "cold"


def module_is_hot_leaf(module: dict[str, Any]) -> bool:
    metrics = [m for m in (module.get("metrics") or []) if isinstance(m, dict)]
    if not metrics:
        return False
    return all(metric_tier(m)[0] == "hot" for m in metrics)


def hot_leaf_names(modules: dict[str, Any]) -> frozenset[str]:
    return frozenset(n for n, mod in modules.items() if module_is_hot_leaf(mod))


def classify_module(
    name: str,
    *,
    known: set[str] | None = None,
    hot_leaves: set[str] | frozenset[str] | None = None,
) -> str:
    """Return scrape tier: hot | cold | topology."""
    n = (name or "").strip()
    leaves = hot_leaves if hot_leaves is not None else HOT_VENDOR_MODULES
    if (
        n in HOT_IF_MODULES
        or n in HOT_SYSTEM_MODULES
        or n in leaves
        or n.endswith("_hot")
        or n.endswith("_identity")
    ):
        return "hot"
    if known is not None and sidecar_base_name(n) is None:
        if any(f"{n}{suf}" in known for suf in VENDOR_SIDECAR_SUFFIXES):
            return "hot"
    if n.endswith(VENDOR_TOPO_SIDECARS) or n in TOPOLOGY_MODULES or TOPOLOGY_NAME_RE.search(n):
        return "topology"
    return "cold"


def apply_vendor_tier_splits(
    tiers: dict[str, list[str]], known: set[str] | None = None
) -> dict[str, list[str]]:
    """Attach real sidecar files (``*_sensors`` / ``*_ext`` / ``*_topo`` / ``*_bgp``).

    Never invent names that are not in ``known``. The original module keeps
    identity + CPU/mem and is moved to hot when a sidecar exists.
    """
    hot = list(tiers.get("hot") or [])
    cold = list(tiers.get("cold") or [])
    topo = list(tiers.get("topology") or [])

    def exists(mod: str) -> bool:
        # Never invent sidecar names. known=None means "no catalog yet".
        return known is not None and mod in known

    def add(bucket: list[str], mod: str) -> None:
        if mod and exists(mod) and mod not in bucket:
            bucket.append(mod)

    seen_bases: list[str] = []
    for m in (*hot, *cold, *topo):
        if sidecar_base_name(m):
            continue
        if m not in seen_bases:
            seen_bases.append(m)

    for base in seen_bases:
        has_cold = any(exists(f"{base}{suf}") for suf in VENDOR_COLD_SIDECARS)
        has_topo = any(exists(f"{base}{suf}") for suf in VENDOR_TOPO_SIDECARS)
        if not has_cold and not has_topo:
            continue
        cold = [x for x in cold if x != base]
        topo = [x for x in topo if x != base]
        add(hot, base)
        for suf in VENDOR_COLD_SIDECARS:
            add(cold, f"{base}{suf}")
        for suf in VENDOR_TOPO_SIDECARS:
            add(topo, f"{base}{suf}")
    if known is not None and "nokia_srlinux_hot" not in known:
        hot = [m for m in hot if m != "nokia_srlinux_hot"]
    return {"hot": hot, "cold": cold, "topology": topo}


def _oids_from_metrics(metrics: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for metric in metrics:
        oid = str(metric.get("oid") or "").strip().lstrip(".")
        if oid:
            out.append(oid)
        for lk in metric.get("lookups") or []:
            if not isinstance(lk, dict):
                continue
            loid = str(lk.get("oid") or "").strip().lstrip(".")
            if loid:
                out.append(loid)
    return out


def _filter_walk_get(
    metrics: list[dict[str, Any]],
    walks: list[str],
    gets: list[str],
) -> tuple[list[str], list[str]]:
    oids = _oids_from_metrics(metrics)

    def used(prefix: str) -> bool:
        p = prefix.strip().lstrip(".")
        if p.endswith(".0"):
            p = p[:-2]
        return any(o == p or o.startswith(p + ".") or p.startswith(o) for o in oids)

    return [w for w in walks if used(str(w))], [g for g in gets if used(str(g))]


def _module_part(
    metrics: list[dict[str, Any]], walks: list[str], gets: list[str]
) -> dict[str, Any]:
    walk, get = _filter_walk_get(metrics, walks, gets)
    part: dict[str, Any] = {"metrics": metrics}
    if walk:
        part["walk"] = walk
    if get:
        part["get"] = get
    return part


def split_vendor_family(name: str, module: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Split a vendor pack onto hot vitals / cold leftover / topology.

    The original ``name`` stays the fingerprint leaf when any vitals exist
    (identity + CPU/mem). Never invent a ``{name}_hot`` sidecar.
    """
    if skip_vendor_split(name):
        return {name: module}
    walks = list(module.get("walk") or [])
    gets = list(module.get("get") or [])
    buckets: dict[str, list[dict[str, Any]]] = {
        "hot": [],
        "sensor": [],
        "topology": [],
        "ext": [],
    }
    for metric in module.get("metrics") or []:
        if not isinstance(metric, dict):
            continue
        kind, _flag = metric_tier(metric)
        buckets[kind].append(dict(metric))

    hot, sensor, topo, ext = (
        buckets["hot"],
        buckets["sensor"],
        buckets["topology"],
        buckets["ext"],
    )
    leftover = sensor + ext
    if not hot and not topo:
        return {name: module}
    if hot and not leftover and not topo:
        return {name: module}

    out: dict[str, dict[str, Any]] = {}
    if hot:
        out[name] = _module_part(hot, walks, gets)
    elif leftover:
        out[name] = _module_part(leftover, walks, gets)
        leftover = []
    if leftover and hot:
        if sensor and not ext:
            out[f"{name}_sensors"] = _module_part(sensor, walks, gets)
        elif ext and not sensor:
            out[f"{name}_ext"] = _module_part(ext, walks, gets)
        else:
            out[f"{name}_sensors"] = _module_part(sensor, walks, gets)
            out[f"{name}_ext"] = _module_part(ext, walks, gets)
    if topo:
        if all(re.search(r"(?i)bgp", str(m.get("name") or "")) for m in topo):
            topo_name = f"{name}_bgp"
        else:
            topo_name = f"{name}_topo"
        out[topo_name] = _module_part(topo, walks, gets)
    return out or {name: module}


def split_nokia_srlinux_family(module: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Split the Nokia pack: vitals / chassis sensors / BGP."""
    return split_vendor_family("nokia_srlinux", module)


def _keep_known(mods: list[str], known: set[str] | None) -> list[str]:
    if known is None:
        return list(mods)
    return [m for m in mods if m in known]


def partition_module_chain(
    chain: list[str],
    known: set[str] | None = None,
    hot_leaves: set[str] | frozenset[str] | None = None,
) -> dict[str, list[str]]:
    """Split an extends chain into hot / cold / topology module lists."""
    hot: list[str] = []
    cold: list[str] = []
    topo: list[str] = []
    seen: set[str] = set()

    def add(bucket: list[str], mod: str) -> None:
        if mod in seen:
            return
        seen.add(mod)
        bucket.append(mod)

    for mod in chain:
        mod = str(mod).strip()
        if not mod or mod in {"system_mib"}:
            continue
        tier = classify_module(mod, known=known, hot_leaves=hot_leaves)
        if tier == "hot":
            add(hot, mod)
            meta = {"if_mib": "if_mib_meta", "if32_mib": "if32_mib_meta"}.get(mod)
            if meta:
                add(cold, meta)
                add(cold, "ip_addr")
        elif tier == "topology":
            add(topo, mod)
        else:
            add(cold, mod)

    tiers = apply_vendor_tier_splits(
        {"hot": hot, "cold": cold, "topology": topo}, known=known
    )
    return {
        "hot": _keep_known(tiers["hot"], known),
        "cold": _keep_known(tiers["cold"], known),
        "topology": _keep_known(tiers["topology"], known),
    }


def _thin_lookups(metric: dict[str, Any], keep: frozenset[str]) -> dict[str, Any]:
    m = dict(metric)
    lookups = m.get("lookups") or []
    m["lookups"] = [lk for lk in lookups if str(lk.get("labelname") or "") in keep]
    return m


def _is_if_speed_lookup(lk: dict[str, Any]) -> bool:
    if str(lk.get("labelname") or "") == "if_Speed":
        return True
    return str(lk.get("oid") or "").strip().lstrip(".") == IF_HIGHSPEED_OID


def _drop_speed_lookups(metric: dict[str, Any]) -> dict[str, Any]:
    """ifHighSpeed is a hot gauge (snmp_ifHighSpeed), not a string label."""
    m = dict(metric)
    m["lookups"] = [lk for lk in (m.get("lookups") or []) if not _is_if_speed_lookup(lk)]
    return m


def _if_highspeed_metric(template: dict[str, Any] | None) -> dict[str, Any]:
    tmpl = _thin_lookups(dict(template), IF_MIB_HOT_LOOKUP_LABELS) if template else {}
    return {
        "name": IF_HIGHSPEED_METRIC,
        "oid": IF_HIGHSPEED_OID,
        "type": "gauge",
        "help": "ifHighSpeed (IF-MIB) - 1.3.6.1.2.1.31.1.1.1.15",
        "indexes": tmpl.get("indexes")
        or [{"labelname": "ifIndex", "type": "gauge"}],
        "lookups": tmpl.get("lookups") or [],
    }


def split_if_mib_family(name: str, module: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Split if_mib / if32_mib into hot octets/oper and cold meta+errors+discards."""
    if name == "if_mib":
        meta_name = "if_mib_meta"
    elif name == "if32_mib":
        meta_name = "if32_mib_meta"
    else:
        return {name: module}

    hot_metrics: list[dict[str, Any]] = []
    cold_metrics: list[dict[str, Any]] = []
    hot_template: dict[str, Any] | None = None
    for metric in module.get("metrics") or []:
        mname = str(metric.get("name") or "")
        if mname in IF_MIB_HOT_METRIC_NAMES:
            thinned = _thin_lookups(dict(metric), IF_MIB_HOT_LOOKUP_LABELS)
            if hot_template is None:
                hot_template = thinned
            hot_metrics.append(thinned)
        else:
            cold_metrics.append(_drop_speed_lookups(dict(metric)))

    if not any(
        str(m.get("name") or "") == IF_HIGHSPEED_METRIC
        or str(m.get("oid") or "").strip().lstrip(".") == IF_HIGHSPEED_OID
        for m in hot_metrics
    ):
        hot_metrics.append(_if_highspeed_metric(hot_template))

    # MAC is 1:1 with ifIndex — cold lookup, not a hot label on octet counters.
    cold_metrics = [_ensure_if_mac_lookup(m) for m in cold_metrics]

    # Hot has no ifAdminStatus metric, but still needs column walks + admin-up filter.
    # Walk must include lookup OIDs (ifName) or legends stay ifIndex-only.
    hot = apply_if_admin_up_filter({"metrics": hot_metrics}, force=True)
    cold = apply_if_admin_up_filter({"metrics": cold_metrics})
    return {name: hot, meta_name: cold}


def _if_mac_lookup() -> dict[str, Any]:
    return {
        "labels": ["ifIndex"],
        "labelname": "if_MAC",
        "oid": IF_PHYSADDRESS_OID,
        "type": "PhysAddress48",
    }


def _ensure_if_mac_lookup(metric: dict[str, Any]) -> dict[str, Any]:
    m = dict(metric)
    lookups = [dict(lk) for lk in (m.get("lookups") or [])]
    for lk in lookups:
        if (
            str(lk.get("oid") or "").strip().lstrip(".") == IF_PHYSADDRESS_OID
            or str(lk.get("labelname") or "") in {"if_MAC", "ifPhysAddress"}
        ):
            lk["type"] = exporter_safe_type(str(lk.get("type") or "PhysAddress48"))
    has = any(
        str(lk.get("oid") or "").strip().lstrip(".") == IF_PHYSADDRESS_OID
        or str(lk.get("labelname") or "") in {"if_MAC", "ifPhysAddress"}
        for lk in lookups
    )
    if not has:
        lookups.append(_if_mac_lookup())
    m["lookups"] = lookups
    return m


def inject_ip_addr_into_cold_lists(text: str) -> str:
    """Insert ``- ip_addr`` after IF-MIB meta list items without dumping YAML.

    ``fingerprinters.yml`` is ~35k lines with YAML anchors; round-tripping
    through ``yaml.safe_dump`` would explode aliases. Matchers that share
    ``modules_cold: *id002`` pick up the extra module from the anchor body.
    """
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        stripped = line.strip()
        if stripped in {"- if_mib_meta", "- if32_mib_meta"}:
            indent = line[: len(line) - len(line.lstrip())]
            before, after = _yaml_dash_list_context(lines, i, indent)
            whole = before + after
            if "ip_addr" not in whole and (
                stripped == "- if_mib_meta" or "if_mib_meta" not in whole
            ):
                nl = "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
                out.append(f"{indent}- ip_addr{nl}")
        i += 1
    return "".join(out)


def _yaml_dash_list_context(
    lines: list[str], idx: int, indent: str
) -> tuple[list[str], list[str]]:
    indent_len = len(indent)
    before: list[str] = []
    j = idx - 1
    while j >= 0:
        raw = lines[j]
        if raw.strip() == "":
            j -= 1
            continue
        cur = len(raw) - len(raw.lstrip())
        st = raw.strip()
        if cur == indent_len and st.startswith("- "):
            before.append(st[2:].strip())
            j -= 1
            continue
        break
    before.reverse()
    after: list[str] = []
    for raw in lines[idx:]:
        if raw.strip() == "":
            continue
        cur = len(raw) - len(raw.lstrip())
        st = raw.strip()
        if cur < indent_len:
            break
        if cur == indent_len and st.startswith("- "):
            after.append(st[2:].strip())
            continue
        if cur == indent_len and not st.startswith("-"):
            break
    return before, after


def build_module_tiers_doc(modules: dict[str, Any]) -> dict[str, Any]:
    tiers: dict[str, list[str]] = {"hot": [], "cold": [], "topology": []}
    known = set(modules)
    leaves = hot_leaf_names(modules)
    for n in sorted(modules):
        tiers[classify_module(n, known=known, hot_leaves=leaves)].append(n)
    return {
        "description": (
            "Scrape tiers for staggered Prometheus jobs. "
            "hot≈60s octets/oper/CPU/mem; cold≈if_mib_meta + sensors + leftover walks; "
            "topology=optional LLDP/CDP/BGP/OSPF/ISIS."
        ),
        "tiers": tiers,
    }


def oid_glob_to_regex(glob: str) -> str:
    """Kentik sysobjectid glob → regex for SuperQ-style fingerprinters (#1468)."""
    g = glob.strip().lstrip(".")
    if g.endswith(".*"):
        prefix = re.escape(g[:-2])
        return rf"^\.?{prefix}(\.[0-9]+)+$"
    return rf"^\.?{re.escape(g)}$"


def build_fingerprinters(
    index: dict[str, Any],
    hot_leaves: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    """Fingerprinters emit tiered module chains from kentik extends.

    Example: nokia_srlinux extends system-mib + if-mib
      → hot: [if_mib, nokia_srlinux] (identity + CPU/mem)
      → cold: [if_mib_meta, ip_addr, nokia_srlinux_sensors]
      → topology: [nokia_srlinux_bgp] (+ lldp_mib when present)
      Unknown sysObjectID: device_base + if_mib (hot), if_mib_meta + ip_addr (cold).
    """
    modules_meta = index.get("modules") or {}
    known = set(modules_meta)
    file_to_mod = {
        meta["profile"]: name
        for name, meta in modules_meta.items()
        if meta.get("profile")
    }

    def extends_filenames_to_mods(filenames: list[str]) -> list[str]:
        out: list[str] = []
        for raw in filenames:
            if skipped_extends(raw):
                continue
            base = Path(str(raw)).name
            mod = file_to_mod.get(base) or file_to_mod.get(str(raw))
            if not mod:
                print(f"WARN: extends {raw!r} has no converted module", file=sys.stderr)
                continue
            out.append(mod)
        return out

    direct: dict[str, list[str]] = {}
    for name, meta in modules_meta.items():
        direct[name] = extends_filenames_to_mods(list(meta.get("extends") or []))
        meta["extends_modules"] = list(direct[name])

    def resolve_chain(mod: str) -> list[str]:
        ordered: list[str] = []
        visiting: set[str] = set()

        def walk(m: str) -> None:
            if m in ordered:
                return
            if m in visiting:
                return
            visiting.add(m)
            for dep in direct.get(m, []):
                walk(dep)
            visiting.discard(m)
            if m not in ordered:
                ordered.append(m)

        walk(mod)
        return ordered

    for name, meta in modules_meta.items():
        chain = resolve_chain(name)
        sidecar = meta.get("identity_sidecar")
        if sidecar and sidecar not in chain:
            chain = list(chain) + [sidecar]
        meta["module_chain"] = chain
        tiers = partition_module_chain(chain, known, hot_leaves=hot_leaves)
        meta["module_chain_hot"] = tiers["hot"]
        meta["module_chain_cold"] = tiers["cold"]
        meta["module_chain_topology"] = tiers["topology"]

    matchers: list[dict[str, Any]] = []
    for mod_name, meta in modules_meta.items():
        chain = meta.get("module_chain") or [mod_name]
        tiers = partition_module_chain(chain, known, hot_leaves=hot_leaves)
        for glob in meta.get("sysobjectids") or []:
            matchers.append(
                {
                    "label": "sysObjectID",
                    "regex": oid_glob_to_regex(str(glob)),
                    # Legacy single list (hot+cold+topology) for older tools.
                    "modules": list(chain),
                    "modules_hot": tiers["hot"],
                    "modules_cold": tiers["cold"],
                    "modules_topology": tiers["topology"],
                    "comment": f"{mod_name} {glob}",
                }
            )
    matchers.sort(
        key=lambda m: (
            1 if r"(\.[0-9]+)+" in m["regex"] else 0,
            -len(m["regex"]),
        )
    )
    default_tiers = partition_module_chain(["device_base", "if_mib"], known)
    return {
        "fingerprinters": {
            "network": {
                "probe_oids": [
                    "1.3.6.1.2.1.1.2.0",
                    "1.3.6.1.2.1.1.5.0",
                    "1.3.6.1.2.1.1.1.0",
                ],
                "default_modules": ["device_base", "if_mib"],
                "default_modules_hot": default_tiers["hot"],
                "default_modules_cold": default_tiers["cold"],
                "default_modules_topology": default_tiers["topology"],
                "matchers": matchers,
            }
        }
    }



def discover_profiles(profiles_root: Path) -> list[Path]:
    """Flat dir or kentik_snmp tree. Skips _general / templates / traps."""
    if not profiles_root.is_dir():
        return []
    out: list[Path] = []
    for path in sorted(profiles_root.rglob("*")):
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        name = path.name
        if name.startswith(SKIP_NAME_PREFIXES):
            continue
        lower = name.lower()
        if any(s in lower for s in SKIP_NAME_SUBSTRINGS):
            continue
        if name in SKIP_PROFILE_FILES:
            continue
        out.append(path)
    # Prefer shallow flat listing when root itself only has files
    if not out:
        out = sorted(profiles_root.glob("*.yml")) + sorted(profiles_root.glob("*.yaml"))
    return out


def dump_yaml(data: Any) -> str:
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)


# IF-MIB ifAdminStatus: 1=up, 2=down, 3=testing. Drop admin-down at scrape time
# (snmp_exporter dynamic filters). Prom relabel cannot drop on gauge *values*.
IF_ADMIN_STATUS_OID = "1.3.6.1.2.1.2.2.1.7"
IF_ADMIN_UP_VALUES = ["1"]


def apply_if_admin_up_filter(
    module: dict[str, Any], *, force: bool = False
) -> dict[str, Any]:
    """Restrict IF-MIB table polls to ifAdminStatus=up via snmp_exporter filters.

    Applies when the module exports ifAdminStatus (if_mib / if32_mib), or when
    force=True (hot if_mib split — counters only, still filter on admin status).

    Also rewrites ``walk`` from the parent ifTable OID (e.g. 1.3.6.1.2.1.2.2) to the
    per-column metric **and lookup** OIDs. A parent-table walk ignores dynamic filters
    and still returns admin-down rows; column walks + filters is the snmp_exporter
    pattern that actually drops them. Lookups (ifName, ifAlias, …) must be in
    ``walk`` / filter ``targets`` or snmp_exporter never GETs them.
    """
    metrics = module.get("metrics") or []
    has_admin = any(
        str(m.get("name") or "") in {"ifAdminStatus", "snmp_ifAdminStatus"}
        or str(m.get("oid") or "").lstrip(".") == IF_ADMIN_STATUS_OID
        for m in metrics
    )
    if not has_admin and not force:
        return module

    targets: list[str] = []
    seen: set[str] = set()

    def add(oid: object) -> None:
        oid_s = str(oid or "").strip().lstrip(".")
        if not oid_s or oid_s in seen:
            return
        seen.add(oid_s)
        targets.append(oid_s)

    for m in metrics:
        add(m.get("oid"))
        for lu in m.get("lookups") or []:
            add(lu.get("oid"))
    if not targets:
        return module

    module = dict(module)
    # Drop parent ifTable / ifXTable walks — they bypass index filters.
    module["walk"] = list(targets)
    # Runtime snmp.yml shape (snmp_exporter): filters is a list.
    # generator.yml uses filters.dynamic; that map form fails to unmarshal here.
    module["filters"] = [
        {
            "oid": IF_ADMIN_STATUS_OID,
            "targets": targets,
            "values": list(IF_ADMIN_UP_VALUES),
        }
    ]
    return module


def write_module_file(modules_dir: Path, vendor: str, mod_name: str, module: dict[str, Any]) -> Path:
    dest_dir = modules_dir / vendor
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{mod_name}.yml"
    if mod_name == "ip_addr":
        header = (
            "# Authored IP-MIB address inventory (not kentik ip-mib.yml stats).\n"
            "# ipAddrTable + ipAddressTable with ifIndex labels for dashboard joins.\n"
        )
    else:
        header = (
            f"# GENERATED from kentik/snmp-profiles — module {mod_name}\n"
            f"# Discovery chain is if_mib + vendor; SNMPv2 identity is inlined as snmp_device_info.\n"
        )
    if module.get("filters"):
        header += (
            "# filters: ifAdminStatus=up only (drop admin-down ifIndex rows; list form).\n"
        )
    body = {"modules": {mod_name: sanitize_module(module)}}
    dest.write_text(header + dump_yaml(body), encoding="utf-8")
    return dest


def concat_snmp_network(
    auths: dict[str, Any],
    modules: dict[str, Any],
    out: Path,
) -> None:
    header = (
        "# GENERATED by tools/snmp-profile-convert/convert.py — do not edit by hand.\n"
        "# Source: snmp/auths.yml + snmp/modules/**/*.yml (kentik/snmp-profiles, Apache-2.0).\n"
        "# License: snmp/LICENSE ; attribution: snmp/NOTICE.\n"
        "# Concatenation for a single snmp_exporter --config.file.\n"
        "# Prefer editing split modules and re-running convert.py.\n"
        "# This file replaces stock embedded modules; do not merge with snmp.yml from the exporter image.\n"
    )
    snmp = {
        "auths": auths,
        "modules": {k: sanitize_module(v) for k, v in modules.items()},
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(header + dump_yaml(snmp), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--profiles",
        type=Path,
        default=DEFAULT_PROFILES,
        help="kentik-style profiles dir (flat) or kentik_snmp tree root",
    )
    ap.add_argument(
        "--modules-dir",
        type=Path,
        default=DEFAULT_MODULES_DIR,
        help="Output directory for per-module YAML fragments",
    )
    ap.add_argument("--auths-out", type=Path, default=DEFAULT_AUTHS_OUT)
    ap.add_argument("--snmp-out", type=Path, default=DEFAULT_SNMP_OUT)
    ap.add_argument("--index-out", type=Path, default=DEFAULT_INDEX_OUT)
    ap.add_argument(
        "--map-out",
        type=Path,
        default=None,
        help="Optional markdown of native OID name → emitted snmp_* stem (not a ktranslate contract)",
    )
    ap.add_argument("--fingerprinters-out", type=Path, default=DEFAULT_FP_OUT)
    ap.add_argument("--tiers-out", type=Path, default=DEFAULT_TIERS_OUT)
    ap.add_argument(
        "--oid-syntax",
        type=Path,
        default=DEFAULT_OID_SYNTAX,
        help="OID→SYNTAX map from lookup-oid-syntax.py. Missing file = name-hint fallback.",
    )
    ap.add_argument(
        "--table-indexes",
        type=Path,
        default=DEFAULT_TABLE_INDEXES_FILE,
        help="Table INDEX map from lookup-oid-indexes.py. Missing file = builtin/fallback.",
    )
    ap.add_argument(
        "--clean-modules",
        action="store_true",
        help="Delete existing snmp/modules/** before writing",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Convert only the first N profiles (0 = all)",
    )
    args = ap.parse_args()

    global OID_SYNTAX, LOADED_TABLE_INDEXES, MERGED_TABLE_INDEXES
    OID_SYNTAX = load_oid_syntax(args.oid_syntax)
    if OID_SYNTAX:
        print(f"oid-syntax: {len(OID_SYNTAX)} OIDs from {args.oid_syntax}")
    elif args.oid_syntax.is_file():
        print(f"WARN: {args.oid_syntax} has no oids:", file=sys.stderr)
    else:
        print(
            f"NOTE: no {args.oid_syntax} — metric types use format/name-hint only. "
            "Run tools/snmp-profile-convert/lookup-oid-syntax.py first.",
            file=sys.stderr,
        )
    LOADED_TABLE_INDEXES = load_table_indexes(args.table_indexes)
    MERGED_TABLE_INDEXES = merge_table_indexes()
    if LOADED_TABLE_INDEXES:
        print(f"table-indexes: {len(LOADED_TABLE_INDEXES)} tables from {args.table_indexes}")
    elif args.table_indexes.is_file():
        print(f"WARN: {args.table_indexes} has no tables:", file=sys.stderr)
    else:
        print(
            f"NOTE: no {args.table_indexes} — table INDEX uses builtin/fallback. "
            "Run tools/snmp-profile-convert/lookup-oid-indexes.py first.",
            file=sys.stderr,
        )

    profiles = discover_profiles(args.profiles)
    if not profiles:
        print(f"ERROR: no profiles in {args.profiles}", file=sys.stderr)
        return 1
    if args.limit > 0:
        profiles = profiles[: args.limit]

    if args.clean_modules and args.modules_dir.exists():
        for old in args.modules_dir.rglob("*.yml"):
            old.unlink()
        # remove empty dirs bottom-up
        for d in sorted(args.modules_dir.rglob("*"), reverse=True):
            if d.is_dir():
                try:
                    d.rmdir()
                except OSError:
                    pass

    modules: dict[str, Any] = {}
    index: dict[str, Any] = {"modules": {}}
    map_rows: list[dict[str, str]] = []
    collisions: list[str] = []
    unknown_index_modules = 0

    skipped: list[str] = []
    for path in profiles:
        try:
            name, vendor, module, idx, profile_map = convert_profile(path, args.profiles)
        except Exception as exc:  # noqa: BLE001 — keep converting the rest of the tree
            skipped.append(f"{path}: {exc}")
            print(f"SKIP {path}: {exc}", file=sys.stderr)
            continue
        if name in modules:
            # Disambiguate: vendor_stem
            alt = f"{vendor.replace('-', '_')}_{name}"
            collisions.append(f"{name} (kept first; also saw {path} → would be {alt})")
            print(f"WARN: duplicate module name {name}; skipping {path}", file=sys.stderr)
            continue
        module = apply_if_admin_up_filter(module)
        if name in ("if_mib", "if32_mib"):
            parts = split_if_mib_family(name, module)
            for part_name, part_mod in parts.items():
                if part_name in modules and part_name != name:
                    print(f"WARN: tier module {part_name} already exists; overwriting", file=sys.stderr)
                modules[part_name] = part_mod
                if part_name == name:
                    index["modules"][part_name] = idx
                else:
                    index["modules"][part_name] = {
                        "profile": f"{part_name.replace('_', '-')}.yml",
                        "vendor": vendor,
                        "sysobjectids": [],
                        "extends": [],
                        "identity_lookups": [],
                        "notes": "cold IF-MIB enrichment (staggered scrape)",
                    }
                n_metrics = len(part_mod.get("metrics") or [])
                print(f"converted {vendor}/{path.name} -> {part_name} ({n_metrics} metrics) [tier]")
        else:
            modules[name] = module
            index["modules"][name] = idx
            if idx.get("unknown_table_indexes"):
                unknown_index_modules += 1
            n_metrics = len(module.get("metrics") or [])
            unk = len(idx.get("unknown_table_indexes") or [])
            extra = f", {unk} tables need INDEX" if unk else ""
            print(f"converted {vendor}/{path.name} -> {name} ({n_metrics} metrics{extra})")
        map_rows.extend(profile_map)

    ident_stats = fold_device_identity(modules, index)
    modules.pop("system_mib", None)
    (index.get("modules") or {}).pop("system_mib", None)
    print(
        f"identity: inlined={ident_stats['inlined']} "
        f"sidecars={ident_stats['sidecars']} + device_base"
    )

    split_n = 0
    for name in list(modules):
        if skip_vendor_split(name):
            continue
        vendor = str((index["modules"].get(name) or {}).get("vendor") or "_general")
        parts = split_vendor_family(name, modules[name])
        if set(parts) == {name}:
            continue
        split_n += 1
        for part_name, part_mod in parts.items():
            modules[part_name] = part_mod
            if part_name == name:
                continue
            index.setdefault("modules", {})[part_name] = {
                "profile": f"{part_name.replace('_', '-')}.yml",
                "vendor": vendor,
                "sysobjectids": [],
                "extends": [],
                "identity_lookups": [],
                "notes": "vendor tier sidecar",
            }
            print(
                f"split {name} -> {part_name} "
                f"({len(part_mod.get('metrics') or [])} metrics)"
            )
    print(f"vendor tier splits: {split_n} packs")

    for name, module in modules.items():
        vendor = str((index["modules"].get(name) or {}).get("vendor") or "_general")
        write_module_file(args.modules_dir, vendor, name, module)

    args.auths_out.parent.mkdir(parents=True, exist_ok=True)
    args.auths_out.write_text(
        "# Named SNMP auths (secrets live here — never on SD labels).\n"
        + dump_yaml({"auths": DEFAULT_AUTHS}),
        encoding="utf-8",
    )
    concat_snmp_network(DEFAULT_AUTHS, modules, args.snmp_out)

    leaves = hot_leaf_names(modules)
    fp = build_fingerprinters(index, hot_leaves=leaves)
    tiers_doc = build_module_tiers_doc(modules)
    args.index_out.write_text(
        "# GENERATED sysObjectID → module index (seed for discovery.snmp).\n"
        + dump_yaml(index),
        encoding="utf-8",
    )
    args.fingerprinters_out.write_text(
        "# GENERATED. Matcher model aligns with prometheus/snmp_exporter#1468\n"
        "# modules_hot / modules_cold / modules_topology = staggered scrape tiers.\n"
        "# Legacy `modules` remains the full chain for older tools.\n"
        + dump_yaml(fp),
        encoding="utf-8",
    )
    args.tiers_out.write_text(
        "# GENERATED module → scrape tier (hot | cold | topology).\n"
        + dump_yaml(tiers_doc),
        encoding="utf-8",
    )

    if args.map_out:
        lines = [
            "# Emitted snmp_* stems from profile object names",
            "",
            "| MIB object | profile tag | emitted |",
            "|------------|-------------|---------|",
        ]
        seen: set[tuple[str, str, str]] = set()
        for row in map_rows:
            key = (row["native"], row.get("tag") or "", row.get("emitted") or "")
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                f"| `{row['native']}` | `{row.get('tag') or '—'}` | `{row.get('emitted') or '—'}` |"
            )
        args.map_out.parent.mkdir(parents=True, exist_ok=True)
        args.map_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {args.map_out}")

    print(f"wrote {args.auths_out}")
    print(f"wrote {args.modules_dir} ({len(modules)} modules)")
    print(f"wrote {args.snmp_out}")
    print(f"wrote {args.index_out}")
    print(f"wrote {args.fingerprinters_out}")
    print(f"wrote {args.tiers_out}")
    th, tc, tt = (
        len(tiers_doc["tiers"]["hot"]),
        len(tiers_doc["tiers"]["cold"]),
        len(tiers_doc["tiers"]["topology"]),
    )
    print(f"tiers: hot={th} cold={tc} topology={tt}")
    print(
        "metric types: "
        + " ".join(f"{k}={TYPE_STATS[k]}" for k in (
            "enum", "format", "mib", "name_hint", "default_gauge"
        ))
    )
    print(
        "table indexes: "
        + " ".join(f"{k}={INDEX_STATS[k]}" for k in (
            "mib", "override", "builtin", "fallback"
        ))
    )
    leaked = [
        row
        for row in map_rows
        if is_unix_load_average(row.get("native") or "")
        and row.get("emitted") == prefix_metric_name("CPU")
    ]
    load_n = sum(
        1
        for row in map_rows
        if is_unix_load_average(row.get("native") or "")
    )
    cpu_n = sum(1 for row in map_rows if row.get("emitted") == prefix_metric_name("CPU"))
    print(f"CPU vs load: {cpu_n} → snmp_CPU, {load_n} load-avg → snmp_{CPU_LOAD_AVG_STEM}")
    if leaked:
        print(
            f"ERROR: {len(leaked)} Unix load-average object(s) still emit snmp_CPU:",
            file=sys.stderr,
        )
        for row in leaked[:12]:
            print(f"  {row.get('native')} tag={row.get('tag')}", file=sys.stderr)
        return 1
    if collisions:
        print(f"WARN: {len(collisions)} duplicate module name(s)", file=sys.stderr)
    if skipped:
        print(f"WARN: skipped {len(skipped)} profile(s)", file=sys.stderr)
    if unknown_index_modules:
        print(
            f"NOTE: {unknown_index_modules}/{len(modules)} modules have tables "
            "using fallback index= — live-check before relying on scrapes.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
