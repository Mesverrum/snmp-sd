# snmp-profile-convert

**One-shot ingest.** [kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) is an OID cookbook (numeric OIDs, no MIB compiler). Convert writes `snmp/modules/` — that tree **is** this repo’s library. Edit modules in place after ingest. Re-run convert only when adding a vendor pack.

## Output layout

```text
snmp/
  auths.yml                      # named communities / v3 (secrets)
  modules/<vendor>/<module>.yml  # one module per file — the edit surface
  snmp-network.yml               # concat for a single snmp_exporter --config.file
  fingerprinters.yml
  sysobjectid-index.yaml
```

```bash
# Small in-tree copies (nokia + lenovo under snmp/profiles/)
python3 tools/snmp-profile-convert/convert.py

# Full kentik tree (sibling clone) — ingest once
python3 tools/snmp-profile-convert/convert.py \
  --profiles ../snmp-profiles/profiles/kentik_snmp \
  --clean-modules
```

Skips `_template/` and trap/syslog-named files. Converts `_general/` bases (`if_mib`, …) as real modules. Kentik `system-mib.yml` is **not** a scrape module — SNMPv2 identity is **inlined** onto each fingerprint module as one `snmp_device_info` (plus `snmp_Uptime`). Root-level `metric_tags` (firmware / serial / model) fold onto that same info metric. Vendor `extends:` become discovery **module chains** (transitive), e.g. `if_mib,nokia_srlinux`. Unknown sysObjectID uses generated `device_base` + `if_mib`.

Parents that both fingerprint (`sysobjectid`) **and** have children (`huawei_all_devices`, `juniper_all_devices`) keep tables only; identity lives on a `{name}_identity` sidecar so a child scrape is not two `snmp_device_info` families. Device-level scalar lookups nested on table metrics are stripped (FRU serials on a chassis INDEX stay).

snmp_exporter `--config.file` is this concat. `snmp-discovery --snmp-config` and `--fingerprinters` must be the same convert.

Every vendor pack is split the same way (no invented `{name}_hot`):

| Module | Tier | Contents |
|---|---|---|
| `{name}` | hot | `snmp_device_info`, `snmp_Uptime`, CPU / CPULoad, RAM (plus `hrStorage` when RAM/disk share a table), core-service counts |
| `{name}_sensors` | cold | chassis / temp / fans / PSU when that is the leftover |
| `{name}_ext` | cold | leftover wide tables (per-tunnel / per-policy / NAT), separable disk MIBs, vendor IF extras |
| `{name}_topo` | topology | neighbor leftovers (BGP, LLDP/CDP, OSPF/ISIS) |

Nokia is `nokia_srlinux` / `_sensors` / `_ext` / `_topo`. Re-split the library without a full ingest: `python3 tools/snmp-profile-convert/split_vendor_tiers.py`.

**Metric names:** every series is `snmp_<stem>`. Profile `tag` values (`CPU`, `MemoryUsed`, `MemoryFree`, `MemoryTotal`, `Temperature`) become the stem (`snmp_CPU`); other objects keep the MIB name (`snmp_ifHCInOctets`). Labels are not prefixed. Two symbols in one module that would share a vital stem and the same indexes: first wins; later keep the native stem (converter warns).

**CPU vs load average:** Unix load averages are not 0–100% utilization. They emit `snmp_CPULoad`; real utilization stays `snmp_CPU`:

| Object | Why | Emitted |
|--------|-----|---------|
| UCD `laLoadInt` / `laLoadInt1Min` (`1.3.6.1.4.1.2021.10.1.5`) | float load × 100 | `snmp_CPULoad` |
| UniFi `loadValue` (FROGFOOT `loadTable`) | 1-min load (per-mil) | `snmp_CPULoad` |
| `hrProcessorLoad` / `hrProcessorLoadCombined` | HOST-RESOURCES “% of time not idle” | `snmp_CPU` |
| `sysXProcessorLoad` | same meaning, vendor OID | `snmp_CPU` (when tagged) |
| Vendor `*Util*`, `cpmCPUTotal*`, `stCPULoad`, `deviceCpuLoad` | percent busy (Peplink is hundredths of a percent) | `snmp_CPU` |

## Rules (do not regress)

1. **Entry `.1`** — kentik symbols are `table.1.column`; keep the full column OID.
2. **Full INDEX** — every MIB INDEX component must appear (from `snmp/table-indexes.yaml`, then builtin, then live-walk `INDEX_OVERRIDES`). Incomplete indexes → duplicate label scrape errors in snmp_exporter.
3. **Live-check arity** — `snmpwalk -On` the column; the suffix after the column OID must match the index list length (or a known packed single sub-id).
4. **Admin-down interfaces** — modules that export `ifAdminStatus` (`if_mib`, `if32_mib`) get snmp_exporter `filters:` as a **list** (`values: ["1"]`) **and** `walk` rewritten from the parent ifTable OID to per-column metric **and lookup** OIDs (a parent-table walk bypasses filters; lookup OIDs omitted from `walk` means ifName never lands on hot counters). Generator YAML uses `filters.dynamic`; the runtime exporter expects the flat list. Do **not** try to drop admin-down in Prom relabel from the gauge *value*.
5. **ifHighSpeed** — kentik ships this as metric_tag `if_Speed` (a label). Convert promotes it to hot gauge `snmp_ifHighSpeed` (Mbps) so utilization can divide by a number. `ifAlias` stays a DisplayString lookup (the `as$` gauge hint would otherwise match Alias).
6. **Counters** — prefer OBJECT-TYPE SYNTAX from `snmp/oid-syntax.yaml` (public OID lookup, not a shipped MIB tree). Counter32/64 → `type: counter`; Gauge32 / Integer / TimeTicks → `gauge`. A Counter64 PDU typed as `gauge` is dropped (`snmp_unexpected_pdu_type_total`) and `ifHCInOctets` never appears. Then honor kentik `format:`; then name hints (`octets|pkts|errors|…`). CPU / memory / temperature stay gauges.
7. **IP / MAC inventory** — `ifPhysAddress` is a cold `if_MAC` lookup on `if_mib_meta` (1:1 with ifIndex). snmp_exporter type must be **`PhysAddress48`** (MIB name `PhysAddress` panics the collector). Address tables are **not** kentik `ip-mib.yml` (that's ipSystemStats). Authored cold module `ip_addr` scrapes `ipAddrTable` / `ipAddressTable` with **`ifIndex` as a label** so queries can join `on(device_name, ifIndex)`. snmp_exporter lookups are 1:1 on the metric INDEX, so IPs cannot be labels on `ifHCInOctets`. Do not `*` the raw `snmp_ipAdEntIfIndex` gauge (value is ifIndex — it would scale octets); use `count by (device_name, ifIndex, ipAdEntAddr) (snmp_ipAdEntIfIndex)`.
8. **One catalog** — never invent sidecars (`nokia_srlinux_hot`, `*_identity`) unless that file exists under `snmp/modules/`. Fingerprinter `module=` names must be keys in `snmp-network.yml`. Discovery drops unknowns with a WARN; mixing convert generations is not a failed scan, but the walker will not load a missing module.

## OID SYNTAX lookup (no MIB library)

We do **not** clone or ship vendor MIB files. `lookup-oid-syntax.py` hits public OID pages ([oid-base.com](https://oid-base.com/), [oidref.com](https://oidref.com/)) for each profile OID and writes a small `oid → SYNTAX → counter|gauge` map. HTML is cached under `~/.cache/snmp-oid-syntax` so reruns skip the network.

```bash
python3 tools/snmp-profile-convert/lookup-oid-syntax.py \
  --profiles ../snmp-profiles/profiles/kentik_snmp

python3 tools/snmp-profile-convert/lookup-oid-indexes.py \
  --profiles ../snmp-profiles/profiles/kentik_snmp

python3 tools/snmp-profile-convert/convert.py \
  --profiles ../snmp-profiles/profiles/kentik_snmp \
  --clean-modules

# IF-MIB + IP inventory (ifName walks, snmp_ifHighSpeed, if_MAC, ip_addr) without re-ingesting vendors:
python3 tools/snmp-profile-convert/refresh_if_mib.py \
  --profiles ../snmp-profiles/profiles/kentik_snmp
```

`snmp/oid-syntax.yaml` and `snmp/table-indexes.yaml` are generated maps, not a MIB corpus. Convert still works without them (name-hint / single `index=` fallback). Kentik profiles are not a reliable INDEX source — the lookup reads `INDEX { … }` / `AUGMENTS { … }` from the Entry page. Hand overrides stay only for live walks that disagree with the MIB (packed sub-ids).

## Extends → discovery module chains

Kentik `extends:` is **not** inlined into one YAML blob. Each extended profile is its own module; discovery sets:

```text
module: if_mib,nokia_srlinux
module: if_mib,cisco_all_devices,cisco_catalyst
```

(transitive: `cisco_catalyst` → `cisco_all_devices` → `if_mib`). SNMPv2 identity is already on the leaf module’s `snmp_device_info`. Default for unknown sysObjectID: `device_base,if_mib`.

## Enum / enrichment (mirror stock if_mib)

Kentik’s split maps cleanly onto snmp_exporter shapes:

| kentik | Intent | snmp_exporter |
|--|--|--|
| `symbols` / `symbol` | Own metric; care about change on a scrape (~&lt;30m) | Metric series |
| `metric_tags` | Stable enrichment; OK if stale for tens of minutes | `lookups` (labels on the metric) |

Enum on those:

| | Type | Notes |
|--|--|--|
| Symbol + inventory-ish name (`*Type`, model, class, …) | `EnumAsInfo` | Same line as stock `ifType` |
| Symbol + status/state (`oper`, `admin`, `status`, …) | `gauge` + `enum_values` | Same as stock `ifOperStatus` — map kept for catalog/docs, value stays numeric |
| `metric_tags` column with `enum` | lookup `EnumAsInfo` | String on the label (Info-shaped enrichment) |

**Never** `EnumAsStateSet` from this converter (mostly-zero series + alert UX noise).
