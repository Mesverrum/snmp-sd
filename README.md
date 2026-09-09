# snmp-sd

Prometheus-shaped **SNMP service discovery** plus a curated [snmp_exporter](https://github.com/prometheus/snmp_exporter) module library.

The exporter does not find devices. This repo does. Discovery emits targets with a named `auth` and a resolved `module` list. Secrets never appear on SD labels.

```text
CIDR / groups  →  snmp-discovery  →  /sd/prometheus
                                      ↓
                                 Prometheus http_sd
                                      ↓
                         snmp_exporter /snmp?target=&module=&auth=
```

| Piece | What it does |
|---|---|
| `snmp-discovery` CLI | CIDR sweep + optional LLDP/CDP crawl + sticky catalog + HTTP SD |
| Fingerprinters | `sysObjectID` → `module=` at **SD time** (SuperQ [#1468](https://github.com/prometheus/snmp_exporter/issues/1468) matcher shape) |
| `snmp/modules/` | Converted device-family modules (edit these) |
| `snmp/snmp-network.yml` | Concat for a single snmp_exporter `--config.file` |
| `tools/snmp-profile-convert/` | One-shot ingest from [kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) |

```text
/snmp?target=192.0.2.10&auth=public_v2&module=if_mib,nokia_srlinux
```

Worked example (discovery + stock exporter + Prometheus): [`examples/prometheus-snmp/`](examples/prometheus-snmp/). Optional two-exporter shard overlay: `compose.shard.yaml`.

## First pass — two files you write

**`discovery.yml`** — where to look. Auth **names** only:

```yaml
groups:
  - name: lab
    cidrs:
      - 172.20.20.0/24
    auths:
      - public_v2
    fingerprinter: network
    mode: sweep
    ping: true
    port: 161
overrides: []
```

**`auths.yml`** — the secrets (mode `0600`, do not commit). Same names:

```yaml
auths:
  public_v2:
    version: 2
    community: public
```

Copy [`snmp/auths.example.yml`](snmp/auths.example.yml) and edit. The module library already ships `auths.public_v2` for a laptop test; split secrets out as soon as communities are real.

You do **not** write `fingerprinters.yml` or the module YAML on day one. Those come from convert. `fingerprinter: network` means “use the `network` table in that generated file.”

## Build

```bash
go test ./...
go build -o snmp-discovery ./cmd/snmp-discovery
```

Static Linux binary:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o snmp-discovery ./cmd/snmp-discovery
```

Container with the binary **and** the library (`Dockerfile`):

```bash
docker build -t snmp-sd:lab .
```

`Dockerfile.linux` is a different image: scratch + a pre-built `snmp-discovery-linux` binary only (no module library). Use it when you already built the Go binary on the host and bind-mount `snmp/`.

## Run

The process must share L2/L3 with the devices (ICMP optional, UDP/161 required). A host that cannot reach the CIDR writes an empty catalog — that is not a fingerprinter failure.

```bash
./snmp-discovery \
  --config examples/colocated-clos.yml \
  --snmp-config snmp/snmp-network.yml \
  --fingerprinters snmp/fingerprinters.yml \
  --out-file-sd snmp-file-sd.json \
  --out-catalog snmp-targets.yml \
  --listen :9780 \
  --interval 24h \
  --tiers hot,cold \
  --ping --timeout 2s --retries 1 --concurrency 16
```

`--interval 0` with no `--listen` is one-shot (cron + file_sd). `--listen` serves:

| Path | What |
|---|---|
| `GET /sd/prometheus` | Prometheus `http_sd` (`__param_module`, `__param_auth`, `snmp_tier`). One group per enabled tier. Optional `?shard=0&shards=4` (same hash as Prometheus `hashmod` on address). |
| `GET /healthz` | Liveness + catalog size |
| `--out-file-sd` | Same payload on disk for `file_sd_configs` |
| `--out-catalog` | YAML device list (one row per device; sibling `-cold` / `-topology` files) |

`--ping` (default true) needs `CAP_NET_RAW` or host `ping_group_range` in a container. `--ping=false` SNMP-probes every hole in the CIDR.

`--tiers` defaults to `hot,cold` (topology off). `--tiers=hot` is the minimum useful walk. `--tiers=all` publishes hot + cold + topology.

Point snmp_exporter at the **same** `snmp-network.yml` (or library + `auths.yml` overlay). Prometheus jobs keep `snmp_tier=hot` vs `cold` and rewrite `__address__` to the exporter. See [`examples/prometheus-snmp/prometheus.yml`](examples/prometheus-snmp/prometheus.yml).

Kubernetes shape (one discoverer, many walkers): [`docs/deploy.md`](docs/deploy.md).

## One catalog

`--snmp-config` and `--fingerprinters` must come from the **same convert**. Fingerprinter `module=` names missing from `modules:` in snmp.yml are dropped (`WARN dropping fingerprinter modules missing from snmp.yml`). Fail-closed, not a failed scan.

`--snmp-config` must define every auth **name** listed on the group. Community / v3 secrets never go in the group file or on SD labels.

`snmp_group` on each target is the group `name`, not a hostname-derived site.

## Library

`snmp/modules/<vendor>/*.yml` is the edit surface. Re-run convert only when ingesting a new Kentik vendor pack. Re-split: `python3 tools/snmp-profile-convert/split_vendor_tiers.py`. See [`tools/snmp-profile-convert/README.md`](tools/snmp-profile-convert/README.md).

| Module | Tier | Contents |
|---|---|---|
| `{name}` | hot | identity, uptime, CPU / CPULoad, RAM (plus `hrStorage` when RAM and disk share a table), core-service counts (firewall sessions, WLC client totals) |
| `{name}_sensors` | cold | chassis / temp / fans / PSU |
| `{name}_ext` | cold | leftover wide tables (per-tunnel / per-policy / NAT), separable disk MIBs, vendor IF extras |
| `{name}_bgp` / `{name}_topo` | topology | BGP-only leftover uses `_bgp`; mixed LLDP/CDP/OSPF/ISIS uses `_topo` |

No invented `{name}_hot`. The original `{name}` stays the fingerprint leaf.

Kentik attribution: [`snmp/NOTICE`](snmp/NOTICE). Apache-2.0. Metric names are `snmp_*`.

## Validated: colocated Clos

2026-09-08, ContainerLab `clab`, `examples/colocated-clos.yml` (`172.20.20.0/24`). Five SR Linux nodes, `sysObjectID=1.3.6.1.4.1.6527.1.20.26`:

| `device_name` | address | hot `module` |
|---|---|---|
| spine1 | 172.20.20.3 | `if_mib,nokia_srlinux` |
| leaf1 | 172.20.20.4 | `if_mib,nokia_srlinux` |
| leaf2 | 172.20.20.5 | `if_mib,nokia_srlinux` |
| leaf-br1 | 172.20.20.2 | `if_mib,nokia_srlinux` |
| leaf-br2 | 172.20.20.7 | `if_mib,nokia_srlinux` |

Cold: `if_mib_meta,ip_addr,nokia_srlinux_sensors,nokia_srlinux_ext`. Topology: `nokia_srlinux_bgp` (off unless `--tiers=all`). Scan: `found=5` in ~1s.

A later run of [`examples/prometheus-snmp/`](examples/prometheus-snmp/) walked those targets with **stock** `prom/snmp-exporter` and scraped them with Prometheus.

## What this is not

- Not a CIDR walker inside snmp_exporter
- Not an SNMP trap listener
- Not a replacement for [snmp_exporter#1468](https://github.com/prometheus/snmp_exporter/issues/1468) in-exporter fingerprinting — if that lands, SD can emit `fingerprint=` instead of a resolved `module=` list

## Other integrations

The default path is Prometheus + snmp_exporter. Other collectors that can consume Prometheus HTTP SD or a YAML target list live under [`examples/`](examples/) as separate use cases.

## License

Apache-2.0. Module OID lists are derived from kentik/snmp-profiles. Secrets: [`SECURITY.md`](SECURITY.md).
