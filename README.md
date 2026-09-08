# snmp-sd

Prometheus-shaped **SNMP service discovery** plus a curated **snmp_exporter module library**.

This repo is the source of truth. Grafana Alloy `discovery.snmp` and the lab overlay image are consumers. Stock [prometheus/snmp_exporter](https://github.com/prometheus/snmp_exporter) stays the walker.

| Piece | What it does |
|---|---|
| `snmp-discovery` CLI | CIDR sweep + optional LLDP/CDP crawl + sticky catalog |
| Fingerprinters | `sysObjectID` → `module=` at **SD time** (SuperQ [#1468](https://github.com/prometheus/snmp_exporter/issues/1468) matcher shape) |
| `snmp/modules/` | Converted device-family modules (edit these) |
| `snmp/snmp-network.yml` | Concat for a single `snmp_exporter` `config_file` |
| `tools/snmp-profile-convert/` | One-shot ingest from [kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) |

The exporter does not find devices. Discovery emits targets with named `auth` and a resolved `module` list. Secrets never appear on SD labels.

```text
/snmp?target=192.0.2.10&auth=public_v2&module=if_mib,nokia_srlinux
```

## Build

```bash
go test ./...
go build -o snmp-discovery ./cmd/snmp-discovery
```

```bash
./snmp-discovery \
  --config examples/discovery.yml \
  --snmp-config snmp/snmp-network.yml \
  --fingerprinters snmp/fingerprinters.yml \
  --out-alloy snmp-targets.yml \
  --out-file-sd snmp-file-sd.json \
  --listen :9780 \
  --interval 24h
```

`--interval 0` is one-shot unless `--listen` is set.

## Outputs

| Path | Consumer |
|---|---|
| `--out-file-sd` / `GET /sd/prometheus` | Prometheus `file_sd` / `http_sd` (`__param_target`, `__param_auth`, `__param_module`) |
| `--out-alloy` / `GET /sd` | Alloy `discovery.http` → `prometheus.exporter.snmp` |
| `GET /healthz` | Liveness |

Copy `snmp/auths.example.yml` to a local `auths.yml` (gitignored). Named auths in the group file must exist in `--snmp-config` or that overlay.

## Library

`snmp/modules/<vendor>/*.yml` is the edit surface. Re-run convert only when ingesting a new Kentik vendor pack. See [`tools/snmp-profile-convert/README.md`](tools/snmp-profile-convert/README.md).

Kentik attribution: [`snmp/NOTICE`](snmp/NOTICE). Apache-2.0. Metric names are `snmp_*`, not `kentik_snmp_*`. This is not a ktranslate name-parity contract.

## What this is not

- Not a CIDR walker inside `snmp_exporter`
- Not an SNMP trap listener
- Not a replacement for [snmp_exporter#1468](https://github.com/prometheus/snmp_exporter/issues/1468) in-exporter fingerprinting — if that lands, SD can emit `fingerprint=` instead of a resolved `module=` list

## License

Apache-2.0. Discovery code started in [Mesverrum/alloy](https://github.com/Mesverrum/alloy). Module OID lists are derived from kentik/snmp-profiles.
