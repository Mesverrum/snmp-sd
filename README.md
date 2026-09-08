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

Static Linux binary (ContainerLab / EC2):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o snmp-discovery ./cmd/snmp-discovery
```

`Dockerfile.linux` wraps that binary in `scratch` (`ENTRYPOINT /snmp-discovery`).

## Run it on the same network as the devices

The process must be able to ICMP (optional) and SNMP GET `sysObjectID` on the CIDR. A laptop that cannot reach ContainerLab mgmt will write an empty catalog.

On a host that has the `clab` bridge, attach the binary to that network. Scratch image (`docker build -f Dockerfile.linux -t snmp-sd:linux .` after the static build above):

```bash
docker run --rm --network clab --user 0:0 --cap-add NET_RAW \
  -v "$PWD:/work" snmp-sd:linux \
  --config /work/examples/colocated-clos.yml \
  --snmp-config /work/snmp/snmp-network.yml \
  --fingerprinters /work/snmp/fingerprinters.yml \
  --out-alloy /work/snmp-targets.yml \
  --out-file-sd /work/snmp-file-sd.json \
  --ping --timeout 2s --retries 1 --concurrency 16
```

A laptop or host namespace that cannot UDP/161 the CIDR writes an empty catalog. Do not treat that as a fingerprinter failure.

`--ping` (default true) needs `CAP_NET_RAW` or host `ping_group_range` in a container. `--ping=false` SNMP-probes every hole in the CIDR (fine for a `/24`, noisy for a `/22`).

`--interval 0` is one-shot unless `--listen` is set. Production cadence is hours (`--interval 24h`).

## One catalog

`--snmp-config` and `--fingerprinters` must come from the **same convert**. Fingerprinter `module=` names that are missing from `modules:` in `snmp.yml` are dropped (`WARN dropping fingerprinter modules missing from snmp.yml`). That is fail-closed, not a failed scan.

Do not mix this repo’s `fingerprinters.yml` with an older image `snmp-network.yml` (or the reverse). Convert must not invent sidecars such as `nokia_srlinux_hot` unless that file exists under `snmp/modules/`.

`--snmp-config` must define every auth **name** listed on the group (`public_v2` for the lab). If your concat has no top-level `auths:`, prepend `snmp/auths.example.yml` (copy to a gitignored `auths.yml` and edit). Community / v3 secrets never go in the group file or on SD labels.

`snmp_group` on each target is the **group `name`**, not a site inferred from the hostname.

## Outputs

| Path | Consumer |
|---|---|
| `--out-file-sd` / `GET /sd/prometheus` | Prometheus `file_sd` / `http_sd` (`__param_target`, `__param_auth`, `__param_module`) |
| `--out-alloy` / `GET /sd` | Alloy `discovery.http` → `prometheus.exporter.snmp` |
| `GET /healthz` | Liveness |

Hosts that ping but do not answer the identity GET increment `probe_errors` and stay out of the catalog (lab clients, printers without `public`).

## Validated: colocated Clos

2026-09-08, AWS colocated ContainerLab, `examples/colocated-clos.yml` (`172.20.20.0/24` sweep). Five SR Linux nodes, `sysObjectID=1.3.6.1.4.1.6527.1.20.26`:

| `device_name` | address | `module` |
|---|---|---|
| spine1 | 172.20.20.3 | `if_mib,nokia_srlinux` |
| leaf1 | 172.20.20.4 | `if_mib,nokia_srlinux` |
| leaf2 | 172.20.20.5 | `if_mib,nokia_srlinux` |
| leaf-br1 | 172.20.20.2 | `if_mib,nokia_srlinux` |
| leaf-br2 | 172.20.20.7 | `if_mib,nokia_srlinux` |

Scan log from that run: `found=5` in ~1s, `ping_up=11`, `probe_errors=6` (non-SNMP ICMP hits), `dropped=0`. `nokia_srlinux_hot` on an older image fingerprinter file was WARNed and dropped; published `module=` stayed `if_mib,nokia_srlinux`.

## Library

`snmp/modules/<vendor>/*.yml` is the edit surface. Re-run convert only when ingesting a new Kentik vendor pack. See [`tools/snmp-profile-convert/README.md`](tools/snmp-profile-convert/README.md).

Kentik attribution: [`snmp/NOTICE`](snmp/NOTICE). Apache-2.0. Metric names are `snmp_*`, not `kentik_snmp_*`. This is not a ktranslate name-parity contract.

## What this is not

- Not a CIDR walker inside `snmp_exporter`
- Not an SNMP trap listener
- Not a replacement for [snmp_exporter#1468](https://github.com/prometheus/snmp_exporter/issues/1468) in-exporter fingerprinting — if that lands, SD can emit `fingerprint=` instead of a resolved `module=` list

## License

Apache-2.0. Discovery code started in [Mesverrum/alloy](https://github.com/Mesverrum/alloy). Module OID lists are derived from kentik/snmp-profiles.
