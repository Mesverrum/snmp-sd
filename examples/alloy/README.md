# Optional: Grafana Alloy

The rest of this repo assumes Prometheus + snmp_exporter. This directory is the **only** place that describes Alloy.

Alloy can consume the same discovery catalog in two ways:

1. **HTTP SD** — `discovery.http` against `GET /sd` (device rows: `name`, `module`, `auth`, `address`). Do not use `/sd/prometheus` here: `__param_*` labels leak onto series in `prometheus.exporter.snmp`.
2. **YAML files** — `snmp-discovery --out-catalog snmp-targets.yml` writes one row per device plus sibling `snmp-targets-cold.yml` / `snmp-targets-topology.yml` for staggered scrapes. `--out-alloy` is the same flag.

Auths stay in the same overlay as the OSS path (`auths.yml` or `SNMP_AUTHS`). River names blocks only (`auths = ["public_v2"]`); do not paste communities into Fleet.

The module library is this repo’s `snmp/snmp-network.yml`. Load it as `config_file` with `config_merge_strategy = "replace"` so stock embedded modules are not mixed in.

Do not drop admin-down interfaces in `prometheus.relabel` from the `ifAdminStatus` gauge value — the library already applies snmp_exporter `filters:` on `if_mib`.

A later cutover can import `github.com/Mesverrum/snmp-sd` as a Go module instead of a forked `internal/snmpdiscovery`. Until then, treat Alloy as a consumer of these outputs, not the source of truth.
