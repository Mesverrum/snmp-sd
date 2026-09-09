# snmp-sd → snmp_exporter → Prometheus

Worked stack: this repo’s CLI, stock [prometheus/snmp_exporter](https://github.com/prometheus/snmp_exporter), Prometheus via HTTP SD.

```text
CIDR sweep  →  snmp-discovery :9780/sd/prometheus
                    ↓  __param_target / __param_module / __param_auth
               snmp_exporter :9116/snmp
                    ↓
               Prometheus  (job snmp-hot @ 60s, snmp-cold @ 2m)
```

Community / v3 secrets stay in `snmp/snmp-network.yml` (`auths.public_v2`). SD never emits them.

## Run on the colocated Clos

The process must share L2/L3 with `172.20.20.0/24` (ContainerLab network `clab`):

```bash
docker build -t snmp-sd:lab .
export SNMP_SD_IMAGE=snmp-sd:lab
docker compose -f examples/prometheus-snmp/compose.yaml up -d
bash examples/prometheus-snmp/check.sh
```

Expect five devices (`spine1`, `leaf1`, `leaf2`, `leaf-br1`, `leaf-br2`):

| Check | What it proves |
|---|---|
| `GET /healthz` | discovery catalog is 5 devices |
| `GET /sd/prometheus` | hot + cold groups, `__param_module` set, no community |
| `GET /snmp?module=if_mib,nokia_srlinux` | stock exporter walks this library |
| PromQL `count by (device_name) (snmp_CPU)` | Prometheus scraped hot |
| `snmp_Temperature` on `job=snmp-cold` | cold tier is a separate scrape |

UI: Prometheus http://127.0.0.1:19090 (published from the host).

Tear down: `docker compose -f examples/prometheus-snmp/compose.yaml down`.

## Optional: two exporters (shard)

Same discovery process. Prometheus pulls `?shard=0&shards=2` and `?shard=1&shards=2` and scrapes one exporter per shard:

```bash
docker compose -f examples/prometheus-snmp/compose.yaml \
  -f examples/prometheus-snmp/compose.shard.yaml up -d
```

See [`docs/deploy.md`](../../docs/deploy.md).
