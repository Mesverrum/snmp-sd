# Deploy with Prometheus and snmp_exporter

Assumes stock [Prometheus](https://prometheus.io/) and [snmp_exporter](https://github.com/prometheus/snmp_exporter). Discovery is a singleton. Walkers scale out.

## Processes

| Workload | Replicas | Why |
|---|---|---|
| `snmp-discovery` | **1** | One sweeper, one catalog. A second copy without shared state can serve an empty list and wipe Prometheus targets. |
| `snmp_exporter` | 1..N | Stateless. Same `--config.file`. Crash = miss at most one scrape interval. |
| Prometheus | your usual HA | Pulls SD; owns scrape intervals (hot vs cold). |

Discovery down does **not** stop walks. Prometheus keeps the last target list until the next SD refresh.

## Discovery

```bash
snmp-discovery \
  --config /etc/snmp-sd/discovery.yml \
  --snmp-config /etc/snmp-sd/snmp-network.yml \
  --fingerprinters /etc/snmp-sd/fingerprinters.yml \
  --listen :9780 \
  --interval 24h \
  --tiers hot,cold
```

Optional PVC for `*.state.json` so a replacement pod does not wait on a full sweep.

Readiness: `GET /healthz` (optionally require a non-zero catalog after the first scan).

## Exporter

```bash
snmp_exporter --config.file=/etc/snmp-sd/snmp-network.yml --snmp.module-concurrency=2
```

One Service in front of N identical replicas is enough until the host is saturated. Then shard.

## Shard the catalog (optional)

Discovery can slice targets (`hashmod` on address, same as Prometheus):

```text
GET /sd/prometheus?shard=0&shards=4
GET /sd/prometheus?shard=1&shards=4
…
```

Each Prometheus job pulls **one** shard and scrapes **one** exporter (or one Service). The exporter does not fetch SD and does not know about shards.

Equivalent with a single full catalog and Prometheus relabel:

```yaml
- source_labels: [__param_target]
  modulus: 4
  action: hashmod
  target_label: __tmp_shard
- source_labels: [__tmp_shard]
  regex: "0"
  action: keep
```

Hashmod spreads **devices**, not walk cost. Pin unusually slow boxes with discovery `overrides` if one shard is unlucky.

Worked overlay (second exporter + `?shard=0|1&shards=2`): [`examples/prometheus-snmp/compose.shard.yaml`](../examples/prometheus-snmp/compose.shard.yaml).

## Site isolation

Prefer a discovery **group** per CIDR / VRF and an exporter that can UDP/161 that network. That is usually the right split before hashmod.
