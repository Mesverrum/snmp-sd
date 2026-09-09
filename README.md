# snmp-sd

Find SNMP devices on your network and hand them to [Prometheus](https://prometheus.io/) plus the usual [snmp_exporter](https://github.com/prometheus/snmp_exporter).

`snmp_exporter` is good at walking a known device. It is not good at answering “what is on this subnet, and which YAML module should I use?” That is what this repo does. You point discovery at a CIDR (a range of addresses, like `172.20.20.0/24`), it probes hosts that speak SNMP, and it publishes a target list Prometheus already understands.

The device-family modules (Cisco, Juniper, Nokia, Aruba, and a few hundred others) ship in the box. Use them as they are. You should not need to edit module YAML or run any converter for a normal install. If a box is missing from that map, or you want extra OIDs on a box that is already mapped, skip to [A device the library does not cover](#a-device-the-library-does-not-cover-or-oids-you-want-to-add).

A Compose stack that wires this CLI, stock `snmp_exporter`, and Prometheus is in [`examples/prometheus-snmp/`](examples/prometheus-snmp/).

## How the pieces fit

Prometheus scrapes HTTP endpoints. Network devices speak SNMP, not Prometheus, so you run `snmp_exporter` next to them. Prometheus hits something like:
```text
http://snmp-exporter:9116/snmp?target=192.0.2.10&auth=public_v2&module=if_mib,nokia_srlinux
```

- `target` is the device.
- `auth` is the **name** of a credential block (community string or SNMPv3 user). The password itself never appears on this URL or on the time series.
- `module` is which OID walks to run (interface counters, CPU, and so on).

Service discovery (often shortened to **SD**) is how Prometheus learns those three values. This process either writes a JSON file Prometheus can watch (`file_sd`) or serves the same list over HTTP (`http_sd` at `/sd/prometheus`).

```text
your subnets  →  snmp-discovery  →  Prometheus SD  →  snmp_exporter  →  metrics in Prometheus
```

## The two files you actually write

Everything else in `snmp/` is already built. You write (1) secrets and (2) where to look. The **same names** appear in both files. `snmp-discovery init` fills them in together so you do not typo `public_v2` in one place and `pubic_v2` in the other.

```bash
snmp-discovery init
# or:
snmp-discovery init \
  --auth-v2 public_v2=public \
  --group lab,cidrs=172.20.20.0/24,auths=public_v2
snmp-discovery init --check
```

**`auths.yml`** is the secret file (mode `0600`, keep it out of git). A community string is the SNMPv2 shared password a lot of labs still use:

```yaml
auths:
  public_v2:
    version: 2
    community: public
```

SNMPv3 looks the same except the block has a username and keys instead of `community`. More shapes are in [`snmp/auths.example.yml`](snmp/auths.example.yml).

**`discovery.yml`** only lists those names. It never holds the community:

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

`fingerprinter: network` means “use the shipped vendor map.” You do not create that map. After a successful SNMP probe, discovery reads the device’s `sysObjectID` (the vendor/model identifier every agent exposes) and fills in `module` for you.

A group can list more than one auth. Discovery tries them in order, which is handy when a subnet is a mix of v2c and v3.

The image already includes a `public_v2` / `public` pair for a throwaway lab. Use `init` (or your own overlay) as soon as the community is real.

## Build and run

```bash
go test ./...
go build -o snmp-discovery ./cmd/snmp-discovery
```

Linux static binary: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o snmp-discovery ./cmd/snmp-discovery`.

The default `Dockerfile` builds the binary **and** copies the module library into the image. That is the one you want. `Dockerfile.linux` is only a tiny scratch wrapper around a binary you already compiled; it does not include `snmp/`.

Discovery has to be able to reach the devices: ICMP if you leave ping on, and UDP/161 for SNMP. If you run it on a host that cannot see that subnet, the catalog stays empty. That is a routing/namespace problem, not a “modules are wrong” problem.

```bash
./snmp-discovery \
  --config discovery.yml \
  --snmp-config snmp/snmp-network.yml \
  --fingerprinters snmp/fingerprinters.yml \
  --out-file-sd snmp-file-sd.json \
  --listen :9780 \
  --interval 24h \
  --tiers hot,cold \
  --ping --timeout 2s --retries 1 --concurrency 16
```

`--listen :9780` keeps an HTTP server up so Prometheus can poll `/sd/prometheus`. `--interval 24h` is “rescan the subnets once a day”; `0` means run once and exit (unless you also set `--listen`).

`--ping` (on by default) skips addresses that do not answer ICMP, which keeps a `/24` scan short. In a container that needs `CAP_NET_RAW`, or you can set `--ping=false` and SNMP-probe every address instead.

Give `snmp_exporter` the same `snmp/snmp-network.yml` (plus your `auths.yml` merged in). Prometheus jobs then rewrite each target’s address to the exporter and keep `auth` / `module` as URL parameters. [`examples/prometheus-snmp/prometheus.yml`](examples/prometheus-snmp/prometheus.yml) is a full scrape config.

Running this on Kubernetes: one discovery pod, as many exporters as you need. Notes in [`docs/deploy.md`](docs/deploy.md).

## What “hot” and “cold” are

A full vendor walk is a lot of OIDs. Doing all of it every minute is how you melt a box (or the collector). Discovery therefore publishes the same device more than once, with a `snmp_tier` label:

| How often (you choose in Prometheus) | Tier | What you usually put there |
|---|---|---|
| ~60s | `hot` | Link counters, oper status, CPU, memory, “is the box doing its job” totals |
| a few minutes | `cold` | Interface names and MACs, sensors, wide leftover tables |
| only if you ask | `topology` | LLDP / CDP neighbors, BGP / OSPF / ISIS tables |

`--tiers` defaults to `hot,cold`. `--tiers=hot` is enough to see traffic and CPU. `--tiers=all` also publishes topology. BGP flaps and link-down still belong in traps or syslog; polling will not catch them in time.

Each enabled tier is its own Prometheus target, so you can scrape hot every minute and cold every five without walking sensors on the hot interval.

## Small things that surprise people

- **Secrets stay in `auths.yml` / the exporter config.** SD only emits the auth **name**. If a community shows up in Prometheus labels, something is wrong.
- **`snmp_group` is the group `name` you wrote** (`lab`, `dc1`, …), not a guess from the hostname.
- **`--snmp-config` and `--fingerprinters` should be the copies from this repo.** They were generated together. If you mix an old map with a new library, unknown module names are dropped and that device walks less than you expect (you will see a WARN in the log). The scan itself still succeeds.
- **`--out-catalog`** is a plain YAML device list if you would rather not use HTTP SD.

## A Clos we actually swept

On 2026-09-08 this CLI ran against a ContainerLab fabric on `172.20.20.0/24` (`examples/colocated-clos.yml`). Five Nokia SR Linux nodes (`sysObjectID=1.3.6.1.4.1.6527.1.20.26`) came back in about a second:

| `device_name` | address | hot modules |
|---|---|---|
| spine1 | 172.20.20.3 | `if_mib,nokia_srlinux` |
| leaf1 | 172.20.20.4 | `if_mib,nokia_srlinux` |
| leaf2 | 172.20.20.5 | `if_mib,nokia_srlinux` |
| leaf-br1 | 172.20.20.2 | `if_mib,nokia_srlinux` |
| leaf-br2 | 172.20.20.7 | `if_mib,nokia_srlinux` |

Cold on those boxes was `if_mib_meta,ip_addr,nokia_srlinux_sensors,nokia_srlinux_ext`. Topology (`nokia_srlinux_bgp`) stays off unless you pass `--tiers=all`. The same targets were then walked with stock `prom/snmp-exporter` and scraped by Prometheus; see [`examples/prometheus-snmp/`](examples/prometheus-snmp/).

## A device the library does not cover, or OIDs you want to add

Two common cases, same tools:

1. **The box is not in the vendor map.** Discovery still finds it (`if_mib` / `device_base` and whatever else the default fingerprint allows). Interface counters work. Vendor CPU, sensors, or custom tables do not, because nothing asked for those OIDs.
2. **The box is already mapped**, but you want a table the shipped module skipped, or a different column on a table it already walks.

Do not start from a MIB compiler, and do not edit the files under `snmp/modules`. Take a **numeric** dump of the whole device, see what we already scrape, then emit a **local overlay** you merge next to the library.

```bash
snmpwalk -On -v2c -c public 192.0.2.10 1.3.6.1 > box.walk
snmp-discovery walk-catalog --file box.walk
```

`1.3.6.1` is mib-2 plus enterprises — everything people usually mean by “the whole box.” Chunking by vendor branch is how you miss HOST-RESOURCES or a table you did not know to name. If the agent times out or hangs, cut the dump at that point and walk the remaining branches; `--oid` / `--prefix` are for that recovery, not the happy path.

The catalog groups single values vs tables, says how many numbers are in the index, and **hides OIDs the library already scrapes**. That is the interesting part for case 2: the leftover list is what you would actually add. `--show-covered` prints the hidden rows too (useful when you want to change a name or confirm IF-MIB is already there). Live walk: `snmp-discovery walk-catalog --target 192.0.2.10 --auth public_v2`.

Then draft a shopping list, edit it, and emit one module:

```bash
snmp-discovery walk-pick --file box.walk --out pick.yml
# edit pick.yml: delete rows you do not want, rename `name` fields (those become snmp_*)
snmp-discovery walk-emit --pick pick.yml --out mymodule.yml
```

`walk-catalog --write-pick pick.yml` prints the catalog and writes the same draft. STRING columns become labels; numbers become metrics. Index labels are `index` or `index_1`…`index_N`. The overlay walks **column** OIDs (not the parent table) and lists the full index. `walk-emit` warns if a pick is already in the library — keep those only if you really want a second scrape.

Merge `mymodule.yml` the same way you merge `auths.yml`: into the exporter `--config.file`. Leave `snmp/modules` alone.

Discovery will not invent the new module name on its own. Pin it on that address (copy the modules the fingerprint already chose, then add yours):

```yaml
overrides:
  - address: 192.0.2.10
    module_hot: if_mib,local_99999
    module_cold: if_mib_meta,ip_addr
```

The `sysobjectid` comment at the top of `mymodule.yml` is a reminder of which model this overlay was walked from. It is not a new fingerprint entry.

## What this is not

It does not listen for SNMP traps. It does not walk a CIDR *inside* `snmp_exporter`. If SuperQ’s in-exporter fingerprinting ([#1468](https://github.com/prometheus/snmp_exporter/issues/1468)) ships, discovery can start emitting a `fingerprint=` hint instead of a resolved module list; until then we resolve modules here.

## Other integrations

The path above is Prometheus + `snmp_exporter`. If you run [Grafana Alloy](https://github.com/grafana/alloy) instead, the same catalog works; notes are in [`examples/alloy/`](examples/alloy/). Alloy should call `GET /sd` (one row per device). Do not point it at `/sd/prometheus` — those `__param_*` labels leak onto every series.

## License

Apache-2.0. Module OID lists come from [kentik/snmp-profiles](https://github.com/kentik/snmp-profiles); see [`snmp/NOTICE`](snmp/NOTICE). How we treat secrets: [`SECURITY.md`](SECURITY.md).
