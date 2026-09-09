#!/usr/bin/env bash
# Verify snmp-sd → stock snmp_exporter → Prometheus.
set -euo pipefail

export SD_URL="${SD_URL:-http://127.0.0.1:19780}"
export EXP_URL="${EXP_URL:-http://127.0.0.1:19116}"
export PROM_URL="${PROM_URL:-http://127.0.0.1:19090}"
TARGET="${TARGET:-172.20.20.4}"

need() { command -v "$1" >/dev/null || { echo "need $1"; exit 1; }; }
need curl
need python3

echo "==> discovery healthz"
hz="$(curl -fsS "${SD_URL}/healthz")"
echo "    ${hz}"
echo "${hz}" | grep -q 'targets' || { echo "FAIL healthz"; exit 1; }

echo "==> /sd/prometheus tiers"
python3 - <<'PY'
import json, os, sys, urllib.request
url = os.environ["SD_URL"] + "/sd/prometheus"
raw = urllib.request.urlopen(url, timeout=15).read()
groups = json.loads(raw)
blob = json.dumps(groups)
if "community" in blob:
    print("FAIL community leaked")
    sys.exit(1)
tiers = {}
for g in groups:
    labels = g.get("labels") or {}
    if labels.get("__param_auth") != "public_v2":
        print("FAIL auth", labels)
        sys.exit(1)
    tiers[labels.get("snmp_tier")] = tiers.get(labels.get("snmp_tier"), 0) + 1
print("    groups", len(groups), "by_tier", tiers)
if tiers.get("hot", 0) < 1 or tiers.get("cold", 0) < 1:
    print("FAIL need hot and cold targets")
    sys.exit(1)
PY

HOT_MOD="if_mib,nokia_srlinux"
COLD_MOD="if_mib_meta,ip_addr,nokia_srlinux_sensors,nokia_srlinux_ext"

echo "==> snmp_exporter hot ${TARGET} module=${HOT_MOD}"
hot="$(curl -fsS --max-time 60 "${EXP_URL}/snmp?target=${TARGET}&auth=public_v2&module=${HOT_MOD}")"
echo "${hot}" | grep -m 3 -E '^snmp_CPU[{ ]' || true
echo "${hot}" | grep -qE '^snmp_CPU[{ ]' || { echo "FAIL missing snmp_CPU"; echo "${hot}" | tail -20; exit 1; }

echo "==> snmp_exporter cold ${TARGET} module=${COLD_MOD}"
cold="$(curl -fsS --max-time 90 "${EXP_URL}/snmp?target=${TARGET}&auth=public_v2&module=${COLD_MOD}")"
echo "${cold}" | grep -m 5 -E '^snmp_(Temperature|ifName|ipAdEntIfIndex|tmnxHwOperState)\{' || true
if ! echo "${cold}" | grep -qE '^snmp_(Temperature|ifName|tmnxHwOperState|ipAdEntIfIndex)\{'; then
  echo "FAIL cold walk returned no expected series"
  echo "${cold}" | tail -30
  exit 1
fi

echo "==> prometheus scrape jobs"
python3 - <<'PY'
import json, os, sys, urllib.request
url = os.environ["PROM_URL"] + "/api/v1/targets"
body = json.loads(urllib.request.urlopen(url, timeout=15).read())
active = body.get("data", {}).get("activeTargets") or []
jobs = {}
up = 0
for t in active:
    job = t.get("labels", {}).get("job", "?")
    jobs[job] = jobs.get(job, 0) + 1
    if t.get("health") == "up":
        up += 1
print("    active", len(active), "up", up, "jobs", jobs)
if "snmp-hot" not in jobs or "snmp-cold" not in jobs:
    print("FAIL expected snmp-hot and snmp-cold")
    sys.exit(1)
PY

echo "==> prometheus snmp_CPU / snmp_Temperature"
python3 - <<'PY'
import json, os, sys, time, urllib.parse, urllib.request
base = os.environ["PROM_URL"]

def query(expr):
    q = urllib.parse.urlencode({"query": expr})
    raw = urllib.request.urlopen(base + "/api/v1/query?" + q, timeout=20).read()
    body = json.loads(raw)
    return body.get("data", {}).get("result") or []

deadline = time.time() + 150
cpu = []
temp = []
while time.time() < deadline:
    cpu = query("count by (device_name, job) (snmp_CPU)")
    temp = query("count by (device_name, job) (snmp_Temperature)")
    if len(cpu) >= 5:
        break
    time.sleep(8)

print("    snmp_CPU series", len(cpu))
for r in cpu:
    print("     ", r.get("metric"), r.get("value", [None, ""])[1])
print("    snmp_Temperature series", len(temp))
for r in temp:
    print("     ", r.get("metric"), r.get("value", [None, ""])[1])
if len(cpu) < 5:
    print("FAIL expected 5 snmp_CPU devices, got", len(cpu))
    sys.exit(1)
print("OK prometheus has hot CPU for the Clos")
PY

echo "==> OK snmp-sd → snmp_exporter → Prometheus"
