"""Vendor pack hot / cold / topology split."""
from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from convert import (
    CISCO_RELATED_RE,
    classify_module,
    metric_tier,
    partition_module_chain,
    split_vendor_family,
)


class VendorTierTests(unittest.TestCase):
    def test_metric_tier_vitals_and_sensors(self):
        self.assertEqual(metric_tier({"name": "snmp_CPU"})[0], "hot")
        self.assertEqual(metric_tier({"name": "snmp_CPULoad"})[0], "hot")
        self.assertEqual(metric_tier({"name": "snmp_MemoryUsed"})[0], "hot")
        self.assertEqual(metric_tier({"name": "snmp_Temperature"})[0], "sensor")
        self.assertEqual(metric_tier({"name": "snmp_cpuTemp"})[0], "sensor")
        self.assertEqual(metric_tier({"name": "snmp_tBgpPeerNgConnState"})[0], "topology")
        self.assertEqual(metric_tier({"name": "snmp_cbgpPeer2State"})[0], "topology")
        self.assertEqual(metric_tier({"name": "snmp_hrSystemProcesses"})[0], "ext")
        self.assertEqual(metric_tier({"name": "snmp_panSessionActive"})[0], "hot")
        self.assertEqual(metric_tier({"name": "snmp_fgSysSesCount"})[0], "hot")
        self.assertEqual(metric_tier({"name": "snmp_sonicDpiSslConnCountCur"})[0], "hot")
        self.assertEqual(
            metric_tier({"name": "snmp_hwNatSessionSrcLocalAddr"})[0],
            "ext",
        )
        kind, flag = metric_tier({"name": "snmp_hrStorageUsed"})
        self.assertEqual(kind, "hot")
        self.assertIsNone(flag)
        self.assertEqual(metric_tier({"name": "snmp_hrSystemNumUsers"})[0], "ext")

    def test_split_vendor_family_three_ways(self):
        parts = split_vendor_family(
            "cisco_all_devices",
            {
                "walk": ["1.3.6.1.4.1.9.9.109", "1.3.6.1.4.1.9.9.13", "1.3.6.1.4.1.9.9.187"],
                "metrics": [
                    {"name": "snmp_CPU", "oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.7"},
                    {"name": "snmp_Temperature", "oid": "1.3.6.1.4.1.9.9.13.1.3.1.3"},
                    {"name": "snmp_cbgpPeer2State", "oid": "1.3.6.1.4.1.9.9.187.1.2.1.1.7"},
                    {"name": "snmp_cieIfResetCount", "oid": "1.3.6.1.4.1.9.9.276.1.1.2.1.1"},
                ],
            },
        )
        self.assertEqual(
            [m["name"] for m in parts["cisco_all_devices"]["metrics"]],
            ["snmp_CPU"],
        )
        self.assertIn("cisco_all_devices_sensors", parts)
        self.assertIn("cisco_all_devices_ext", parts)
        self.assertIn("cisco_all_devices_topo", parts)
        self.assertEqual(
            [m["name"] for m in parts["cisco_all_devices_sensors"]["metrics"]],
            ["snmp_Temperature"],
        )
        self.assertEqual(
            [m["name"] for m in parts["cisco_all_devices_ext"]["metrics"]],
            ["snmp_cieIfResetCount"],
        )

    def test_partition_attaches_sidecars(self):
        known = {
            "if_mib",
            "if_mib_meta",
            "ip_addr",
            "lldp_mib",
            "cdp_mib",
            "cisco_all_devices",
            "cisco_all_devices_sensors",
            "cisco_all_devices_ext",
            "cisco_all_devices_topo",
        }
        tiers = partition_module_chain(["if_mib", "cisco_all_devices"], known)
        self.assertEqual(tiers["hot"], ["if_mib", "cisco_all_devices"])
        self.assertIn("cisco_all_devices_sensors", tiers["cold"])
        self.assertIn("cisco_all_devices_ext", tiers["cold"])
        self.assertEqual(
            tiers["topology"],
            ["cisco_all_devices_topo", "lldp_mib", "cdp_mib"],
        )

    def test_partition_lldp_on_non_cisco(self):
        known = {
            "if_mib",
            "if_mib_meta",
            "ip_addr",
            "lldp_mib",
            "cdp_mib",
            "nokia_srlinux",
            "nokia_srlinux_topo",
        }
        tiers = partition_module_chain(["if_mib", "nokia_srlinux"], known)
        self.assertEqual(tiers["topology"], ["nokia_srlinux_topo", "lldp_mib"])
        self.assertNotIn("cdp_mib", tiers["topology"])

    def test_classify_vitals_only_leaf(self):
        self.assertEqual(
            classify_module("zyxel_switch", hot_leaves={"zyxel_switch"}),
            "hot",
        )


class ShippedCatalogTests(unittest.TestCase):
    """Load snmp/fingerprinters.yml so convert CI fails if coverage drifts."""

    @classmethod
    def setUpClass(cls):
        repo = Path(__file__).resolve().parents[2]
        data = yaml.safe_load(
            (repo / "snmp" / "fingerprinters.yml").read_text(encoding="utf-8")
        )
        cls.fp = data["fingerprinters"]["network"]

    def test_default_topology_is_lldp(self):
        self.assertIn("lldp_mib", self.fp["default_modules_topology"])

    def test_every_tiered_matcher_has_lldp(self):
        missing = []
        for m in self.fp["matchers"]:
            if not (m.get("modules_hot") or m.get("modules_cold") or m.get("modules_topology")):
                continue
            if "lldp_mib" not in (m.get("modules_topology") or []):
                missing.append(m.get("comment") or m.get("regex"))
        self.assertEqual(missing[:5], [], msg=f"{len(missing)} matchers missing lldp_mib")

    def test_cisco_meraki_matchers_have_cdp(self):
        missing = []
        for m in self.fp["matchers"]:
            names = [
                *(m.get("modules") or []),
                *(m.get("modules_hot") or []),
                *(m.get("modules_cold") or []),
                *(m.get("modules_topology") or []),
            ]
            if not any(CISCO_RELATED_RE.search(str(n) or "") for n in names):
                continue
            if "cdp_mib" not in (m.get("modules_topology") or []):
                missing.append(m.get("comment") or m.get("regex"))
        self.assertEqual(missing[:5], [], msg=f"{len(missing)} cisco/meraki matchers missing cdp_mib")


if __name__ == "__main__":
    unittest.main()
