"""Vendor pack hot / cold / topology split."""
from __future__ import annotations

import unittest
from pathlib import Path

import yaml

import convert
from convert import (
    CISCO_RELATED_RE,
    classify_module,
    consolidate_topology_modules,
    lookup_type,
    lookups_from_tags,
    merge_topology_modules,
    metric_tier,
    partition_module_chain,
    split_vendor_family,
)


class LookupTypeTests(unittest.TestCase):
    def test_address_columns_render_dotted(self):
        saved = dict(convert.OID_SYNTAX)
        try:
            convert.OID_SYNTAX.clear()
            convert.OID_SYNTAX["1.3.6.1.4.1.6527.3.1.2.14.4.7.1.13"] = {
                "name": "tBgpPeerNgLocalAddress",
                "syntax": "InetAddress",
            }
            # snmp_exporter decodes a bare InetAddress value with the INDEX parser
            # (type.length.bytes) and renders garbage; IPv4 is the fixed-size type.
            self.assertEqual(
                lookup_type("tBgpPeerNgLocalAddress", "local_address", None, "1.3.6.1.4.1.6527.3.1.2.14.4.7.1.13"),
                "InetAddressIPv4",
            )
            # No SYNTAX row: the column name still says address.
            self.assertEqual(lookup_type("bgpPeerLocalAddr", "local_address", None, "1.3.6.1.2.1.15.3.1.5"), "InetAddressIPv4")
            self.assertEqual(lookup_type("tBgpPeerNgLocalAddressType", "local_address_type"), "DisplayString")
            self.assertEqual(lookup_type("ifPhysAddress", "if_MAC"), "DisplayString")
            self.assertEqual(lookup_type("tBgpPeerNgDescription", "peer_description"), "DisplayString")
            self.assertEqual(lookup_type("tBgpPeerNgLocalAS4Byte", "local_as"), "gauge")
        finally:
            convert.OID_SYNTAX.clear()
            convert.OID_SYNTAX.update(saved)

    def test_lookups_from_tags_passes_oid(self):
        saved = dict(convert.OID_SYNTAX)
        try:
            convert.OID_SYNTAX.clear()
            convert.OID_SYNTAX["1.3.6.1.4.1.6527.3.1.2.14.4.7.1.13"] = {"syntax": "InetAddress"}
            out = lookups_from_tags(
                [
                    {
                        "column": {"OID": "1.3.6.1.4.1.6527.3.1.2.14.4.7.1.13", "name": "tBgpPeerNgLocalAddress"},
                        "tag": "local_address",
                    }
                ],
                [{"labelname": "tBgpPeerNgAddress", "type": "InetAddress"}],
            )
            self.assertEqual(out[0]["type"], "InetAddressIPv4")
            self.assertEqual(out[0]["labelname"], "local_address")
        finally:
            convert.OID_SYNTAX.clear()
            convert.OID_SYNTAX.update(saved)


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

    def test_merge_topology_fragments_deduplicates_walks_and_metrics(self):
        merged = merge_topology_modules(
            ["vendor_topo", "lldp_mib"],
            {
                "vendor_topo": {
                    "walk": ["1.3.6.1.4.1.9", "1.0.8802.1.1.2"],
                    "metrics": [
                        {"name": "snmp_vendorPeer", "oid": "1.3.6.1.4.1.9.1"}
                    ],
                },
                "lldp_mib": {
                    "walk": ["1.0.8802.1.1.2"],
                    "metrics": [
                        {"name": "snmp_lldpRemSysName", "oid": "1.0.8802.1.1.2.1"}
                    ],
                },
            },
        )
        self.assertEqual(merged["walk"], ["1.3.6.1.4.1.9", "1.0.8802.1.1.2"])
        self.assertEqual(
            [m["name"] for m in merged["metrics"]],
            ["snmp_vendorPeer", "snmp_lldpRemSysName"],
        )

    def test_consolidate_topology_modules_selects_one_object(self):
        modules = {
            "device_base": {"metrics": []},
            "if_mib": {"metrics": []},
            "if_mib_meta": {"metrics": []},
            "ip_addr": {"metrics": []},
            "nokia_srlinux": {"metrics": [{"name": "snmp_CPU", "oid": "1.2.3"}]},
            "nokia_srlinux_topo": {
                "walk": ["1.3.6.1.4.1.6527"],
                "metrics": [{"name": "snmp_tBgpPeer", "oid": "1.3.6.1.4.1.6527.1"}],
            },
            "lldp_mib": {
                "walk": ["1.0.8802.1.1.2"],
                "metrics": [{"name": "snmp_lldpRemSysName", "oid": "1.0.8802.1.1.2.1"}],
            },
        }
        index = {
            "modules": {
                "device_base": {
                    "profile": "device-base.yml",
                    "vendor": "_general",
                    "sysobjectids": [],
                    "extends": [],
                },
                "if_mib": {
                    "profile": "if-mib.yml",
                    "vendor": "_general",
                    "sysobjectids": [],
                    "extends": [],
                },
                "if_mib_meta": {
                    "profile": "if-mib-meta.yml",
                    "vendor": "_general",
                    "sysobjectids": [],
                    "extends": [],
                },
                "ip_addr": {
                    "profile": "ip-addr.yml",
                    "vendor": "_general",
                    "sysobjectids": [],
                    "extends": [],
                },
                "lldp_mib": {
                    "profile": "lldp-mib.yml",
                    "vendor": "_general",
                    "sysobjectids": [],
                    "extends": [],
                },
                "nokia_srlinux": {
                    "profile": "nokia-srlinux.yml",
                    "vendor": "nokia",
                    "sysobjectids": ["1.3.6.1.4.1.6527.1.20.26"],
                    "extends": ["if-mib.yml"],
                },
                "nokia_srlinux_topo": {
                    "profile": "nokia-srlinux-topo.yml",
                    "vendor": "nokia",
                    "sysobjectids": [],
                    "extends": [],
                },
            }
        }
        count = consolidate_topology_modules(modules, index)
        self.assertEqual(count, 2)
        self.assertEqual(
            index["modules"]["nokia_srlinux"]["module_chain_topology"],
            ["nokia_srlinux_topo"],
        )
        self.assertEqual(
            index["modules"]["nokia_srlinux_topo"]["topology_fragments"],
            ["nokia_srlinux_topo", "lldp_mib"],
        )
        names = [m["name"] for m in modules["nokia_srlinux_topo"]["metrics"]]
        self.assertEqual(names, ["snmp_tBgpPeer", "snmp_lldpRemSysName"])

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

    def test_default_topology_is_one_consolidated_object(self):
        self.assertEqual(self.fp["default_modules_topology"], ["device_base_topo"])

    def test_every_tiered_matcher_has_one_topology_object(self):
        invalid = []
        for m in self.fp["matchers"]:
            if not (m.get("modules_hot") or m.get("modules_cold") or m.get("modules_topology")):
                continue
            topology = m.get("modules_topology") or []
            if len(topology) != 1 or not topology[0].endswith("_topo"):
                invalid.append((m.get("comment") or m.get("regex"), topology))
        self.assertEqual(invalid[:5], [], msg=f"{len(invalid)} invalid topology chains")

    def test_cisco_meraki_topology_objects_fold_cdp(self):
        modules = {}
        repo = Path(__file__).resolve().parents[2]
        network = yaml.safe_load(
            (repo / "snmp" / "snmp-network.yml").read_text(encoding="utf-8")
        )
        modules.update(network["modules"])
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
            topology = m.get("modules_topology") or []
            if len(topology) != 1:
                missing.append(m.get("comment") or m.get("regex"))
                continue
            metric_names = {
                str(metric.get("name") or "")
                for metric in modules[topology[0]].get("metrics") or []
            }
            if "snmp_cdpCacheDeviceId" not in metric_names:
                missing.append(m.get("comment") or m.get("regex"))
        self.assertEqual(missing[:5], [], msg=f"{len(missing)} cisco/meraki matchers missing cdp_mib")


if __name__ == "__main__":
    unittest.main()
