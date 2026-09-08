"""snmp_device_info folding — one info metric per scrape, no system_mib sibling."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from convert import (
    SKIP_PROFILE_FILES,
    build_fingerprinters,
    device_info_label,
    discover_profiles,
    fold_device_identity,
    identity_lookup_from_tag,
    inject_device_identity,
    skipped_extends,
)


class DeviceInfoLabel(unittest.TestCase):
    def test_snmpv2_canonical(self):
        self.assertEqual(device_info_label("SysDescr", "sysDescr", "1.3.6.1.2.1.1.1.0"), "sysDescr")
        self.assertIsNone(device_info_label("Uptime", "sysUpTime", "1.3.6.1.2.1.1.3.0"))

    def test_serial_firmware_model(self):
        self.assertEqual(
            device_info_label("serial_number", "panSysSerialNumber", "1.3.6.1.4.1.25461.2.1.2.1.3.0"),
            "serial",
        )
        self.assertEqual(
            device_info_label("", "panSysSwVersion", "1.3.6.1.4.1.25461.2.1.2.1.1.0"),
            "firmware",
        )
        self.assertEqual(
            device_info_label("model", "panChassisType", "1.3.6.1.4.1.25461.2.1.2.2.1.0"),
            "model",
        )

    def test_av_version_is_not_firmware(self):
        self.assertEqual(
            device_info_label("", "panSysAvVersion", "1.3.6.1.4.1.25461.2.1.2.1.8.0"),
            "panSysAvVersion",
        )

    def test_drop_electrical(self):
        self.assertIsNone(device_info_label("amps_rating", "ampsRating", "1.2.3.4.0"))


class IdentityLookup(unittest.TestCase):
    def test_root_tag_skips_snmpv2(self):
        self.assertIsNone(
            identity_lookup_from_tag(
                {"column": {"name": "sysDescr", "OID": "1.3.6.1.2.1.1.1.0"}}
            )
        )

    def test_root_tag_firmware(self):
        lu = identity_lookup_from_tag(
            {"column": {"name": "panSysSwVersion", "OID": "1.3.6.1.4.1.25461.2.1.2.1.1.0"}}
        )
        assert lu is not None
        self.assertEqual(lu["labelname"], "firmware")
        self.assertEqual(lu["oid"], "1.3.6.1.4.1.25461.2.1.2.1.1")


class InjectDeviceIdentity(unittest.TestCase):
    def test_one_info_metric_plus_extra_lookup(self):
        mod = inject_device_identity(
            {"metrics": [{"name": "snmp_CPU", "oid": "1.2.3"}]},
            [{"oid": "1.9.9.9", "get": "1.9.9.9.0", "labelname": "serial"}],
        )
        names = [m["name"] for m in mod["metrics"]]
        self.assertEqual(names.count("snmp_device_info"), 1)
        self.assertIn("snmp_Uptime", names)
        info = next(m for m in mod["metrics"] if m["name"] == "snmp_device_info")
        labels = [lu["labelname"] for lu in info["lookups"]]
        self.assertIn("sysDescr", labels)
        self.assertIn("serial", labels)
        self.assertIn("1.9.9.9.0", mod["get"])


class FoldDeviceIdentity(unittest.TestCase):
    def _index(self) -> dict:
        return {
            "modules": {
                "if_mib": {
                    "profile": "if-mib.yml",
                    "vendor": "_general",
                    "sysobjectids": [],
                    "extends": [],
                    "identity_lookups": [],
                },
                "huawei_all_devices": {
                    "profile": "huawei-all-devices.yml",
                    "vendor": "huawei",
                    "sysobjectids": ["1.3.6.1.4.1.2011.2.*"],
                    "extends": ["if-mib.yml", "system-mib.yml"],
                    "identity_lookups": [],
                },
                "huawei_switches": {
                    "profile": "huawei-switches.yml",
                    "vendor": "huawei",
                    "sysobjectids": ["1.3.6.1.4.1.2011.2.23.*"],
                    "extends": ["huawei-all-devices.yml"],
                    "identity_lookups": [
                        {
                            "oid": "1.9.9.9",
                            "get": "1.9.9.9.0",
                            "labelname": "serial",
                        }
                    ],
                },
                "palo_alto": {
                    "profile": "palo-alto.yml",
                    "vendor": "palo_alto",
                    "sysobjectids": ["1.3.6.1.4.1.25461.2.3.*"],
                    "extends": ["system-mib.yml", "if-mib.yml"],
                    "identity_lookups": [
                        {
                            "oid": "1.3.6.1.4.1.25461.2.1.2.1.1",
                            "get": "1.3.6.1.4.1.25461.2.1.2.1.1.0",
                            "labelname": "firmware",
                        }
                    ],
                },
            }
        }

    def _modules(self) -> dict:
        nested = {
            "name": "snmp_ifHCInOctets",
            "oid": "1.3.6.1.2.1.31.1.1.1.6",
            "lookups": [
                {
                    "labels": ["ifIndex"],
                    "labelname": "sysDescr",
                    "oid": "1.3.6.1.2.1.1.1",
                    "type": "DisplayString",
                },
                {
                    "labels": ["ifIndex"],
                    "labelname": "if_interface_name",
                    "oid": "1.3.6.1.2.1.31.1.1.1.1",
                    "type": "DisplayString",
                },
            ],
        }
        return {
            "if_mib": {"metrics": [nested]},
            "huawei_all_devices": {
                "metrics": [{"name": "snmp_hwEntityOperStatus", "oid": "1.2.3"}]
            },
            "huawei_switches": {"metrics": [{"name": "snmp_foo", "oid": "1.2.4"}]},
            "palo_alto": {"metrics": [{"name": "snmp_panSessionActive", "oid": "1.2.5"}]},
        }

    def test_skip_system_mib_extends(self):
        self.assertTrue(skipped_extends("system-mib.yml"))
        self.assertTrue(skipped_extends("_general/system-mib.yml"))
        self.assertFalse(skipped_extends("if-mib.yml"))

    def test_parent_with_children_gets_sidecar(self):
        modules = self._modules()
        index = self._index()
        stats = fold_device_identity(modules, index)
        self.assertEqual(stats["sidecars"], 1)
        parent_names = [m["name"] for m in modules["huawei_all_devices"]["metrics"]]
        self.assertNotIn("snmp_device_info", parent_names)
        self.assertIn("huawei_all_devices_identity", modules)
        self.assertEqual(
            index["modules"]["huawei_all_devices"]["identity_sidecar"],
            "huawei_all_devices_identity",
        )
        child_names = [m["name"] for m in modules["huawei_switches"]["metrics"]]
        self.assertEqual(child_names.count("snmp_device_info"), 1)
        palo_info = next(
            m for m in modules["palo_alto"]["metrics"] if m["name"] == "snmp_device_info"
        )
        self.assertIn("firmware", [lu["labelname"] for lu in palo_info["lookups"]])
        self.assertIn("device_base", modules)

    def test_strip_nested_snmpv2_lookup_keeps_ifname(self):
        modules = self._modules()
        fold_device_identity(modules, self._index())
        lookups = modules["if_mib"]["metrics"][0].get("lookups") or []
        labels = [lu["labelname"] for lu in lookups]
        self.assertNotIn("sysDescr", labels)
        self.assertIn("if_interface_name", labels)

    def test_fingerprinters_sidecar_only_on_parent_matcher(self):
        modules = self._modules()
        index = self._index()
        fold_device_identity(modules, index)
        fp = build_fingerprinters(index)
        net = fp["fingerprinters"]["network"]
        self.assertEqual(net["default_modules"], ["device_base", "if_mib"])
        self.assertIn("device_base", net["default_modules_hot"])
        self.assertNotIn("system_mib", net["default_modules_hot"])
        parent = next(m for m in net["matchers"] if m["comment"].startswith("huawei_all_devices "))
        child = next(m for m in net["matchers"] if m["comment"].startswith("huawei_switches "))
        self.assertIn("huawei_all_devices_identity", parent["modules_hot"])
        self.assertNotIn("huawei_all_devices_identity", child["modules_hot"])
        self.assertNotIn("huawei_all_devices_identity", child["modules"])
        self.assertIn("huawei_switches", child["modules"])
        palo = next(m for m in net["matchers"] if m["comment"].startswith("palo_alto "))
        self.assertIn("palo_alto", palo["modules"])
        self.assertNotIn("system_mib", palo["modules"])
        self.assertNotIn("system_mib", palo["modules_hot"])
        self.assertNotIn("device_base", palo["modules"])


class DiscoverSkip(unittest.TestCase):
    def test_skips_system_mib_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "system-mib.yml").write_text("sysobjectid: []\n", encoding="utf-8")
            (root / "if-mib.yml").write_text("sysobjectid: []\n", encoding="utf-8")
            found = {p.name for p in discover_profiles(root)}
            self.assertIn("if-mib.yml", found)
            self.assertNotIn("system-mib.yml", found)
            self.assertEqual(SKIP_PROFILE_FILES, {"system-mib.yml", "system_mib.yml"})


if __name__ == "__main__":
    unittest.main()
