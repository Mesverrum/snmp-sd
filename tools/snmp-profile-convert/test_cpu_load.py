"""CPU utilization vs Unix load-average stem mapping."""
from __future__ import annotations

import unittest

from convert import (
    CPU_LOAD_AVG_STEM,
    claim_metric_stem,
    is_hr_processor_utilization,
    is_unix_load_average,
    prefix_metric_name,
    vital_stem,
)


class UnixLoadAverageDetect(unittest.TestCase):
    def test_ucd_laloadint_oid(self):
        self.assertTrue(is_unix_load_average("laLoadInt1Min", "1.3.6.1.4.1.2021.10.1.5.1"))
        self.assertTrue(is_unix_load_average("laLoadInt", "1.3.6.1.4.1.2021.10.1.5"))

    def test_frogfoot_loadvalue_oid(self):
        self.assertTrue(
            is_unix_load_average("loadValue", "1.3.6.1.4.1.10002.1.1.1.4.2.1.3.1")
        )

    def test_name_fallback(self):
        self.assertTrue(is_unix_load_average("laLoadInt1Min"))
        self.assertTrue(is_unix_load_average("loadValue"))

    def test_utilization_not_load(self):
        for name, oid in (
            ("cpmCPUTotal1minRev", "1.3.6.1.4.1.9.9.109.1.1.1.1.7"),
            ("hrProcessorLoadCombined", "1.3.6.1.2.1.25.3.3.1.2.196608"),
            ("hrProcessorLoad", "1.3.6.1.2.1.25.3.3.1.2"),
            ("sysXProcessorLoad", "1.3.6.1.4.1.14823.2.2.1.1.1.9.1.3"),
            ("stCPULoad", "1.3.6.1.4.1.1230.2.7.2.5.1.0"),
            ("deviceCpuLoad", "1.3.6.1.4.1.23695.200.1.1.1.3.1"),
            ("sgiCpuUsage", "1.3.6.1.4.1.6527.3.1.2.1.1.1.0"),
            ("perCentCPUUtilization", "1.3.6.1.4.1.15497.1.1.1.2.0"),
        ):
            self.assertFalse(is_unix_load_average(name, oid), name)


class VitalStem(unittest.TestCase):
    def test_load_avg_never_inherits_cpu_tag(self):
        self.assertEqual(
            vital_stem("laLoadInt1Min", "CPU", "1.3.6.1.4.1.2021.10.1.5.1"),
            CPU_LOAD_AVG_STEM,
        )
        self.assertEqual(vital_stem("loadValue", "CPU"), CPU_LOAD_AVG_STEM)

    def test_utilization_keeps_cpu_tag(self):
        self.assertEqual(vital_stem("cpmCPUTotal1minRev", "CPU"), "CPU")
        self.assertEqual(vital_stem("hrProcessorLoadCombined", "CPU"), "CPU")
        self.assertEqual(vital_stem("stCPULoad", "CPU"), "CPU")
        self.assertEqual(vital_stem("deviceCpuLoad", "CPU"), "CPU")
        self.assertEqual(vital_stem("sysXProcessorLoad", "CPU"), "CPU")

    def test_untagged_hrprocessor_is_cpu(self):
        self.assertTrue(is_hr_processor_utilization("hrProcessorLoad", "1.3.6.1.2.1.25.3.3.1.2"))
        self.assertTrue(
            is_hr_processor_utilization(
                "hrProcessorLoadCombined", "1.3.6.1.2.1.25.3.3.1.2.196608"
            )
        )
        self.assertEqual(vital_stem("hrProcessorLoad", ""), "CPU")
        self.assertEqual(vital_stem("hrProcessorLoadCombined", ""), "CPU")
        self.assertEqual(
            vital_stem("cpu1Min", "CPU", "1.3.6.1.2.1.25.3.3.1.2.1"),
            "CPU",
        )

    def test_claim_emits_prefixed(self):
        claimed: dict = {}
        warn: list[str] = []
        stem = claim_metric_stem(
            "laLoadInt",
            "CPU",
            (),
            claimed,
            warn,
            oid="1.3.6.1.4.1.2021.10.1.5.1",
        )
        self.assertEqual(prefix_metric_name(stem), "snmp_CPULoad")
        self.assertEqual(warn, [])


if __name__ == "__main__":
    unittest.main()
