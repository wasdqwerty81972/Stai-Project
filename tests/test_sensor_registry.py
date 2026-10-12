import unittest

from cyber_os.sensors.sensor_registry import (
    PHASE1_TO_REGISTRY_ID,
    SENSOR_REGISTRY,
    build_runtime_registry,
    validate_registry,
)


class SensorRegistryTests(unittest.TestCase):
    def test_catalog_contains_all_256_complete_capabilities(self):
        validate_registry()
        self.assertEqual(len(SENSOR_REGISTRY), 256)
        self.assertEqual([item["id"] for item in SENSOR_REGISTRY], list(range(1, 257)))
        self.assertEqual(len({item["key"] for item in SENSOR_REGISTRY}), 256)
        self.assertEqual(len({item["category"] for item in SENSOR_REGISTRY}), 32)
        self.assertEqual({item["layer"] for item in SENSOR_REGISTRY}, {1, 2, 3, 4})
        for item in SENSOR_REGISTRY:
            self.assertTrue(item["name"])
            self.assertTrue(item["description"])
            self.assertTrue(item["telemetry_source"])
            self.assertTrue(item["shared_collector_id"])
            self.assertTrue(item["required_permissions"])
            self.assertTrue(item["collection_method"])
            self.assertTrue(item["event_schema"]["id"])
            self.assertEqual(
                item["event_schema"]["required_fields"],
                ["sensor_ids", "timestamp", "event_id", "event_type", "source", "category", "severity", "details"],
            )
            self.assertTrue(item["performance_cost"]["class"])
            self.assertTrue(item["test_refs"])

    def test_phase_one_ids_are_explicit_aliases_for_catalog_ids(self):
        self.assertEqual(
            PHASE1_TO_REGISTRY_ID,
            {
                1: 1, 3: 3, 6: 17, 17: 49, 18: 50, 19: 51, 25: 65,
                26: 67, 27: 68, 33: 89, 35: 97, 49: 129, 50: 130, 58: 180,
            },
        )
        process_handle = SENSOR_REGISTRY[16]
        self.assertEqual((process_handle["id"], process_handle["name"]), (17, "Process Handle Access"))
        self.assertEqual(process_handle["phase1_requested_id"], 6)

    def test_capabilities_reuse_shared_sources_and_derived_rules_do_not_add_collectors(self):
        by_id = {item["id"]: item for item in SENSOR_REGISTRY}
        self.assertEqual(by_id[1]["shared_collector_id"], by_id[3]["shared_collector_id"])
        self.assertEqual(by_id[89]["shared_collector_id"], by_id[93]["shared_collector_id"])
        self.assertEqual(by_id[93]["kind"], "derived_detection")
        self.assertEqual(by_id[93]["derived_from"], [89])
        self.assertIn("no separate collector", by_id[93]["collection_method"])

    def test_unimplemented_and_unsupported_rows_are_not_reported_as_collecting(self):
        registry = build_runtime_registry("Windows", [])
        self.assertEqual(len(registry), 256)
        by_id = {entry["id"]: entry for entry in registry}
        self.assertEqual(by_id[1]["runtime_state"], "stopped")
        self.assertEqual(by_id[2]["runtime_state"], "registered_only")
        self.assertEqual(by_id[209]["host_support"], "unsupported")
        self.assertEqual(by_id[209]["runtime_state"], "unsupported_on_this_host")
        self.assertEqual(by_id[233]["host_support"], "integration_required")
        self.assertEqual(by_id[233]["runtime_state"], "registered_only")

    def test_runtime_phase_one_status_joins_to_canonical_catalog_id(self):
        registry = build_runtime_registry(
            "Windows",
            [{"id": 17, "state": "partial", "error": "audit policy unverified"}],
        )
        file_create = registry[48]
        self.assertEqual(file_create["id"], 49)
        self.assertEqual(file_create["phase1_requested_id"], 17)
        self.assertEqual(file_create["runtime_state"], "partial")
        self.assertEqual(file_create["runtime_error"], "audit policy unverified")


if __name__ == "__main__":
    unittest.main()
