import importlib.util
import json
import pathlib
import unittest


SOURCE = pathlib.Path(__file__).with_name("load.py")
SPEC = importlib.util.spec_from_file_location("capacity_load", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class CapacityLoadTest(unittest.TestCase):
    def test_manifest_freezes_the_several_hundred_user_profile(self):
        manifest = json.loads(pathlib.Path(__file__).with_name("manifest.json").read_text())
        profile = manifest["profile"]
        self.assertEqual(profile["logical_telegram_users"], 300)
        self.assertEqual(profile["duration_seconds"] * profile["webhook_requests_per_second"], 3000)
        self.assertEqual(profile["duration_seconds"] * profile["bot_api_requests_per_second"], 1500)
        self.assertEqual(profile["personal_clients"], 5)
        self.assertLess(manifest["fault"]["accepted_failure_window_start_seconds"], manifest["fault"]["frps_stop_after_seconds"])
        self.assertGreater(manifest["fault"]["accepted_failure_window_end_seconds"], manifest["fault"]["frps_stop_after_seconds"])

    def test_telegram_body_has_exact_size_and_shape(self):
        payload = MODULE.telegram_body(599, 512)
        self.assertEqual(len(payload), 512)
        self.assertIn(b'"update_id":600', payload)
        self.assertIn(b'"id":300', payload)

    def test_percentiles_use_nearest_rank(self):
        self.assertEqual(MODULE.percentile([4, 1, 3, 2], 0.50), 2)
        self.assertEqual(MODULE.percentile([4, 1, 3, 2], 0.95), 4)


if __name__ == "__main__":
    unittest.main()
