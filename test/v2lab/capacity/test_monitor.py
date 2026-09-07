import importlib.util
import pathlib
import unittest


SOURCE = pathlib.Path(__file__).with_name("monitor.py")
SPEC = importlib.util.spec_from_file_location("capacity_monitor", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class CapacityMonitorTest(unittest.TestCase):
    def test_cpu_delta_separates_busy_iowait_and_steal(self):
        before = {"total": 100, "idle": 40, "iowait": 10, "steal": 2}
        after = {"total": 200, "idle": 70, "iowait": 20, "steal": 7}
        result = MODULE.cpu_delta(before, after)
        self.assertEqual(result["busy"], 60.0)
        self.assertEqual(result["iowait"], 10.0)
        self.assertEqual(result["steal"], 5.0)

    def test_zero_length_cpu_sample_is_safe(self):
        sample = {"total": 100, "idle": 40, "iowait": 10, "steal": 2}
        self.assertEqual(
            MODULE.cpu_delta(sample, sample),
            {"busy": 0.0, "iowait": 0.0, "steal": 0.0},
        )


if __name__ == "__main__":
    unittest.main()
