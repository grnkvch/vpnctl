import importlib.util
import pathlib
import subprocess
import unittest
from unittest import mock


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

    def test_unit_states_batch_one_bounded_systemctl_snapshot(self):
        process = subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                "Id=one.service\nActiveState=active\nSubState=running\nMainPID=12\nNRestarts=1\n\n"
                "Id=two.service\nActiveState=inactive\nSubState=dead\nMainPID=0\nNRestarts=0\n"
            ),
            stderr="",
        )
        with mock.patch.object(MODULE.subprocess, "run", return_value=process) as run:
            with mock.patch.object(MODULE, "cgroup_processes", return_value=[]):
                states, errors = MODULE.unit_states(
                    ["one.service", "two.service"],
                    {"one.service": "/one", "two.service": "/two"},
                )
        self.assertEqual(run.call_count, 1)
        self.assertEqual(errors, [])
        self.assertEqual(states["one.service"]["main_pid"], 12)
        self.assertEqual(states["two.service"]["active_state"], "inactive")

    def test_unit_state_timeout_is_structured_and_does_not_escape(self):
        with mock.patch.object(
            MODULE.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["systemctl", "show"], 1),
        ):
            with mock.patch.object(MODULE, "cgroup_processes", return_value=[]):
                states, errors = MODULE.unit_states(
                    ["one.service"], {"one.service": "/one"}
                )
        self.assertEqual(errors, [{"unit": "one.service", "error_class": "timeout"}])
        self.assertEqual(states["one.service"]["active_state"], "unknown")
        self.assertEqual(
            states["one.service"]["diagnostic_error"],
            {"operation": "systemctl_show", "error_class": "timeout"},
        )

    def test_malformed_unit_state_is_structured_and_does_not_escape(self):
        process = subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                "Id=one.service\nActiveState=active\nSubState=running\n"
                "MainPID=not-a-pid\nNRestarts=0\n"
            ),
            stderr="",
        )
        with mock.patch.object(MODULE.subprocess, "run", return_value=process):
            with mock.patch.object(MODULE, "cgroup_processes", return_value=[]):
                states, errors = MODULE.unit_states(
                    ["one.service"], {"one.service": "/one"}
                )
        self.assertEqual(
            errors, [{"unit": "one.service", "error_class": "malformed_response"}]
        )
        self.assertEqual(
            states["one.service"]["diagnostic_error"]["error_class"],
            "malformed_response",
        )


if __name__ == "__main__":
    unittest.main()
