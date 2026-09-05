import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock


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

    def test_success_latency_is_partitioned_by_fault_window(self):
        results = [
            {"elapsed_ms": 10.0, "offset_seconds": 10.0},
            {"elapsed_ms": 20.0, "offset_seconds": 135.0},
            {"elapsed_ms": 30.0, "offset_seconds": 155.0},
            {"elapsed_ms": 40.0, "offset_seconds": 175.0},
            {"elapsed_ms": 50.0, "offset_seconds": 200.0},
        ]
        summary = MODULE.latency_by_fault_window(results, 135.0, 175.0)
        self.assertEqual(summary["inside"]["successful_requests"], 3)
        self.assertEqual(summary["inside"]["latency_ms"]["p95"], 40.0)
        self.assertEqual(summary["outside"]["successful_requests"], 2)
        self.assertEqual(summary["outside"]["latency_ms"]["p95"], 50.0)

    def test_recovery_probe_reuses_one_process_and_requires_five_successes_before_deadline(self):
        clock = FakeClock()
        operation = RecoveryOperation(clock, [(0.2, False)] + [(0.2, True)] * 5)
        result = MODULE.run_recovery_probe(recovery_args(), operation, clock, clock.sleep)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["recovery_probe_attempts"], 6)
        self.assertEqual(result["successful_recovery_probes"], 5)
        self.assertEqual(result["maximum_stable_recovery_probes"], 5)
        self.assertEqual(result["first_recovery_seconds"], 0.5)
        self.assertEqual(result["recovery_seconds"], 1.7)

    def test_recovery_probe_does_not_count_response_completed_after_deadline(self):
        clock = FakeClock()
        operation = RecoveryOperation(clock, [(2.0, True)] * 5)
        result = MODULE.run_recovery_probe(recovery_args(), operation, clock, clock.sleep)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["recovery_probe_attempts"], 4)
        self.assertEqual(result["successful_recovery_probes"], 3)
        self.assertEqual(result["maximum_stable_recovery_probes"], 3)
        self.assertEqual(result["first_recovery_seconds"], 2.0)
        self.assertEqual(result["last_recovery_seconds"], 6.2)

    def test_armed_probe_waits_for_trigger_without_startup_in_fault_window(self):
        clock = FakeClock()
        trigger = TriggerPath(clock, visible_at=0.03)
        MODULE.wait_for_trigger(trigger, 1.0, clock, clock.sleep)
        self.assertAlmostEqual(clock.value, 0.03)

    def test_armed_probe_trigger_wait_is_bounded(self):
        clock = FakeClock()
        trigger = TriggerPath(clock, visible_at=2.0)
        with self.assertRaises(TimeoutError):
            MODULE.wait_for_trigger(trigger, 0.025, clock, clock.sleep)
        self.assertAlmostEqual(clock.value, 0.025)

    def test_armed_probe_resets_connect_timeout_before_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            args = types.SimpleNamespace(
                public_ip="192.0.2.1",
                certificate="unused",
                body_bytes=128,
                timeout=2.0,
                connect_timeout=5.0,
                trigger_file=str(root / "trigger"),
                ready_file=str(root / "ready"),
                trigger_timeout=30.0,
            )
            connection = FakeHTTPSConnection()
            with (
                mock.patch.object(MODULE.ssl, "create_default_context", return_value=object()),
                mock.patch.object(MODULE.http.client, "HTTPSConnection", return_value=connection) as constructor,
                mock.patch.object(MODULE, "wait_for_trigger"),
            ):
                result = MODULE.run_armed_probe(args)

            constructor.assert_called_once_with("192.0.2.1", 443, timeout=5.0, context=mock.ANY)
            self.assertEqual(connection.timeout, 2.0)
            self.assertEqual(connection.sock.timeouts, [2.0])
            self.assertEqual(result["status"], 503)
            self.assertFalse(result["ok"])

    def test_armed_recovery_reads_restart_timestamp_after_trigger(self):
        clock = FakeClock()
        trigger = TriggerTextPath(clock, visible_at=0.03, contents="0.03\n")
        started = MODULE.read_trigger_timestamp(trigger, 1.0, clock, clock.sleep)
        self.assertEqual(started, 0.03)
        self.assertEqual(trigger.encoding, "ascii")


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class RecoveryOperation:
    def __init__(self, clock, outcomes):
        self.clock = clock
        self.outcomes = outcomes

    def __call__(self, _args, index, _started):
        duration, successful = self.outcomes[min(index, len(self.outcomes) - 1)]
        self.clock.value += duration
        return {"ok": successful, "status": 200 if successful else 503}


class FakeSocket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)


class FakeResponse:
    status = 503

    def read(self, _limit):
        return b"{}"


class FakeHTTPSConnection:
    def __init__(self):
        self.timeout = None
        self.sock = None

    def connect(self):
        self.sock = FakeSocket()

    def request(self, *_args, **_kwargs):
        return None

    def getresponse(self):
        return FakeResponse()

    def close(self):
        return None


class TriggerPath:
    def __init__(self, clock, visible_at):
        self.clock = clock
        self.visible_at = visible_at

    def exists(self):
        return self.clock.value >= self.visible_at


class TriggerTextPath(TriggerPath):
    def __init__(self, clock, visible_at, contents):
        super().__init__(clock, visible_at)
        self.contents = contents

    def read_text(self, encoding):
        self.encoding = encoding
        return self.contents


def recovery_args():
    return types.SimpleNamespace(
        started_monotonic=0.0,
        recovery_limit_seconds=8.0,
        stable_probes=5,
        probe_interval=0.1,
    )


if __name__ == "__main__":
    unittest.main()
