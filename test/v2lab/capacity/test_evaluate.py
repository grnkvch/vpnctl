import copy
import importlib.util
import json
import pathlib
import unittest


SOURCE = pathlib.Path(__file__).with_name("evaluate.py")
SPEC = importlib.util.spec_from_file_location("capacity_evaluate", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def phase(requests=5, dispatch=10.0, latency=50.0):
    return {
        "requests": requests,
        "successful_requests": requests,
        "failed_requests": 0,
        "latency_ms": {"p50": latency, "p95": latency, "p99": latency, "max": latency},
        "end_to_end_ms": {"p50": latency, "p95": latency, "p99": latency, "max": latency},
        "dispatch_lag_ms": {"p50": dispatch, "p95": dispatch, "p99": dispatch, "max": dispatch},
    }


def lifecycle_results(count):
    return [
        {
            "request_index": index,
            "scheduled_offset_seconds": float(index),
            "started_offset_seconds": float(index),
            "completed_offset_seconds": float(index) + 0.05,
            "elapsed_ms": 50.0,
            "dispatch_lag_ms": 0.0,
            "end_to_end_ms": 50.0,
            "ok": True,
            "status": 200,
            "error": "",
        }
        for index in range(count)
    ]


def load_summary(count, tail_count):
    return {
        "schema_version": 2,
        "status": "completed",
        "scheduled_requests": count,
        "submitted_requests": count,
        "completed_requests": count,
        "successful_requests": count,
        "failed_requests": 0,
        "request_results": lifecycle_results(count),
        "latency_ms": {"p50": 50.0, "p95": 50.0, "p99": 50.0, "max": 50.0},
        "dispatch_lag_ms": {"p50": 10.0, "p95": 10.0, "p99": 10.0, "max": 10.0},
        "tail_30_seconds": phase(tail_count),
        "worker_pool": {
            "configured_workers": 32,
            "maximum_active_workers": 8,
            "saturation_observed": False,
            "worker_queue_lag_ms": {"p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0},
            "timeout_like_failures": 0,
        },
    }


def resources(cpu=50.0, logical_cpus=1):
    return {
        "schema_version": 3,
        "status": "completed",
        "diagnostic_errors": [],
        "cpu_percent": {"average": cpu, "maximum_interval": cpu, "average_iowait": 0, "average_steal": 0},
        "scheduler": {"logical_cpus": logical_cpus, "maximum_load1": 1.0, "maximum_run_queue": logical_cpus},
        "memory": {
            "minimum_available_bytes": 200_000_000,
            "swap_total_bytes": 1_073_741_824,
            "maximum_swap_used_bytes": 1_000_000,
        },
        "disk": {"minimum_free_bytes": 2_000_000_000, "growth_bytes": 1_000_000},
        "services": {"service": {"oom_kills": 0, "restarts": 0}},
        "host_oom_kills": 0,
    }


def valid_case():
    manifest = json.loads(pathlib.Path(__file__).with_name("manifest.json").read_text())
    manifest = copy.deepcopy(manifest)
    manifest["profile"]["duration_seconds"] = 10
    manifest["profile"]["webhook_requests_per_second"] = 2
    manifest["profile"]["bot_api_requests_per_second"] = 1
    manifest["bounds"]["load_generator_tail_seconds"] = 3
    manifest["bounds"]["webhook_successful_requests_minimum"] = 19
    webhook = load_summary(20, 6)
    webhook["client_disruption"] = {
        "status": "passed",
        "first_impact_within_sanity_window": True,
        "stable_recovery_observed": True,
        "duration_seconds": 6.0,
        "failures_outside": 0,
        "latency_by_client_phase": {
            "pre_disruption": phase(),
            "disruption": phase(),
            "post_recovery": phase(),
        },
    }
    evidence = {
        "controller": {"within_target": True},
        "webhook": webhook,
        "api": load_summary(10, 3),
        "webhook_warmup": load_summary(20, 20),
        "api_warmup": load_summary(10, 10),
        "clients": {
            "status": "passed",
            "clients": [{"packet_loss_percent": 0} for _ in range(5)],
        },
        "gateway_resources": resources(),
        "node_resources": resources(cpu=99.0, logical_cpus=4),
        "reconnect": {
            "status": "passed",
            "scheduled_start_after_seconds": 145,
            "restart_policy_restoration_phase": "post_measurement_cleanup",
            "prearmed_probe_keepalive_seconds": 5,
            "prearmed_probe_trigger_timeout_seconds": 213,
            "requested_down_seconds": 3,
            "down_seconds": 3.0,
            "recovery_seconds": 7.0,
            "stable_recovery_observed": True,
            "recovered_without_client_service_restart": True,
            "unavailable_probe": {
                "status": 503,
                "ok": False,
                "prearmed_keepalive_requests": 29,
            },
        },
        "per_expose": {"status_counts": {"200": 40, "503": 5}},
        "gateway_limit": {"status_counts": {"200": 64, "503": 8}},
        "gateway_limit_backend": {"max_active_requests": 64},
        "gateway_fixture": {
            "name": "vpnctl-v2-gateway",
            "vmType": "qemu",
            "arch": "x86_64",
            "cpus": 1,
            "memory": 536870912,
            "disk": 10737418240,
        },
        "node_fixture": {
            "name": "vpnctl-v2-node",
            "vmType": "qemu",
            "arch": "x86_64",
            "cpus": 4,
            "memory": 2147483648,
            "disk": 10737418240,
        },
        "node_health": {"status": "passed"},
        "diagnostics": {"fault_boundary": "a", "recovery": "b"},
    }
    return manifest, evidence


class CapacityEvaluationTest(unittest.TestCase):
    def evaluate(self, manifest, evidence):
        return MODULE.build_summary(manifest, "a" * 40, "b" * 64, evidence)

    def test_gateway_only_capacity_case_passes_with_busy_node(self):
        manifest, evidence = valid_case()
        evidence["node_resources"]["memory"]["minimum_available_bytes"] = 1
        evidence["node_resources"]["memory"]["maximum_swap_used_bytes"] = 900_000_000
        evidence["node_resources"]["disk"]["minimum_free_bytes"] = 1
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["measurement_classification"], "passed")
        self.assertTrue(summary["gateway_capacity"]["within_contract"])
        self.assertTrue(summary["node_fixture_health"]["within_contract"])
        self.assertFalse(summary["node_fixture_health"]["resource_acceptance_thresholds_applied"])

    def test_missing_prearmed_probe_evidence_rejects_reconnect(self):
        manifest, evidence = valid_case()
        del evidence["reconnect"]["unavailable_probe"]["prearmed_keepalive_requests"]
        summary = self.evaluate(manifest, evidence)
        self.assertFalse(summary["fault_reconnect"]["within_contract"])
        self.assertIn(
            "fault_reconnect.prearmed_probe_keepalive_observed",
            summary["failure_reasons"]["product"],
        )

    def test_wrong_restart_policy_restoration_phase_rejects_reconnect(self):
        manifest, evidence = valid_case()
        evidence["reconnect"]["restart_policy_restoration_phase"] = "during_recovery"
        summary = self.evaluate(manifest, evidence)
        self.assertFalse(summary["fault_reconnect"]["within_contract"])
        self.assertIn(
            "fault_reconnect.restart_policy_restoration_phase_applied",
            summary["failure_reasons"]["product"],
        )

    def test_dispatch_lag_classifies_measurement_as_invalid_generation(self):
        manifest, evidence = valid_case()
        evidence["webhook"]["client_disruption"]["latency_by_client_phase"]["post_recovery"]["dispatch_lag_ms"]["p99"] = 1001
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["measurement_classification"], "invalid_load_generation")
        self.assertIn(
            "webhook_post_recovery_dispatch_lag_p99_within_bound",
            summary["failure_reasons"]["load_generator"],
        )

    def test_webhook_global_dispatch_lag_cannot_hide_inside_disruption(self):
        manifest, evidence = valid_case()
        evidence["webhook"]["dispatch_lag_ms"]["p99"] = 1001
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "invalid_load_generation")
        self.assertIn(
            "webhook_global_dispatch_lag_p99_within_bound",
            summary["failure_reasons"]["load_generator"],
        )

    def test_bot_api_dispatch_lag_is_global_without_fault_exception(self):
        manifest, evidence = valid_case()
        evidence["api"]["dispatch_lag_ms"]["p99"] = 1001
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "invalid_load_generation")
        self.assertIn(
            "bot_api_global_dispatch_lag_p99_within_bound",
            summary["failure_reasons"]["load_generator"],
        )

    def test_gateway_threshold_failure_is_not_blended_with_generator_failure(self):
        manifest, evidence = valid_case()
        evidence["gateway_resources"]["cpu_percent"]["average"] = 85.001
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "gateway_capacity_not_demonstrated")
        self.assertTrue(summary["load_generator_validity"]["within_contract"])
        self.assertIn("gateway_capacity.average_cpu", summary["failure_reasons"]["product"])

    def test_completed_count_mismatch_invalidates_generation(self):
        manifest, evidence = valid_case()
        evidence["api"]["completed_requests"] = 9
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "invalid_load_generation")
        self.assertFalse(
            summary["load_generator_validity"]["checks"]["bot_api_scheduled_and_completed"]
        )

    def test_missing_warmup_invalidates_generation(self):
        manifest, evidence = valid_case()
        evidence["webhook_warmup"] = {
            "status": "invalid_evidence",
            "evidence_error": "FileNotFoundError",
        }
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "invalid_load_generation")
        self.assertFalse(
            summary["load_generator_validity"]["checks"]["webhook_warmup_completed"]
        )
        self.assertIn(
            "webhook_warmup_completed",
            summary["failure_reasons"]["load_generator"],
        )

    def test_tail_backlog_invalidates_generation(self):
        manifest, evidence = valid_case()
        evidence["webhook"]["tail_30_seconds"]["dispatch_lag_ms"]["max"] = 1001
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "invalid_load_generation")
        self.assertFalse(
            summary["load_generator_validity"]["checks"][
                "webhook_last_30_seconds_without_backlog_or_errors"
            ]
        )

    def test_incomplete_lifecycle_invalidates_generation(self):
        manifest, evidence = valid_case()
        del evidence["api"]["request_results"][0]["error"]
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "invalid_load_generation")

    def test_gateway_swap_profile_is_normative(self):
        manifest, evidence = valid_case()
        evidence["gateway_resources"]["memory"]["swap_total_bytes"] = 0
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "gateway_capacity_not_demonstrated")
        self.assertIn(
            "gateway_capacity.managed_swap_profile",
            summary["failure_reasons"]["product"],
        )

    def test_kernel_reserved_swap_page_still_matches_managed_allocation(self):
        manifest, evidence = valid_case()
        evidence["gateway_resources"]["memory"]["swap_total_bytes"] = 1_073_737_728
        evidence["node_resources"]["memory"]["swap_total_bytes"] = 1_073_737_728
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "passed")
        self.assertTrue(summary["gateway_capacity"]["checks"]["managed_swap_profile"])
        self.assertTrue(summary["node_fixture_health"]["checks"]["managed_swap_profile"])

    def test_swap_larger_than_kernel_reservation_is_rejected(self):
        manifest, evidence = valid_case()
        evidence["gateway_resources"]["memory"]["swap_total_bytes"] = 1_073_737_727
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "gateway_capacity_not_demonstrated")
        self.assertFalse(summary["gateway_capacity"]["checks"]["managed_swap_profile"])

    def test_node_swap_profile_is_fixture_health_not_gateway_capacity(self):
        manifest, evidence = valid_case()
        evidence["node_resources"]["memory"]["swap_total_bytes"] = 0
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "invalid_node_fixture")

    def test_diagnostic_signals_keep_candidate_causes_separate(self):
        manifest, evidence = valid_case()
        evidence["node_resources"]["cpu_percent"]["average"] = 90
        evidence["node_resources"]["scheduler"]["maximum_run_queue"] = 5
        evidence["webhook"]["worker_pool"].update(
            {
                "saturation_observed": True,
                "worker_queue_lag_ms": {
                    "p50": 100,
                    "p95": 1200,
                    "p99": 1500,
                    "max": 1800,
                },
            }
        )
        evidence["webhook"]["dispatch_lag_ms"]["p99"] = 1500
        evidence["reconnect"].update(
            {"status": "failed", "stable_recovery_observed": False, "recovery_seconds": 8.1}
        )
        evidence["gateway_resources"]["cpu_percent"]["average"] = 86
        summary = self.evaluate(manifest, evidence)
        signals = summary["diagnostic_signals"]
        self.assertTrue(signals["node_cpu_starvation_suspected"])
        self.assertTrue(signals["webhook_worker_pool_exhaustion_suspected"])
        self.assertTrue(signals["frp_reconnect_defect_observed"])
        self.assertTrue(signals["gateway_saturation_observed"])
        self.assertEqual(signals["interpretation"], "heuristic_signals_not_causal_proof")

    def test_post_recovery_latency_is_a_product_failure_not_generator_failure(self):
        manifest, evidence = valid_case()
        post = evidence["webhook"]["client_disruption"]["latency_by_client_phase"]["post_recovery"]
        post["latency_ms"]["p99"] = 2001
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "gateway_capacity_not_demonstrated")
        self.assertTrue(summary["load_generator_validity"]["within_contract"])
        self.assertFalse(summary["steady_state_latency"]["within_contract"])

    def test_bot_api_has_no_disruption_exception(self):
        manifest, evidence = valid_case()
        evidence["api"]["failed_requests"] = 1
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "gateway_capacity_not_demonstrated")
        self.assertTrue(summary["load_generator_validity"]["within_contract"])
        self.assertFalse(summary["steady_state_latency"]["within_contract"])

    def test_node_service_failure_is_invalid_fixture_not_gateway_capacity(self):
        manifest, evidence = valid_case()
        evidence["node_health"]["status"] = "failed"
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "invalid_node_fixture")
        self.assertTrue(summary["gateway_capacity"]["within_contract"])

    def test_degraded_monitor_is_invalid_measurement_not_gateway_saturation(self):
        manifest, evidence = valid_case()
        evidence["gateway_resources"]["status"] = "degraded"
        evidence["gateway_resources"]["memory"] = {}
        evidence["gateway_resources"]["disk"] = {}
        evidence["gateway_resources"]["services"] = {}
        evidence["gateway_resources"]["diagnostic_errors"] = [
            {
                "offset_seconds": 145.0,
                "unit": "service",
                "operation": "systemctl_show",
                "error_class": "timeout",
            }
        ]
        summary = self.evaluate(manifest, evidence)
        self.assertEqual(summary["measurement_classification"], "invalid_measurement_evidence")
        self.assertFalse(summary["measurement_validity"]["within_contract"])
        self.assertFalse(summary["diagnostic_signals"]["gateway_saturation_observed"])
        self.assertEqual(summary["failure_reasons"]["product"], [])


if __name__ == "__main__":
    unittest.main()
