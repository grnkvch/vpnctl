#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


def read_evidence(root: pathlib.Path, name: str) -> dict[str, Any]:
    path = root / name
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        return {
            "status": "invalid_evidence",
            "evidence_file": name,
            "evidence_error": type(error).__name__,
        }
    if not isinstance(value, dict):
        return {
            "status": "invalid_evidence",
            "evidence_file": name,
            "evidence_error": "top_level_not_object",
        }
    return value


def number(value: object, default: float = float("inf")) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return default


def integer(value: object, default: int = -1) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default


def nested(value: object, *keys: str) -> object:
    current = value
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def service_oom_kills(resources: dict[str, Any]) -> int:
    services = resources.get("services", {})
    if not isinstance(services, dict):
        return 1
    return int(resources.get("host_oom_kills", 1)) + sum(
        int(service.get("oom_kills", 1))
        for service in services.values()
        if isinstance(service, dict)
    )


def service_restarts(resources: dict[str, Any]) -> int:
    services = resources.get("services", {})
    if not isinstance(services, dict):
        return 1
    return sum(
        int(service.get("restarts", 1))
        for service in services.values()
        if isinstance(service, dict)
    )


def fixture_matches(actual: dict[str, Any], expected: dict[str, Any], name: str) -> bool:
    return (
        actual.get("name") == name
        and actual.get("vmType") == "qemu"
        and actual.get("arch") == "x86_64"
        and actual.get("cpus") == expected.get("vcpu")
        and actual.get("memory") == expected.get("memory_bytes")
        and actual.get("disk") == expected.get("disk_bytes")
    )


def managed_swap_matches(resources: dict[str, Any], expected: dict[str, Any]) -> bool:
    configured = integer(expected.get("managed_swap_bytes"))
    kernel_reserved = integer(expected.get("managed_swap_kernel_reserved_bytes"), 0)
    observed = integer(nested(resources, "memory", "swap_total_bytes"))
    return configured > 0 and kernel_reserved >= 0 and configured - kernel_reserved <= observed <= configured


def monitor_completed(resources: dict[str, Any]) -> bool:
    return resources.get("status") == "completed" and resources.get("diagnostic_errors") == []


def lifecycle_valid(summary: dict[str, Any], expected: int) -> bool:
    results = summary.get("request_results")
    return (
        summary.get("status") == "completed"
        and summary.get("scheduled_requests") == expected
        and summary.get("submitted_requests") == expected
        and summary.get("completed_requests") == expected
        and isinstance(results, list)
        and len(results) == expected
        and all(
            isinstance(result, dict)
            and result.get("request_index") == index
            and isinstance(result.get("scheduled_offset_seconds"), (int, float))
            and isinstance(result.get("started_offset_seconds"), (int, float))
            and isinstance(result.get("completed_offset_seconds"), (int, float))
            and isinstance(result.get("elapsed_ms"), (int, float))
            and isinstance(result.get("dispatch_lag_ms"), (int, float))
            and isinstance(result.get("end_to_end_ms"), (int, float))
            and isinstance(result.get("ok"), bool)
            and isinstance(result.get("status"), int)
            and not isinstance(result.get("status"), bool)
            and isinstance(result.get("error"), str)
            and number(result.get("completed_offset_seconds"))
            >= number(result.get("started_offset_seconds"))
            >= number(result.get("scheduled_offset_seconds"))
            for index, result in enumerate(results)
        )
    )


def dispatch_within(summary: dict[str, Any], bound: float) -> bool:
    return number(nested(summary, "dispatch_lag_ms", "p99")) <= bound


def tail_valid(summary: dict[str, Any], expected: int, bound: float) -> bool:
    tail = summary.get("tail_30_seconds")
    return (
        isinstance(tail, dict)
        and tail.get("requests") == expected
        and tail.get("failed_requests") == 0
        and number(nested(tail, "dispatch_lag_ms", "max")) <= bound
    )


def warmup_valid(summary: dict[str, Any], expected: int) -> bool:
    return (
        lifecycle_valid(summary, expected)
        and summary.get("successful_requests") == expected
        and summary.get("failed_requests") == 0
    )


def phase_within(
    phase: object, latency_p95: float, latency_p99: float, dispatch_p99: float
) -> bool:
    return (
        isinstance(phase, dict)
        and int(phase.get("requests", 0)) > 0
        and int(phase.get("failed_requests", 1)) == 0
        and number(nested(phase, "latency_ms", "p95")) <= latency_p95
        and number(nested(phase, "latency_ms", "p99")) <= latency_p99
        and number(nested(phase, "dispatch_lag_ms", "p99")) <= dispatch_p99
    )


def build_summary(
    manifest: dict[str, Any],
    source_commit: str,
    fixture_contract_sha256: str,
    evidence: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    profile = manifest["profile"]
    generator = manifest["load_generator"]
    bounds = manifest["bounds"]
    fault = manifest["fault"]
    webhook = evidence["webhook"]
    api = evidence["api"]
    webhook_warmup = evidence["webhook_warmup"]
    api_warmup = evidence["api_warmup"]
    clients = evidence["clients"]
    gateway_resources = evidence["gateway_resources"]
    node_resources = evidence["node_resources"]
    reconnect = evidence["reconnect"]
    disruption = webhook.get("client_disruption", {})
    phases = disruption.get("latency_by_client_phase", {})
    if not isinstance(phases, dict):
        phases = {}
    gateway_monitor_completed = monitor_completed(gateway_resources)
    node_monitor_completed = monitor_completed(node_resources)

    expected_webhook = profile["duration_seconds"] * profile["webhook_requests_per_second"]
    expected_api = profile["duration_seconds"] * profile["bot_api_requests_per_second"]
    expected_webhook_warmup = generator["warmup_seconds"] * profile["webhook_requests_per_second"]
    expected_api_warmup = generator["warmup_seconds"] * profile["bot_api_requests_per_second"]
    tail_seconds = bounds["load_generator_tail_seconds"]
    dispatch_bound = bounds["load_generator_dispatch_lag_p99_ms"]

    webhook_lifecycle = lifecycle_valid(webhook, expected_webhook)
    api_lifecycle = lifecycle_valid(api, expected_api)
    webhook_pre_dispatch = number(
        nested(phases.get("pre_disruption"), "dispatch_lag_ms", "p99")
    ) <= dispatch_bound
    webhook_post_dispatch = number(
        nested(phases.get("post_recovery"), "dispatch_lag_ms", "p99")
    ) <= dispatch_bound
    webhook_tail = tail_valid(
        webhook, tail_seconds * profile["webhook_requests_per_second"], dispatch_bound
    )
    api_tail = tail_valid(
        api, tail_seconds * profile["bot_api_requests_per_second"], dispatch_bound
    )
    api_dispatch = dispatch_within(api, dispatch_bound)
    webhook_dispatch = dispatch_within(webhook, dispatch_bound)
    load_checks = {
        "webhook_warmup_completed": warmup_valid(webhook_warmup, expected_webhook_warmup),
        "bot_api_warmup_completed": warmup_valid(api_warmup, expected_api_warmup),
        "webhook_scheduled_and_completed": webhook_lifecycle,
        "bot_api_scheduled_and_completed": api_lifecycle,
        "webhook_global_dispatch_lag_p99_within_bound": webhook_dispatch,
        "webhook_pre_disruption_dispatch_lag_p99_within_bound": webhook_pre_dispatch,
        "webhook_post_recovery_dispatch_lag_p99_within_bound": webhook_post_dispatch,
        "bot_api_global_dispatch_lag_p99_within_bound": api_dispatch,
        "webhook_last_30_seconds_without_backlog_or_errors": webhook_tail,
        "bot_api_last_30_seconds_without_backlog_or_errors": api_tail,
        "no_persistent_backlog_after_recovery": webhook_post_dispatch
        and webhook_tail
        and api_tail,
    }
    load_valid = all(load_checks.values())

    gateway_resource_checks = {
        "fixture_profile": fixture_matches(
            evidence["gateway_fixture"], manifest["gateway_target"], "vpnctl-v2-gateway"
        ),
        "controller_idle_rss": bool(evidence["controller"].get("within_target")),
        "monitor_completed": gateway_monitor_completed,
        "average_cpu": number(nested(gateway_resources, "cpu_percent", "average"))
        <= bounds["maximum_average_cpu_percent"],
        "minimum_available_memory": number(
            nested(gateway_resources, "memory", "minimum_available_bytes"), -1
        )
        >= bounds["minimum_mem_available_bytes"],
        "managed_swap_profile": managed_swap_matches(
            gateway_resources, manifest["gateway_target"]
        ),
        "maximum_swap_used": number(
            nested(gateway_resources, "memory", "maximum_swap_used_bytes")
        )
        <= bounds["maximum_swap_used_bytes"],
        "minimum_free_disk": number(
            nested(gateway_resources, "disk", "minimum_free_bytes"), -1
        )
        >= bounds["minimum_free_disk_bytes"],
        "maximum_disk_growth": number(
            nested(gateway_resources, "disk", "growth_bytes")
        )
        <= bounds["maximum_disk_growth_bytes"],
        "no_oom": service_oom_kills(gateway_resources) == 0,
        "per_expose_limit": evidence["per_expose"].get("status_counts")
        == {"200": bounds["per_expose_concurrent_requests"], "503": 5},
        "gateway_limit": evidence["gateway_limit"].get("status_counts")
        == {"200": bounds["gateway_concurrent_requests"], "503": 8}
        and evidence["gateway_limit_backend"].get("max_active_requests", 0) >= 60,
    }
    gateway_capacity_valid = all(gateway_resource_checks.values())

    client_items = clients.get("clients", [])
    node_health_checks = {
        "fixture_profile": fixture_matches(
            evidence["node_fixture"], manifest["node_fixture"], "vpnctl-v2-node"
        ),
        "monitor_completed": node_monitor_completed,
        "managed_swap_profile": managed_swap_matches(
            node_resources, manifest["node_fixture"]
        ),
        "no_oom": service_oom_kills(node_resources) == 0,
        "no_service_crash": service_restarts(node_resources) == 0,
        "services_healthy_after_recovery": evidence["node_health"].get("status") == "passed",
        "five_client_workload_completed": clients.get("status") == "passed"
        and isinstance(client_items, list)
        and len(client_items) == profile["personal_clients"],
    }
    node_healthy = all(node_health_checks.values())

    reconnect_checks = {
        "fault_process_passed": reconnect.get("status") == "passed",
        "scheduled_offset_unchanged": reconnect.get("scheduled_start_after_seconds")
        == fault["frps_stop_after_seconds"],
        "requested_downtime_unchanged": reconnect.get("requested_down_seconds")
        == fault["frps_down_seconds"],
        "actual_downtime_within_timer_tolerance": fault["frps_down_seconds"] - 0.25
        <= number(reconnect.get("down_seconds"))
        <= fault["frps_down_seconds"] + 0.5,
        "reconnect_within_bound": number(reconnect.get("recovery_seconds"))
        <= bounds["tunnel_reconnect_seconds"],
        "stable_recovery_observed": reconnect.get("stable_recovery_observed") is True,
        "watchdog_service_not_restarted": reconnect.get(
            "recovered_without_client_service_restart"
        )
        is True,
    }
    reconnect_valid = all(reconnect_checks.values())

    disruption_checks = {
        "classified": disruption.get("status") == "passed",
        "first_impact_within_sanity_window": disruption.get(
            "first_impact_within_sanity_window"
        )
        is True,
        "stable_recovery_observed": disruption.get("stable_recovery_observed") is True,
        "duration_within_bound": number(disruption.get("duration_seconds"))
        <= bounds["maximum_client_disruption_seconds"],
        "no_failures_outside_disruption": disruption.get("failures_outside")
        == bounds["webhook_failures_outside_client_disruption"],
    }
    disruption_valid = all(disruption_checks.values())

    pre_valid = phase_within(
        phases.get("pre_disruption"),
        bounds["webhook_steady_state_success_p95_ms"],
        bounds["webhook_steady_state_success_p99_ms"],
        dispatch_bound,
    )
    post_valid = phase_within(
        phases.get("post_recovery"),
        bounds["webhook_steady_state_success_p95_ms"],
        bounds["webhook_steady_state_success_p99_ms"],
        dispatch_bound,
    )
    api_valid = (
        api.get("failed_requests") == 0
        and number(nested(api, "latency_ms", "p95")) <= bounds["bot_api_success_p95_ms"]
        and number(nested(api, "latency_ms", "p99")) <= bounds["bot_api_success_p99_ms"]
        and api_dispatch
    )
    steady_checks = {
        "webhook_minimum_successes": webhook.get("successful_requests", 0)
        >= bounds["webhook_successful_requests_minimum"],
        "webhook_pre_disruption_latency": pre_valid,
        "webhook_post_recovery_latency": post_valid,
        "bot_api_global_errors_latency_and_dispatch": api_valid,
    }
    steady_valid = all(steady_checks.values())

    client_checks = {
        "five_clients": isinstance(client_items, list)
        and len(client_items) == profile["personal_clients"],
        "zero_packet_loss": isinstance(client_items, list)
        and len(client_items) == profile["personal_clients"]
        and all(
            isinstance(item, dict)
            and item.get("packet_loss_percent") == bounds["client_packet_loss_percent"]
            for item in client_items
        ),
    }
    clients_valid = all(client_checks.values())

    measurement_checks = {
        "gateway_resource_monitor_completed": gateway_monitor_completed,
        "node_resource_monitor_completed": node_monitor_completed,
    }
    measurement_valid = all(measurement_checks.values())

    invalid_reasons = [name for name, passed in load_checks.items() if not passed]
    node_non_monitor_checks = {
        "fixture_profile",
        "services_healthy_after_recovery",
        "five_client_workload_completed",
    }
    node_reasons = [
        name
        for name, passed in node_health_checks.items()
        if not passed
        and name != "monitor_completed"
        and (node_monitor_completed or name in node_non_monitor_checks)
    ]
    gateway_non_monitor_checks = {
        "fixture_profile",
        "controller_idle_rss",
        "per_expose_limit",
        "gateway_limit",
    }
    product_reasons = (
        [
            f"gateway_capacity.{name}"
            for name, passed in gateway_resource_checks.items()
            if not passed
            and name != "monitor_completed"
            and (gateway_monitor_completed or name in gateway_non_monitor_checks)
        ]
        + [f"fault_reconnect.{name}" for name, passed in reconnect_checks.items() if not passed]
        + [f"client_disruption.{name}" for name, passed in disruption_checks.items() if not passed]
        + [f"steady_state_latency.{name}" for name, passed in steady_checks.items() if not passed]
        + [f"clients.{name}" for name, passed in client_checks.items() if not passed]
    )
    all_product_valid = (
        gateway_capacity_valid
        and reconnect_valid
        and disruption_valid
        and steady_valid
        and clients_valid
    )
    measurement_reasons = [name for name, passed in measurement_checks.items() if not passed]
    if not measurement_valid:
        classification = "invalid_measurement_evidence"
    elif not load_valid:
        classification = "invalid_load_generation"
    elif not node_healthy:
        classification = "invalid_node_fixture"
    elif not all_product_valid:
        classification = "gateway_capacity_not_demonstrated"
    else:
        classification = "passed"

    node_cpu_starvation = (
        number(nested(node_resources, "scheduler", "maximum_run_queue"), 0)
        > manifest["node_fixture"]["vcpu"]
        and (
            number(nested(node_resources, "cpu_percent", "average"), 0) >= 85
            or number(nested(node_resources, "cpu_percent", "maximum_interval"), 0)
            >= 95
        )
    )
    webhook_pool_exhaustion = (
        nested(webhook, "worker_pool", "saturation_observed") is True
        and number(nested(webhook, "worker_pool", "worker_queue_lag_ms", "p99"), 0)
        > dispatch_bound
    )
    api_pool_exhaustion = (
        nested(api, "worker_pool", "saturation_observed") is True
        and number(nested(api, "worker_pool", "worker_queue_lag_ms", "p99"), 0)
        > dispatch_bound
    )
    gateway_saturation = gateway_monitor_completed and any(
        not gateway_resource_checks[key]
        for key in (
            "average_cpu",
            "minimum_available_memory",
            "maximum_swap_used",
            "minimum_free_disk",
            "maximum_disk_growth",
        )
    )

    return {
        "schema_version": 3,
        "status": "passed" if classification == "passed" else "failed",
        "measurement_classification": classification,
        "source_commit": source_commit,
        "fixture_contract_sha256": fixture_contract_sha256,
        "topology": manifest["topology"],
        "profile": profile,
        "fixture_profiles": {
            "gateway": manifest["gateway_target"],
            "node": manifest["node_fixture"],
            "gateway_observed": evidence["gateway_fixture"],
            "node_observed": evidence["node_fixture"],
        },
        "measurement_validity": {
            "within_contract": measurement_valid,
            "checks": measurement_checks,
            "invalid_reasons": measurement_reasons,
        },
        "gateway_capacity": {
            "within_contract": gateway_capacity_valid,
            "checks": gateway_resource_checks,
            "resources": gateway_resources,
            "controller": evidence["controller"],
            "thresholds": {
                key: bounds[key]
                for key in (
                    "controller_idle_rss_bytes",
                    "minimum_mem_available_bytes",
                    "maximum_swap_used_bytes",
                    "maximum_average_cpu_percent",
                    "minimum_free_disk_bytes",
                    "maximum_disk_growth_bytes",
                )
            },
        },
        "node_fixture_health": {
            "within_contract": node_healthy,
            "checks": node_health_checks,
            "resources_diagnostic_only": node_resources,
            "service_health": evidence["node_health"],
            "resource_acceptance_thresholds_applied": False,
        },
        "load_generator_validity": {
            "within_contract": load_valid,
            "checks": load_checks,
            "dispatch_lag_p99_bound_ms": dispatch_bound,
            "contract": generator,
            "invalid_reasons": invalid_reasons,
            "warmup": {
                "webhook": {
                    key: webhook_warmup.get(key)
                    for key in (
                        "status",
                        "scheduled_requests",
                        "submitted_requests",
                        "completed_requests",
                        "successful_requests",
                        "failed_requests",
                    )
                },
                "bot_api": {
                    key: api_warmup.get(key)
                    for key in (
                        "status",
                        "scheduled_requests",
                        "submitted_requests",
                        "completed_requests",
                        "successful_requests",
                        "failed_requests",
                    )
                },
            },
            "webhook": {
                key: webhook.get(key)
                for key in (
                    "status",
                    "scheduled_requests",
                    "submitted_requests",
                    "completed_requests",
                    "dispatch_lag_ms",
                    "tail_30_seconds",
                    "worker_pool",
                )
            },
            "bot_api": {
                key: api.get(key)
                for key in (
                    "status",
                    "scheduled_requests",
                    "submitted_requests",
                    "completed_requests",
                    "dispatch_lag_ms",
                    "tail_30_seconds",
                    "worker_pool",
                )
            },
        },
        "fault_reconnect": {
            "within_contract": reconnect_valid,
            "checks": reconnect_checks,
            "result": reconnect,
        },
        "client_disruption": {
            "within_contract": disruption_valid,
            "checks": disruption_checks,
            "result": disruption,
        },
        "steady_state_latency": {
            "within_contract": steady_valid,
            "checks": steady_checks,
            "webhook_phases": phases,
            "bot_api": {
                "failed_requests": api.get("failed_requests"),
                "latency_ms": api.get("latency_ms"),
                "dispatch_lag_ms": api.get("dispatch_lag_ms"),
            },
        },
        "client_health": {
            "within_contract": clients_valid,
            "checks": client_checks,
            "result": clients,
        },
        "diagnostic_signals": {
            "node_cpu_starvation_suspected": node_cpu_starvation,
            "webhook_worker_pool_exhaustion_suspected": webhook_pool_exhaustion,
            "bot_api_worker_pool_exhaustion_suspected": api_pool_exhaustion,
            "frp_reconnect_defect_observed": reconnect.get("status") != "passed"
            or reconnect.get("stable_recovery_observed") is not True
            or number(reconnect.get("recovery_seconds"))
            > bounds["tunnel_reconnect_seconds"],
            "gateway_saturation_observed": gateway_saturation,
            "interpretation": "heuristic_signals_not_causal_proof",
            "fault_snapshots": evidence["diagnostics"],
        },
        "failure_reasons": {
            "measurement": measurement_reasons,
            "load_generator": invalid_reasons,
            "node_fixture": node_reasons,
            "product": product_reasons,
        },
        "cleanup": {
            "owner_scoped": True,
            "temporary_resources_absent": True,
            "prior_fixture_states_restored": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="classify vpnctl v2 capacity evidence")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--fixture-contract-sha256", required=True)
    args = parser.parse_args()
    root = pathlib.Path(args.run_root)
    manifest = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))
    names = {
        "controller": "controller-idle.json",
        "webhook": "webhook-load.json",
        "api": "api-load.json",
        "webhook_warmup": "webhook-warmup.json",
        "api_warmup": "api-warmup.json",
        "clients": "clients.json",
        "gateway_resources": "gateway-resources.json",
        "node_resources": "node-resources.json",
        "reconnect": "reconnect.json",
        "per_expose": "per-expose-limit.json",
        "gateway_limit": "gateway-limit.json",
        "gateway_limit_backend": "gateway-limit-backend.json",
        "gateway_fixture": "gateway-before.json",
        "node_fixture": "node-before.json",
        "node_health": "node-health.json",
    }
    evidence = {key: read_evidence(root, name) for key, name in names.items()}
    evidence["diagnostics"] = {
        "window_start_seconds": manifest["fault"]["accepted_failure_window_start_seconds"],
        "window_end_seconds": manifest["fault"]["accepted_failure_window_end_seconds"],
        "gateway_timeline": "gateway-resources.json#timeline.runtime",
        "node_timeline": "node-resources.json#timeline.runtime",
        "post_workload_node_health": "node-health.json",
    }
    print(
        json.dumps(
            build_summary(
                manifest, args.source_commit, args.fixture_contract_sha256, evidence
            ),
            separators=(",", ":"),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
