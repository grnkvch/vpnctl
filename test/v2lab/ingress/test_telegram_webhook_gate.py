#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import telegram_webhook_gate as gate


TOKEN = "123456789:abcdefghijklmnopqrstuvwxyzABCDE"
PUBLIC_IP = "8.8.8.8"
WEBHOOK_URL = f"https://{PUBLIC_IP}/telegram/webhook"
PUBLIC_CERTIFICATE = b"""-----BEGIN CERTIFICATE-----
offline-test-public-certificate
-----END CERTIFICATE-----
"""


class TelegramWebhookGateTests(unittest.TestCase):
    def certificate_path(self) -> tuple[tempfile.TemporaryDirectory[str], str]:
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "gateway.crt"
        path.write_bytes(PUBLIC_CERTIFICATE)
        return directory, str(path)

    def test_success_registers_observes_and_removes_only_created_webhook(self) -> None:
        directory, certificate = self.certificate_path()
        self.addCleanup(directory.cleanup)
        with (
            mock.patch.object(gate, "read_hidden_token", return_value=TOKEN),
            mock.patch.object(gate, "receiver_count", side_effect=[4, 5]),
            mock.patch.object(
                gate,
                "bot_api",
                side_effect=[
                    {"url": ""},
                    True,
                    {"url": WEBHOOK_URL, "has_custom_certificate": True},
                    {"url": WEBHOOK_URL, "has_custom_certificate": True},
                    True,
                ],
            ) as api,
        ):
            result = gate.run_gate(PUBLIC_IP, certificate, 10)
        self.assertEqual("passed", result["status"])
        self.assertTrue(result["registered"])
        self.assertTrue(result["real_request_received"])
        self.assertTrue(result["cleanup_succeeded"])
        self.assertFalse(result["sensitive_values_emitted"])
        self.assertEqual(
            ["getWebhookInfo", "setWebhook", "getWebhookInfo", "getWebhookInfo", "deleteWebhook"],
            [call.args[1] for call in api.call_args_list],
        )

    def test_existing_webhook_is_never_replaced_or_deleted(self) -> None:
        directory, certificate = self.certificate_path()
        self.addCleanup(directory.cleanup)
        with (
            mock.patch.object(gate, "read_hidden_token", return_value=TOKEN),
            mock.patch.object(gate, "bot_api", return_value={"url": "https://example.test/existing"}) as api,
        ):
            with self.assertRaisesRegex(RuntimeError, "refusing to replace"):
                gate.run_gate(PUBLIC_IP, certificate, 10)
        self.assertEqual(["getWebhookInfo"], [call.args[1] for call in api.call_args_list])

    def test_concurrent_provider_change_is_not_deleted(self) -> None:
        directory, certificate = self.certificate_path()
        self.addCleanup(directory.cleanup)
        with (
            mock.patch.object(gate, "read_hidden_token", return_value=TOKEN),
            mock.patch.object(gate, "receiver_count", side_effect=[1, 2]),
            mock.patch.object(
                gate,
                "bot_api",
                side_effect=[
                    {"url": ""},
                    True,
                    {"url": WEBHOOK_URL, "has_custom_certificate": True},
                    {"url": "https://example.test/replaced"},
                ],
            ) as api,
        ):
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                gate.run_gate(PUBLIC_IP, certificate, 10)
        self.assertNotIn("deleteWebhook", [call.args[1] for call in api.call_args_list])

    def test_public_certificate_reader_rejects_private_and_symlink_inputs(self) -> None:
        directory, certificate = self.certificate_path()
        self.addCleanup(directory.cleanup)
        private = Path(directory.name) / "private.pem"
        private.write_bytes(PUBLIC_CERTIFICATE + b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
        with self.assertRaisesRegex(RuntimeError, "public PEM"):
            gate.read_public_certificate(str(private))
        symlink = Path(directory.name) / "linked.crt"
        symlink.symlink_to(certificate)
        with self.assertRaises(OSError):
            gate.read_public_certificate(str(symlink))


if __name__ == "__main__":
    unittest.main()
