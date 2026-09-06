#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import http.client
import json
import os
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
            mock.patch.object(gate, "LocalWebhookReceiver") as receiver_type,
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
            receiver = receiver_type.return_value.__enter__.return_value
            receiver.count.side_effect = [0, 1]
            result = gate.run_gate(PUBLIC_IP, certificate, 10)
        self.assertEqual("passed", result["status"])
        self.assertTrue(result["registered"])
        self.assertTrue(result["real_request_received"])
        self.assertTrue(result["provider_authenticated_request"])
        self.assertTrue(result["cleanup_succeeded"])
        self.assertEqual(hashlib.sha256(PUBLIC_CERTIFICATE).hexdigest(), result["public_certificate_sha256"])
        self.assertFalse(result["sensitive_values_emitted"])
        provider_secret = api.call_args_list[1].args[2]["secret_token"]
        self.assertEqual(43, len(provider_secret))
        self.assertRegex(provider_secret, r"^[A-Za-z0-9_-]+$")
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
            mock.patch.object(gate, "LocalWebhookReceiver") as receiver_type,
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
            receiver_type.return_value.__enter__.return_value.count.return_value = 1
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

    def test_local_receiver_accepts_only_authenticated_telegram_updates(self) -> None:
        valid = gate.valid_webhook_update
        self.assertFalse(valid("application/json", "wrong", "release-gate-secret", b'{"update_id":1}'))
        self.assertFalse(valid("text/plain", "release-gate-secret", "release-gate-secret", b'{"update_id":1}'))
        self.assertFalse(valid("application/json", "release-gate-secret", "release-gate-secret", b'{"message":{}}'))
        self.assertTrue(valid("application/json", "release-gate-secret", "release-gate-secret", b'{"update_id":2}'))

    @unittest.skipUnless(os.environ.get("VPNCTL_TELEGRAM_RECEIVER_SOCKET_TEST") == "1", "requires loopback bind")
    def test_local_receiver_socket_is_loopback_and_fail_closed(self) -> None:
        with gate.LocalWebhookReceiver(0, "release-gate-secret") as receiver:
            host, port = receiver._server.server_address
            self.assertEqual("127.0.0.1", host)

            def request(secret: str, body: object) -> int:
                payload = json.dumps(body).encode()
                connection = http.client.HTTPConnection(host, port, timeout=2)
                connection.request(
                    "POST",
                    "/telegram/webhook",
                    body=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(payload)),
                        "X-Telegram-Bot-Api-Secret-Token": secret,
                    },
                )
                response = connection.getresponse()
                response.read()
                connection.close()
                return response.status

            self.assertEqual(400, request("wrong", {"update_id": 1}))
            self.assertEqual(400, request("release-gate-secret", {"message": {}}))
            self.assertEqual(200, request("release-gate-secret", {"update_id": 2}))
            self.assertEqual(1, receiver.count())

    def test_receiver_port_is_bounded_before_token_input(self) -> None:
        with mock.patch.object(gate, "read_hidden_token") as token_input:
            with self.assertRaisesRegex(RuntimeError, "receiver port"):
                gate.run_gate(PUBLIC_IP, "/not/read", 10, 80)
        token_input.assert_not_called()


if __name__ == "__main__":
    unittest.main()
