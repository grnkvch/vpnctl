import importlib.util
import json
import pathlib
import stat
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("pty_secret.py")
SPEC = importlib.util.spec_from_file_location("pty_secret", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PTY_SECRET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PTY_SECRET)


class PTYSecretTests(unittest.TestCase):
    def test_extracts_exactly_one_token(self):
        token = b"vpnctl-" + b"invite-v1." + b"abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOP"
        self.assertEqual(PTY_SECRET.extract_single_token(b"prompt\r\n" + token + b"\r\n"), token)
        with self.assertRaises(PTY_SECRET.HelperError):
            PTY_SECRET.extract_single_token(b"no token")
        with self.assertRaises(PTY_SECRET.HelperError):
            PTY_SECRET.extract_single_token(token + b"\n" + token)

    def test_projection_is_allowlisted(self):
        source = {
            "schema_version": 1,
            "status": "ok",
            "resource_ids": {"invite_id": "inv-ABC123", "private": "drop"},
            "data": {
                "expires_at": "2026-09-15T12:00:00Z",
                "displayed_to_tty": True,
                "token": "must-not-survive",
            },
            "secret": "must-not-survive",
        }
        projected = PTY_SECRET.safe_projection(source, "invite")
        encoded = json.dumps(projected)
        self.assertNotIn("must-not-survive", encoded)
        self.assertEqual(projected["resource_ids"], {"invite_id": "inv-ABC123"})

    def test_join_and_purge_projections_drop_unlisted_fields(self):
        join = PTY_SECRET.safe_projection(
            {
                "schema_version": 1,
                "status": "ok",
                "resource_ids": {"node_id": "node-1", "credential": "drop"},
                "data": {
                    "generation": 2,
                    "active_transport": "standard",
                    "presets": ["telegram"],
                    "private_key": "drop",
                },
            },
            "join",
        )
        purge = PTY_SECRET.safe_projection(
            {
                "schema_version": 1,
                "status": "ok",
                "resource_ids": {"secret": "drop"},
                "data": {
                    "changed": True,
                    "role": "node",
                    "data_purged": True,
                    "binary_removed": True,
                    "credentials": "drop",
                },
            },
            "purge-node",
        )
        encoded = json.dumps({"join": join, "purge": purge})
        self.assertNotIn("drop", encoded)
        self.assertEqual(join["resource_ids"], {"node_id": "node-1"})
        self.assertNotIn("resource_ids", purge)

    def test_projection_rejects_non_success_result(self):
        with self.assertRaises(PTY_SECRET.HelperError):
            PTY_SECRET.safe_projection(
                {"schema_version": 1, "status": "failed", "resource_ids": {}, "data": {}},
                "invite",
            )

    def test_private_write_is_create_only_mode_0600(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "token"
            PTY_SECRET.private_write(target, b"secret\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                PTY_SECRET.private_write(target, b"replacement\n")


if __name__ == "__main__":
    unittest.main()
