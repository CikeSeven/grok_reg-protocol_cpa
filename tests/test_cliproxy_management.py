from __future__ import annotations

import json
import unittest
from unittest import mock

from webui.cliproxy_management import CLIProxyManagementClient, ManagementSettings


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class CLIProxyManagementClientTests(unittest.TestCase):
    def setUp(self):
        self.client = CLIProxyManagementClient(
            ManagementSettings(
                enabled=True,
                base_url="http://127.0.0.1:8317/v0/management",
                key="management-secret",
            )
        )

    def test_lists_auth_files_with_bearer_auth(self):
        captured = {}

        def open_request(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return _Response({"files": [{"email": "user@example.com", "priority": 100}]})

        with mock.patch("webui.cliproxy_management.urllib.request.urlopen", side_effect=open_request):
            files = self.client.list_auth_files(force=True)

        self.assertEqual(files[0]["email"], "user@example.com")
        self.assertEqual(captured["request"].get_header("Authorization"), "Bearer management-secret")
        self.assertTrue(captured["request"].full_url.endswith("/v0/management/auth-files"))

    def test_patch_fields_sends_priority_disabled_and_metadata(self):
        captured = {}

        def open_request(request, timeout):
            captured["method"] = request.get_method()
            captured["body"] = json.loads(request.data)
            captured["timeout"] = timeout
            return _Response({"status": "ok"})

        with mock.patch("webui.cliproxy_management.urllib.request.urlopen", side_effect=open_request):
            self.client.patch_fields(
                "xai-user.json",
                **{"priority": 50, "disabled": True, "_cpa_pool.tier": "observe"},
            )

        self.assertEqual(captured["method"], "PATCH")
        self.assertEqual(captured["body"]["priority"], 50)
        self.assertTrue(captured["body"]["disabled"])
        self.assertEqual(captured["body"]["_cpa_pool.tier"], "observe")


if __name__ == "__main__":
    unittest.main()
