from __future__ import annotations

import unittest
from unittest import mock

from webui import store


class WebuiCpaFilterTests(unittest.TestCase):
    def _items(self):
        return {
            "ok@example.com": {
                "email": "ok@example.com",
                "path": "/tmp/xai-ok@example.com.json",
                "filename": "xai-ok@example.com.json",
                "mint_method": "protocol",
                "expired": "",
                "mtime": 100.0,
                "location": "hotload",
                "size": 10,
            },
            "bad@example.com": {
                "email": "bad@example.com",
                "path": "/tmp/xai-bad@example.com.json",
                "filename": "xai-bad@example.com.json",
                "mint_method": "protocol",
                "expired": "",
                "mtime": 90.0,
                "location": "hotload",
                "size": 10,
            },
            "new@example.com": {
                "email": "new@example.com",
                "path": "/tmp/xai-new@example.com.json",
                "filename": "xai-new@example.com.json",
                "mint_method": "browser",
                "expired": "",
                "mtime": 80.0,
                "location": "auth_dir",
                "size": 10,
            },
        }

    def test_list_cpa_filters_by_scan_status_and_unchecked(self):
        scan_results = {
            "ok@example.com": {"email": "ok@example.com", "status": "ok", "reason": "models ok"},
            "bad@example.com": {"email": "bad@example.com", "status": "refresh_failed", "reason": "invalid_grant"},
        }
        with mock.patch("webui.store.list_cpa_index", return_value=self._items()):
            ok = store.list_cpa(scan_status="ok", scan_results=scan_results)
            bad = store.list_cpa(scan_status="bad", scan_results=scan_results)
            unchecked = store.list_cpa(scan_status="unchecked", scan_results=scan_results)

        self.assertEqual([i["email"] for i in ok["items"]], ["ok@example.com"])
        self.assertEqual([i["email"] for i in bad["items"]], ["bad@example.com"])
        self.assertEqual([i["email"] for i in unchecked["items"]], ["new@example.com"])
        self.assertEqual(unchecked["items"][0]["scan_status"], "unchecked")

    def test_list_cpa_quota_filter_includes_cooling(self):
        scan_results = {
            "ok@example.com": {"email": "ok@example.com", "status": "quota"},
            "bad@example.com": {"email": "bad@example.com", "status": "cooling"},
            "new@example.com": {"email": "new@example.com", "status": "ok"},
        }
        with mock.patch("webui.store.list_cpa_index", return_value=self._items()):
            result = store.list_cpa(scan_status="quota", scan_results=scan_results)

        self.assertEqual([i["email"] for i in result["items"]], ["ok@example.com", "bad@example.com"])


if __name__ == "__main__":
    unittest.main()
