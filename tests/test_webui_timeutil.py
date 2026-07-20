from __future__ import annotations

import unittest

from webui import timeutil


class WebuiTimeutilTests(unittest.TestCase):
    def test_iso_to_beijing_iso_converts_utc_z(self):
        self.assertEqual(
            timeutil.iso_to_beijing_iso("2026-07-20T15:30:41Z"),
            "2026-07-20T23:30:41+08:00",
        )

    def test_timestamp_display_uses_beijing_label(self):
        self.assertEqual(
            timeutil.timestamp_display(0),
            "",
        )
        self.assertIn("北京时间", timeutil.timestamp_display(1784561442.4843535))


if __name__ == "__main__":
    unittest.main()
