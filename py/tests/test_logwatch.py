import argparse
import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logwatch

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "sample.log")
NOW = datetime(2026, 11, 21, 12, 0, 0)


def analyze_fixture():
    lines = logwatch.read_file(FIXTURE)
    return logwatch.analyze(lines, since_dt=None, now=NOW, top=5)


class TestLogwatch(unittest.TestCase):

    def test_top_errors_grouped_by_pattern(self):
        result = analyze_fixture()
        first = result["top_errors"][0]
        self.assertEqual(first["count"], 3)
        self.assertTrue(first["pattern"].startswith("kernel: EXTN-fs error"))
        self.assertEqual(result["counts"]["matched_errors"], 10)

    def test_top_failed_ips(self):
        result = analyze_fixture()
        self.assertEqual(result["top_failed_ips"], [
            {"ip": "10.0.0.5", "count": 4},
            {"ip": "192.168.1.20", "count": 1},
        ])

    def test_unparsed_lines_are_counted(self):
        result = analyze_fixture()
        self.assertEqual(result["counts"]["unparsed"], 2)
        self.assertEqual(result["counts"]["total"], 14)

    def test_since_filters_old_lines(self):
        lines = logwatch.read_file(FIXTURE)
        result = logwatch.analyze(lines, since_dt=datetime(2026, 11, 21, 9, 15), now=NOW, top=5)
        self.assertEqual(result["counts"]["total"], 5)
        self.assertEqual(result["top_failed_ips"], [])

    def test_normalize_replaces_ip_before_numbers(self):
        text = "Failed password for root from 10.0.0.5 port 50122 ssh2"
        self.assertEqual(
            logwatch.normalize(text),
            "Failed password for root from IP port N sshN",
        )

    def test_parse_since(self):
        self.assertEqual(logwatch.parse_since("24h"), timedelta(hours=24))
        self.assertEqual(logwatch.parse_since("7d"), timedelta(days=7))
        with self.assertRaises(argparse.ArgumentTypeError):
            logwatch.parse_since("5x")

    def test_missing_file_raises(self):
        with self.assertRaises(logwatch.LogSourceError):
            logwatch.read_file("/nonexistent/file.log")


if __name__ == "__main__":
    unittest.main()
