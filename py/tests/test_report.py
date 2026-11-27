import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report

NOW = datetime.now().replace(microsecond=0)


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class TestReport(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        stamp = (NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        old = (NOW - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        write(os.path.join(self.dir, "health_test.log"),
              f"{old} | cpu=CRIT(99%) | load=9 | mem=OK(10%) | disk=OK(10% /) | net=OK(0%)\n"
              f"{stamp} | cpu=OK(12%) | load=0.3 | mem=WARN(87%) | disk=OK(40% /) | net=CRIT(100%)\n")
        write(os.path.join(self.dir, "logwatch.json"), json.dumps({
            "top_errors": [{"pattern": "sshd: Failed password", "count": 3, "example": "x"}],
            "top_failed_ips": [{"ip": "10.0.0.5", "count": 42}],
        }))
        write(os.path.join(self.dir, "secaudit.json"), json.dumps({
            "critical": True,
            "accounts": {"uid0": ["toor"]},
            "suid": {"suspicious": [{"path": "/opt/evil"}]},
            "permissions": {},
            "ports": {"unexpected": []},
        }))
        write(os.path.join(self.dir, "actions.log"),
              f"{stamp} | BLOCK | ip=10.0.0.5 | неудачных входов 42 > 10\n")

    def tearDown(self):
        self.tmp.cleanup()

    def build(self):
        return report.collect(self.dir, NOW - timedelta(days=7), NOW)

    def test_old_health_lines_are_filtered_out(self):
        data = self.build()
        self.assertEqual(len(data["health"]), 1)
        self.assertEqual(data["counts"], {"OK": 2, "WARN": 1, "CRIT": 2})

    def test_html_has_all_sections_and_same_counts(self):
        data = self.build()
        page = report.render_html(data)
        for title in ("Здоровье системы", "Топ ошибок",
                      "Подозрительные учётки и файлы", "Действия реагирования"):
            self.assertIn(f"<h2>{title}</h2>", page)
        for status in ("OK", "WARN", "CRIT"):
            found = re.search(rf'id="count-{status}">(\d+)<', page).group(1)
            self.assertEqual(int(found), data["counts"][status])
        self.assertIn("/opt/evil", page)
        self.assertIn("10.0.0.5", page)

    def test_no_data_raises(self):
        empty = tempfile.TemporaryDirectory()
        with self.assertRaises(report.NoDataError):
            report.collect(empty.name, NOW - timedelta(days=7), NOW)
        empty.cleanup()


if __name__ == "__main__":
    unittest.main()
