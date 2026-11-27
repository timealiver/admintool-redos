import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secaudit

FIXTURE_PASSWD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "passwd")


class TestPasswd(unittest.TestCase):

    def test_parse_passwd_skips_comments_and_broken_lines(self):
        users = secaudit.parse_passwd(FIXTURE_PASSWD)
        self.assertEqual(len(users), 7)
        self.assertEqual(users[4], {
            "name": "toor", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash",
        })

    def test_finds_uid0_other_than_root(self):
        users = secaudit.parse_passwd(FIXTURE_PASSWD)
        result = secaudit.audit_accounts(users, shadow=None, check_expiry=False)
        self.assertEqual(result["uid0"], ["toor"])
        self.assertEqual(result["nologin"], ["bin", "daemon", "sshd"])
        self.assertFalse(result["shadow_readable"])

    def test_finds_empty_and_missing_passwords(self):
        users = secaudit.parse_passwd(FIXTURE_PASSWD)
        shadow = {"root": "$6$abc", "toor": "$6$def", "timur": "$6$ghi", "dev1": "", "bin": "*"}
        result = secaudit.audit_accounts(users, shadow, check_expiry=False)
        self.assertEqual(result["empty_password"], ["dev1"])
        self.assertEqual(result["shell_without_password"], ["dev1"])


class TestFileModes(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def make_file(self, name, mode):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            f.write("test")
        os.chmod(path, mode)
        return path

    def test_is_suid_by_st_mode(self):
        suid_file = self.make_file("with_suid", 0o4755)
        plain_file = self.make_file("plain", 0o755)
        self.assertTrue(secaudit.is_suid(os.stat(suid_file).st_mode))
        self.assertFalse(secaudit.is_suid(os.stat(plain_file).st_mode))

    def test_scan_suid_uses_whitelist(self):
        allowed = self.make_file("allowed", 0o4755)
        bad = self.make_file("bad", 0o4755)
        self.make_file("plain", 0o755)
        result = secaudit.scan_suid([self.dir], whitelist={os.path.realpath(allowed)})
        found = sorted(os.path.basename(item["path"]) for item in result["found"])
        suspicious = [os.path.basename(item["path"]) for item in result["suspicious"]]
        self.assertEqual(found, ["allowed", "bad"])
        self.assertEqual(suspicious, ["bad"])

    def test_scan_permissions_finds_777_and_orphans(self):
        self.make_file("open", 0o777)
        self.make_file("writable", 0o666)
        self.make_file("normal", 0o644)
        result = secaudit.scan_permissions([self.dir], known_uids=set())
        self.assertEqual([os.path.basename(p) for p in result["perm_777"]], ["open"])
        self.assertEqual([os.path.basename(i["path"]) for i in result["world_writable"]], ["writable"])
        self.assertEqual(len(result["orphan"]), 3)


if __name__ == "__main__":
    unittest.main()
