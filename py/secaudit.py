#!/usr/bin/env python3
import argparse
import json
import os
import stat
import subprocess
import sys
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONF_FILE = os.path.join(ROOT_DIR, "conf", "thresholds.json")

SUID_WHITELIST = {
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chage",
    "/usr/bin/pkexec",
    "/usr/bin/crontab",
    "/usr/bin/at",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/bin/write",
    "/usr/bin/wall",
    "/usr/bin/locate",
    "/usr/sbin/unix_chkpwd",
    "/usr/sbin/pam_timestamp_check",
    "/usr/sbin/userhelper",
    "/usr/sbin/mount.nfs",
    "/usr/sbin/grub2-set-bootflag",
    "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/libexec/utempter/utempter",
}

SUID_DIRS = ["/usr", "/bin", "/sbin", "/opt"]
PERM_DIRS = ["/etc", "/home"]
NOLOGIN_SHELLS = {"/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false"}
NO_PASSWORD_HASHES = {"", "!", "!!", "*"}
CRITICAL_KEYS = ["uid0", "empty_password", "suid_suspicious", "perm_777", "world_writable"]


def parse_passwd(path):
    users = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) < 7:
                continue
            users.append({
                "name": fields[0],
                "uid": int(fields[2]),
                "gid": int(fields[3]),
                "home": fields[5],
                "shell": fields[6],
            })
    return users


def read_shadow(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            hashes = {}
            for line in f:
                fields = line.strip().split(":")
                if len(fields) >= 2:
                    hashes[fields[0]] = fields[1]
            return hashes
    except (PermissionError, FileNotFoundError):
        return None


def can_login(user):
    return user["shell"] not in NOLOGIN_SHELLS


def password_expiry(name):
    try:
        result = subprocess.run(
            ["chage", "-l", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=dict(os.environ, LC_ALL="C"),
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.startswith("Password expires"):
            value = line.split(":", 1)[1].strip()
            if value == "never":
                return "never"
            if value == "password must be changed":
                return "expired"
            expires = datetime.strptime(value, "%b %d, %Y")
            return "expired" if expires < datetime.now() else "ok"
    return None


def audit_accounts(users, shadow, check_expiry=True):
    result = {
        "shadow_readable": shadow is not None,
        "uid0": [],
        "empty_password": [],
        "shell_without_password": [],
        "nologin": [],
        "password_expired": [],
        "password_never_expires": [],
    }
    for user in users:
        name = user["name"]
        if user["uid"] == 0 and name != "root":
            result["uid0"].append(name)

        if not can_login(user):
            result["nologin"].append(name)
            continue

        if shadow is not None:
            password_hash = shadow.get(name)
            if password_hash == "":
                result["empty_password"].append(name)
            if password_hash in NO_PASSWORD_HASHES:
                result["shell_without_password"].append(name)

        if check_expiry and (user["uid"] == 0 or user["uid"] >= 1000):
            expiry = password_expiry(name)
            if expiry == "expired":
                result["password_expired"].append(name)
            elif expiry == "never":
                result["password_never_expires"].append(name)
    return result


def is_suid(mode):
    return bool(mode & stat.S_ISUID)


def is_sgid(mode):
    return bool(mode & stat.S_ISGID)


def scan_suid(dirs, whitelist):
    found = []
    suspicious = []
    skipped = []
    seen_roots = set()

    def on_error(error):
        skipped.append(error.filename)

    for top in dirs:
        real_top = os.path.realpath(top)
        if not os.path.isdir(real_top):
            continue
        if any(real_top == root or real_top.startswith(root + os.sep) for root in seen_roots):
            continue
        seen_roots.add(real_top)

        for root, _dirs, files in os.walk(real_top, onerror=on_error):
            for name in files:
                path = os.path.join(root, name)
                try:
                    st = os.lstat(path)
                except (PermissionError, FileNotFoundError):
                    skipped.append(path)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if not (is_suid(st.st_mode) or is_sgid(st.st_mode)):
                    continue
                item = {
                    "path": path,
                    "mode": oct(st.st_mode & 0o7777),
                    "suid": is_suid(st.st_mode),
                    "sgid": is_sgid(st.st_mode),
                }
                found.append(item)
                if path not in whitelist:
                    suspicious.append(item)
    return {"found": found, "suspicious": suspicious, "skipped": len(skipped)}


def scan_permissions(dirs, known_uids):
    result = {
        "perm_777": [],
        "world_writable": [],
        "home_exec_all": [],
        "orphan": [],
        "skipped": 0,
    }

    def on_error(_error):
        result["skipped"] += 1

    for top in dirs:
        if not os.path.isdir(top):
            continue
        for root, dirs_here, files in os.walk(top, onerror=on_error):
            for name in dirs_here + files:
                path = os.path.join(root, name)
                try:
                    st = os.lstat(path)
                except (PermissionError, FileNotFoundError):
                    result["skipped"] += 1
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue

                if st.st_uid not in known_uids:
                    result["orphan"].append({"path": path, "uid": st.st_uid})

                if not stat.S_ISREG(st.st_mode):
                    continue
                perms = st.st_mode & 0o777
                if perms == 0o777:
                    result["perm_777"].append(path)
                elif perms & 0o002:
                    result["world_writable"].append({"path": path, "mode": oct(perms)})
                if path.startswith("/home/") and perms & 0o111 == 0o111:
                    result["home_exec_all"].append(path)
    return result


def is_loopback(address):
    return address.startswith("127.") or address in ("[::1]", "::1") or "%lo" in address


def audit_ports(allowed):
    try:
        result = subprocess.run(
            ["ss", "-tulpn"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
    except FileNotFoundError:
        return {"error": "команда ss не найдена", "listening": [], "unexpected": []}

    listening = []
    unexpected = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        address, port = parts[4].rsplit(":", 1)
        if not port.isdigit():
            continue
        item = {
            "proto": parts[0],
            "address": address,
            "port": int(port),
            "process": parts[6] if len(parts) > 6 else "",
        }
        listening.append(item)
        if item["port"] not in allowed and not is_loopback(address):
            unexpected.append(item)
    return {"listening": listening, "unexpected": unexpected}


def load_allowed_ports():
    with open(CONF_FILE, encoding="utf-8") as f:
        return set(json.load(f)["allowed_ports"])


def summarize(report):
    accounts = report["accounts"]
    perms = report["permissions"]
    return {
        "uid0": len(accounts["uid0"]),
        "empty_password": len(accounts["empty_password"]),
        "suid_suspicious": len(report["suid"]["suspicious"]),
        "perm_777": len(perms["perm_777"]),
        "world_writable": len(perms["world_writable"]),
        "orphan": len(perms["orphan"]),
        "unexpected_ports": len(report["ports"]["unexpected"]),
        "password_expired": len(accounts["password_expired"]),
    }


def build_parser():
    parser = argparse.ArgumentParser(
        description="Аудит безопасности: учётки, SUID/SGID, опасные права, порты"
    )
    parser.add_argument("--out", default="logs/secaudit.json",
                        help="куда сохранить JSON-отчёт")
    return parser


def main():
    args = build_parser().parse_args()

    try:
        allowed_ports = load_allowed_ports()
    except (OSError, ValueError, KeyError) as e:
        print(f"ОШИБКА: не удалось прочитать allowed_ports из {CONF_FILE}: {e}", file=sys.stderr)
        return 3

    users = parse_passwd("/etc/passwd")
    shadow = read_shadow("/etc/shadow")
    if shadow is None:
        print("ВНИМАНИЕ: /etc/shadow не читается (нужен root), проверка паролей пропущена",
              file=sys.stderr)

    report = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "accounts": audit_accounts(users, shadow),
        "suid": scan_suid(SUID_DIRS, SUID_WHITELIST),
        "permissions": scan_permissions(PERM_DIRS, {u["uid"] for u in users}),
        "ports": audit_ports(allowed_ports),
    }
    report["summary"] = summarize(report)
    critical = any(report["summary"][key] > 0 for key in CRITICAL_KEYS)
    report["critical"] = critical

    try:
        directory = os.path.dirname(args.out)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    except OSError as e:
        print(f"ОШИБКА: не удалось записать {args.out}: {e}", file=sys.stderr)
        return 3

    summary = report["summary"]
    label = "CRIT" if critical else "OK"
    print(f"{label}: " + ", ".join(f"{key}={value}" for key, value in summary.items()))
    return 2 if critical else 0


if __name__ == "__main__":
    sys.exit(main())
