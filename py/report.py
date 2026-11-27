#!/usr/bin/env python3
import argparse
import glob
import html
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from string import Template

from logwatch import parse_since

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(ROOT_DIR, "logs")

HEALTH_FIELD = re.compile(r"(\w+)=(OK|WARN|CRIT)\(([^)]*)\)")
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class NoDataError(Exception):
    pass


def parse_health_line(line):
    try:
        ts = datetime.strptime(line[:19], TIME_FORMAT)
    except ValueError:
        return None
    checks = {}
    for name, status, value in HEALTH_FIELD.findall(line):
        checks[name] = {"status": status, "value": value}
    return {"time": ts, "checks": checks}


def read_health(logs_dir, since_dt):
    entries = []
    for path in sorted(glob.glob(os.path.join(logs_dir, "health_*.log"))):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                entry = parse_health_line(line.strip())
                if entry and entry["time"] >= since_dt:
                    entries.append(entry)
    return entries


def read_json_if_fresh(path, since_dt):
    if not os.path.isfile(path):
        return None
    if datetime.fromtimestamp(os.path.getmtime(path)) < since_dt:
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read_actions(logs_dir, since_dt):
    path = os.path.join(logs_dir, "actions.log")
    if not os.path.isfile(path):
        return []
    actions = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            try:
                ts = datetime.strptime(line[:19], TIME_FORMAT)
            except ValueError:
                continue
            if ts >= since_dt:
                actions.append(line)
    return actions


def count_statuses(health, secaudit):
    counts = {"OK": 0, "WARN": 0, "CRIT": 0}
    for entry in health:
        for check in entry["checks"].values():
            counts[check["status"]] += 1
    if secaudit is not None:
        counts["CRIT" if secaudit.get("critical") else "OK"] += 1
    return counts


def collect(logs_dir, since_dt, now):
    health = read_health(logs_dir, since_dt)
    logwatch = read_json_if_fresh(os.path.join(logs_dir, "logwatch.json"), since_dt)
    secaudit = read_json_if_fresh(os.path.join(logs_dir, "secaudit.json"), since_dt)
    actions = read_actions(logs_dir, since_dt)

    if not health and logwatch is None and secaudit is None and not actions:
        raise NoDataError(f"нет данных в {logs_dir} за период с {since_dt:%Y-%m-%d %H:%M}")

    return {
        "generated": now.isoformat(timespec="seconds"),
        "period": {
            "from": since_dt.isoformat(timespec="seconds"),
            "to": now.isoformat(timespec="seconds"),
        },
        "counts": count_statuses(health, secaudit),
        "health": [
            {"time": e["time"].isoformat(timespec="seconds"), "checks": e["checks"]}
            for e in health
        ],
        "logwatch": logwatch,
        "secaudit": secaudit,
        "actions": actions,
    }


def top_processes(limit=5):
    result = subprocess.run(
        ["ps", "-eo", "pid,ppid,pcpu,pmem,comm", "--sort=-pcpu"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    processes = []
    for line in result.stdout.splitlines()[1:limit + 1]:
        pid, ppid, cpu, mem, command = line.split(None, 4)
        processes.append({
            "pid": int(pid),
            "ppid": int(ppid),
            "cpu": float(cpu),
            "mem": float(mem),
            "command": command,
        })
    return {"generated": datetime.now().isoformat(timespec="seconds"), "top_processes": processes}


def esc(value):
    return html.escape(str(value))


def table(headers, rows):
    if not rows:
        return "<p class=\"empty\">нет данных</p>"
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><tr>{head}</tr>{body}</table>"


def health_section(report):
    rows = []
    for entry in report["health"][-20:]:
        checks = entry["checks"]
        row = [entry["time"]]
        for name in ("cpu", "mem", "disk", "net"):
            check = checks.get(name)
            row.append(f"{check['status']} ({check['value']})" if check else "—")
        rows.append(row)
    return table(["Время", "CPU", "Память", "Диск", "Сеть"], rows)


def errors_section(report):
    logwatch = report["logwatch"]
    if logwatch is None:
        return "<p class=\"empty\">нет logwatch.json за период</p>"
    errors = table(
        ["Кол-во", "Шаблон ошибки"],
        [[e["count"], e["pattern"]] for e in logwatch.get("top_errors", [])],
    )
    ips = table(
        ["Кол-во", "IP"],
        [[i["count"], i["ip"]] for i in logwatch.get("top_failed_ips", [])],
    )
    return f"{errors}<h3>Топ IP по неудачным входам</h3>{ips}"


def security_section(report):
    secaudit = report["secaudit"]
    if secaudit is None:
        return "<p class=\"empty\">нет secaudit.json за период</p>"
    accounts = secaudit.get("accounts", {})
    rows = [
        ["UID 0 кроме root", ", ".join(accounts.get("uid0", [])) or "—"],
        ["Пустой пароль", ", ".join(accounts.get("empty_password", [])) or "—"],
        ["Оболочка без пароля", ", ".join(accounts.get("shell_without_password", [])) or "—"],
        ["Пароль истёк", ", ".join(accounts.get("password_expired", [])) or "—"],
        ["Пароль не истекает", ", ".join(accounts.get("password_never_expires", [])) or "—"],
        ["Подозрительные SUID/SGID",
         ", ".join(i["path"] for i in secaudit.get("suid", {}).get("suspicious", [])) or "—"],
        ["Файлы 777", ", ".join(secaudit.get("permissions", {}).get("perm_777", [])) or "—"],
        ["Запись для всех",
         ", ".join(i["path"] for i in secaudit.get("permissions", {}).get("world_writable", [])) or "—"],
        ["Файлы-сироты",
         ", ".join(i["path"] for i in secaudit.get("permissions", {}).get("orphan", [])) or "—"],
        ["Неожиданные порты",
         ", ".join(f"{p['port']}/{p['proto']}" for p in secaudit.get("ports", {}).get("unexpected", [])) or "—"],
    ]
    return table(["Проверка", "Находки"], rows)


def actions_section(report):
    return table(["Запись"], [[line] for line in report["actions"]])


PAGE = Template("""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Отчёт admintool</title>
<style>
body { font-family: sans-serif; margin: 24px; color: #222; }
table { border-collapse: collapse; margin: 8px 0 16px; }
th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: #f0f0f0; }
.empty { color: #888; }
.OK { color: #2e7d32; } .WARN { color: #b26a00; } .CRIT { color: #c62828; }
</style>
</head>
<body>
<h1>Отчёт admintool</h1>
<p>Период: $period_from — $period_to. Сформирован: $generated.</p>
<table>
<tr><th class="OK">OK</th><th class="WARN">WARN</th><th class="CRIT">CRIT</th></tr>
<tr><td id="count-OK">$ok</td><td id="count-WARN">$warn</td><td id="count-CRIT">$crit</td></tr>
</table>
<h2>Здоровье системы</h2>
$health
<h2>Топ ошибок</h2>
$errors
<h2>Подозрительные учётки и файлы</h2>
$security
<h2>Действия реагирования</h2>
$actions
</body>
</html>
""")


def render_html(report):
    return PAGE.substitute(
        period_from=esc(report["period"]["from"]),
        period_to=esc(report["period"]["to"]),
        generated=esc(report["generated"]),
        ok=report["counts"]["OK"],
        warn=report["counts"]["WARN"],
        crit=report["counts"]["CRIT"],
        health=health_section(report),
        errors=errors_section(report),
        security=security_section(report),
        actions=actions_section(report),
    )


def write_file(path, text):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def build_parser():
    parser = argparse.ArgumentParser(description="Сводный отчёт admintool (JSON или HTML)")
    parser.add_argument("--since", type=parse_since, default="7d",
                        help="за какой период собирать данные: 24h, 7d (по умолчанию 7d)")
    parser.add_argument("--format", choices=["json", "html"], default="json",
                        help="формат отчёта (по умолчанию json)")
    parser.add_argument("--out", help="куда сохранить (по умолчанию logs/report.json или .html)")
    parser.add_argument("--top-processes", action="store_true",
                        help="только топ-5 процессов по CPU в JSON")
    parser.add_argument("--logs-dir", default=LOG_DIR, help=argparse.SUPPRESS)
    return parser


def main():
    args = build_parser().parse_args()

    if args.top_processes:
        text = json.dumps(top_processes(), ensure_ascii=False, indent=2)
    else:
        now = datetime.now()
        try:
            report = collect(args.logs_dir, now - args.since, now)
        except NoDataError as e:
            print(f"НЕТ ДАННЫХ: {e}", file=sys.stderr)
            return 2
        if args.format == "html":
            text = render_html(report)
        else:
            text = json.dumps(report, ensure_ascii=False, indent=2)
        if args.out is None:
            args.out = os.path.join(args.logs_dir, f"report.{args.format}")

    if args.out is None:
        print(text)
        return 0

    try:
        write_file(args.out, text)
    except OSError as e:
        print(f"ОШИБКА: не удалось записать {args.out}: {e}", file=sys.stderr)
        return 3
    print(f"Отчёт сохранён: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
